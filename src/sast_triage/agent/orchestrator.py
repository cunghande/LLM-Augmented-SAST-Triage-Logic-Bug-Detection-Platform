"""ControlledTriageAgent: Orchestrates budget-bounded agent loops with fail-closed safety."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sast_triage.agent.judge import AgentJudge
from sast_triage.agent.ledger import EvidenceLedger
from sast_triage.agent.models import (
    ActionValidationResult,
    AgentAction,
    AgentMode,
    AgentTraceEntry,
)
from sast_triage.agent.planner import AgentPlanner
from sast_triage.agent.tools import AgentToolRegistry
from sast_triage.agent.validator import ActionValidator
from sast_triage.analysis.base import AnalysisBackend, GraphEvidence, QueryResultStatus
from sast_triage.models import (
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PolicyAction,
    PolicyDecision,
    SanitizedContext,
    TriageDecision,
)
from sast_triage.policy.engine import apply_policy
from sast_triage.triage.post_verifier import verify_post_triage_decision


@dataclass(frozen=True, slots=True)
class AgentTriageResult:
    """Final outcome of the Controlled Triage Agent execution."""

    policy_decision: PolicyDecision
    triage_decision: TriageDecision
    ledger: EvidenceLedger
    trace: tuple[AgentTraceEntry, ...]
    escalated_to_agent: bool
    tool_calls_executed: int
    fallback_applied: bool = False


class ControlledTriageAgent:
    """Controlled multi-turn agent coordinator with escalation rules and tool caching."""

    def __init__(
        self,
        repository_root: Path,
        analysis_backend: AnalysisBackend | None = None,
        provider: TriageProvider | None = None,
        *,
        agent_mode: AgentMode = AgentMode.OFF,
        max_iterations: int = 4,
        max_tool_calls: int = 4,
        timeout_seconds: float = 30.0,
        enable_self_consistency: bool = False,
    ) -> None:
        self._repository_root = repository_root.resolve()
        self._backend = analysis_backend
        self._provider = provider
        self._agent_mode = agent_mode
        self._max_iterations = max(1, min(max_iterations, 8))
        self._max_tool_calls = max(1, min(max_tool_calls, 8))
        self._timeout_seconds = timeout_seconds
        self._enable_self_consistency = enable_self_consistency

        # Subsystems
        self._tools = AgentToolRegistry(self._repository_root, analysis_backend)
        self._validator = ActionValidator(self._repository_root)
        self._planner = AgentPlanner(provider)
        self._judge = AgentJudge(provider)

        # Tool caching: (file_path, enclosing_function, canonical_signature) -> tool result
        self._tool_cache: dict[tuple[str, str, str], tuple[QueryResultStatus, str, str, dict[str, Any]]] = {}

    @property
    def agent_mode(self) -> AgentMode:
        return self._agent_mode

    def _should_escalate(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        tier1_decision: TriageDecision | None,
        initial_evidence: GraphEvidence | None,
    ) -> bool:
        """Determines whether to trigger the multi-turn agent loop."""
        if self._agent_mode == AgentMode.OFF:
            return False
        if self._agent_mode == AgentMode.ALWAYS:
            return True

        # Mode ESCALATE:
        # 1. Any tool returned UNKNOWN or missing in Tier-1
        if initial_evidence and (
            initial_evidence.query_status == QueryResultStatus.UNKNOWN
            or not initial_evidence.reachability_resolved
        ):
            return True

        # 2. Tier-1 decision has low confidence or is missing
        if tier1_decision is None or tier1_decision.model_confidence != ModelConfidence.HIGH:
            return True

        return False

    def triage(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        tier1_decision: TriageDecision | None = None,
        initial_evidence: GraphEvidence | None = None,
    ) -> AgentTriageResult:
        """Run triage with controlled agent escalation and fail-closed safety."""
        # 1. Check escalation threshold
        if not self._should_escalate(finding, context, tier1_decision, initial_evidence):
            fallback_dec = tier1_decision or TriageDecision(
                model_verdict=ModelVerdict.LIKELY_TP,
                model_confidence=ModelConfidence.MEDIUM,
                summary="Tier-1 decision retained (Agent mode disabled or not escalated).",
                model_version="tier1-fallback",
                prompt_version="tier1-v15",
            )
            policy_res = apply_policy(finding, context, fallback_dec)
            return AgentTriageResult(
                policy_decision=policy_res,
                triage_decision=fallback_dec,
                ledger=EvidenceLedger(),
                trace=(),
                escalated_to_agent=False,
                tool_calls_executed=0,
                fallback_applied=False,
            )

        # 2. Agent Loop Execution
        ledger = EvidenceLedger()
        trace_list: list[AgentTraceEntry] = []
        started = time.monotonic()
        tool_calls = 0

        # Seed initial facts if available
        if initial_evidence and initial_evidence.sink_symbol:
            ledger.add_entry(
                tool_name="trace_dataflow",
                parameters={"target_symbol": initial_evidence.sink_symbol},
                canonical_signature=f"trace_dataflow::{initial_evidence.sink_symbol}",
                query_status=initial_evidence.query_status or QueryResultStatus.FOUND,
                status_reason=initial_evidence.status_reason or "INITIAL_FACT",
                summary=f"Initial graph evidence: reaches_sink={initial_evidence.source_reaches_sink}",
                facts={"reaches_sink": initial_evidence.source_reaches_sink},
            )

        try:
            for step_idx in range(1, self._max_iterations + 1):
                # Budget & Timeout checks
                if tool_calls >= self._max_tool_calls:
                    trace_list.append(
                        AgentTraceEntry(
                            step=step_idx,
                            action=AgentAction(tool="DONE", parameters={}),
                            is_valid=True,
                            status="STOPPED",
                            summary="Reached max tool call budget.",
                            stop_reason="MAX_TOOL_CALLS_REACHED",
                        )
                    )
                    break

                if time.monotonic() - started >= self._timeout_seconds:
                    trace_list.append(
                        AgentTraceEntry(
                            step=step_idx,
                            action=AgentAction(tool="DONE", parameters={}),
                            is_valid=True,
                            status="STOPPED",
                            summary="Agent execution timed out.",
                            stop_reason="AGENT_TIMEOUT",
                        )
                    )
                    break

                # Planner selects action
                planner_res = self._planner.plan_next_action(
                    finding, context, ledger, self._max_iterations - step_idx
                )
                action = planner_res.action

                if action.tool == "DONE":
                    trace_list.append(
                        AgentTraceEntry(
                            step=step_idx,
                            action=action,
                            is_valid=True,
                            status="COMPLETED",
                            summary=planner_res.thought,
                            stop_reason="PLANNER_CONCLUDED",
                        )
                    )
                    break

                # Validate Action
                val_res = self._validator.validate_action(action, ledger)
                if not val_res.is_valid:
                    trace_list.append(
                        AgentTraceEntry(
                            step=step_idx,
                            action=action,
                            is_valid=False,
                            status="BLOCKED",
                            summary=f"Action blocked by validator: {val_res.error_message}",
                            stop_reason=val_res.error_code,
                        )
                    )
                    continue

                # Check Tool Cache
                cache_key = (
                    finding.file_path,
                    context.enclosing_function or "",
                    val_res.canonical_signature or action.tool,
                )
                if cache_key in self._tool_cache:
                    q_status, q_reason, q_summary, q_facts = self._tool_cache[cache_key]
                else:
                    q_status, q_reason, q_summary, q_facts = self._tools.execute_tool(
                        action.tool, action.parameters, finding, initial_evidence
                    )
                    self._tool_cache[cache_key] = (q_status, q_reason, q_summary, q_facts)

                tool_calls += 1
                ledger.add_entry(
                    tool_name=action.tool,
                    parameters=action.parameters,
                    canonical_signature=val_res.canonical_signature or action.tool,
                    query_status=q_status,
                    status_reason=q_reason,
                    summary=q_summary,
                    facts=q_facts,
                )

                trace_list.append(
                    AgentTraceEntry(
                        step=step_idx,
                        action=action,
                        is_valid=True,
                        status=q_status.value,
                        summary=q_summary,
                        stop_reason=None,
                    )
                )

            # 3. Judge Evaluates Ledger
            judge_decision = self._judge.evaluate(finding, context, ledger)

            # 4. Self-consistency check (k=3 samples for borderline)
            if self._enable_self_consistency and judge_decision.model_confidence != ModelConfidence.HIGH:
                decisions = [judge_decision]
                for _ in range(2):
                    decisions.append(self._judge.evaluate(finding, context, ledger))
                fp_count = sum(1 for d in decisions if d.model_verdict == ModelVerdict.LIKELY_FP)
                if fp_count >= 2:
                    judge_decision = decisions[0]
                elif fp_count == 0:
                    judge_decision = decisions[0]
                else:
                    # Disagreement -> fail-closed to MEDIUM confidence
                    judge_decision = TriageDecision(
                        structured_evidence=judge_decision.structured_evidence,
                        model_verdict=ModelVerdict.LIKELY_TP,
                        model_confidence=ModelConfidence.MEDIUM,
                        summary="Self-consistency sample consensus disagreement: forced fail-closed.",
                        model_version="agent-self-consistency",
                        prompt_version=judge_decision.prompt_version,
                    )

            # 5. Verify & Apply Policy
            post_ver_res = verify_post_triage_decision(judge_decision, context, finding)
            verified_decision = post_ver_res.verified_decision
            policy_decision = apply_policy(finding, context, verified_decision)

            return AgentTriageResult(
                policy_decision=policy_decision,
                triage_decision=verified_decision,
                ledger=ledger,
                trace=tuple(trace_list),
                escalated_to_agent=True,
                tool_calls_executed=tool_calls,
                fallback_applied=False,
            )

        except Exception as exc:
            # 6. Fail-closed Fallback
            fallback_dec = tier1_decision or TriageDecision(
                model_verdict=ModelVerdict.LIKELY_TP,
                model_confidence=ModelConfidence.MEDIUM,
                summary=f"Agent loop encountered safe fallback due to: {type(exc).__name__}",
                model_version="agent-error-fallback",
                prompt_version="tier1-v15",
            )
            policy_res = apply_policy(finding, context, fallback_dec)
            return AgentTriageResult(
                policy_decision=policy_res,
                triage_decision=fallback_dec,
                ledger=ledger,
                trace=tuple(trace_list),
                escalated_to_agent=True,
                tool_calls_executed=tool_calls,
                fallback_applied=True,
            )
