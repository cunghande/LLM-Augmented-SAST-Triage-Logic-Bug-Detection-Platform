"""AgentPlanner: Selects next investigation action or DONE based on evidence ledger."""

from __future__ import annotations

import json
from typing import Any

from sast_triage.agent.models import AgentAction, PlannerOutput
from sast_triage.agent.ledger import EvidenceLedger
from sast_triage.agent.prompts import build_planner_prompt
from sast_triage.models import NormalizedFinding, SanitizedContext


class AgentPlanner:
    """Invokes the LLM Planner role to select the next allowlisted tool call."""

    def __init__(self, provider: Any = None) -> None:
        self._provider = provider

    def plan_next_action(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        ledger: EvidenceLedger,
        remaining_steps: int,
    ) -> PlannerOutput:
        """Decide the next investigative action."""
        if self._provider is None or getattr(self._provider, "is_mock", False):
            return self._heuristic_plan(finding, context, ledger, remaining_steps)

        prompt = build_planner_prompt(finding, context, ledger, remaining_steps)
        try:
            # We call the provider with planner prompt
            # TriageProvider interface takes TriageInput, or provider can execute custom prompt
            if hasattr(self._provider, "invoke_raw_prompt"):
                raw_res = self._provider.invoke_raw_prompt(prompt.system_message, prompt.user_message)
                return self._parse_planner_response(raw_res)
            return self._heuristic_plan(finding, context, ledger, remaining_steps)
        except Exception as exc:
            return PlannerOutput(
                thought=f"Encountered planner exception: {exc}. Concluding safely.",
                action=AgentAction(tool="DONE", parameters={"reason": "planner_error"}),
            )

    def _parse_planner_response(self, text: str) -> PlannerOutput:
        """Parse raw model text into PlannerOutput."""
        # Try direct or fenced JSON extraction
        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        data = json.loads(cleaned)
        thought = data.get("thought", "Proceeding with next tool")
        act_dict = data.get("action", {})
        tool = act_dict.get("tool", "DONE")
        params = act_dict.get("parameters", {})
        return PlannerOutput(
            thought=thought,
            action=AgentAction(tool=tool, parameters=params),
        )

    def _heuristic_plan(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        ledger: EvidenceLedger,
        remaining_steps: int,
    ) -> PlannerOutput:
        """Deterministic, heuristic planner for test suite and reproducible benchmarks."""
        cwe_list = [str(c).upper() for c in finding.metadata.get("cwe", [])]
        rule_lower = finding.rule_id.lower()
        file_path = finding.file_path
        func_name = context.enclosing_function or "handle_request"

        # 1. IDOR / Authz
        if any(c in ("CWE-639", "CWE-284") for c in cwe_list) or "idor" in rule_lower:
            if not ledger.has_signature(f"get_route_decorators:{file_path}:{func_name}"):
                return PlannerOutput(
                    thought="Inspect route decorators to verify authentication constraints.",
                    action=AgentAction(
                        tool="get_route_decorators",
                        parameters={"symbol_name": func_name, "file_path": file_path},
                    ),
                )
            if not ledger.has_signature(f"read_function:{file_path}:{func_name}"):
                return PlannerOutput(
                    thought="Inspect function implementation to check object-level ownership filter.",
                    action=AgentAction(
                        tool="read_function",
                        parameters={"symbol_name": func_name, "file_path": file_path},
                    ),
                )
            return PlannerOutput(
                thought="Sufficient authorization context collected in ledger.",
                action=AgentAction(tool="DONE", parameters={}),
            )

        # 2. Concurrency / TOCTOU
        if any(c in ("CWE-362", "CWE-367") for c in cwe_list) or "race" in rule_lower:
            if not ledger.has_signature(f"check_lock_or_transaction:{file_path}:{func_name}"):
                return PlannerOutput(
                    thought="Check for atomic transaction or lock synchronization.",
                    action=AgentAction(
                        tool="check_lock_or_transaction",
                        parameters={"symbol_name": func_name, "file_path": file_path},
                    ),
                )
            return PlannerOutput(
                thought="Concurrency facts recorded.",
                action=AgentAction(tool="DONE", parameters={}),
            )

        # 3. Injection / General Taint
        if not ledger.has_signature(f"read_function:{file_path}:{func_name}"):
            return PlannerOutput(
                thought="Read enclosing function to examine sink call and sanitizer usage.",
                action=AgentAction(
                    tool="read_function",
                    parameters={"symbol_name": func_name, "file_path": file_path},
                ),
            )
        if not ledger.has_signature(f"find_callees:{file_path}:{func_name}"):
            return PlannerOutput(
                thought="Inspect external calls from enclosing function.",
                action=AgentAction(
                    tool="find_callees",
                    parameters={"symbol_name": func_name, "file_path": file_path},
                ),
            )

        return PlannerOutput(
            thought="Investigation complete; collected required facts.",
            action=AgentAction(tool="DONE", parameters={}),
        )
