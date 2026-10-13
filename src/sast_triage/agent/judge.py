"""AgentJudge: Evaluates the verified EvidenceLedger and produces final TriageDecision."""

from __future__ import annotations

import json
from typing import Any

from sast_triage.agent.ledger import EvidenceLedger
from sast_triage.agent.prompts import JUDGE_PROMPT_VERSION, build_judge_prompt
from sast_triage.models import (
    EvidenceRole,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    SanitizedContext,
    StructuredEvidence,
    TriageDecision,
)


class AgentJudge:
    """Evaluates verified facts in the EvidenceLedger to produce an AppSec verdict."""

    def __init__(self, provider: Any = None) -> None:
        self._provider = provider

    def evaluate(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        ledger: EvidenceLedger,
    ) -> TriageDecision:
        """Produce final TriageDecision from verified ledger."""
        if self._provider is None or getattr(self._provider, "is_mock", False):
            return self._heuristic_judge(finding, context, ledger)

        prompt = build_judge_prompt(finding, context, ledger)
        try:
            if hasattr(self._provider, "invoke_raw_prompt"):
                raw_text = self._provider.invoke_raw_prompt(prompt.system_message, prompt.user_message)
                return self._parse_judge_response(raw_text, finding)
            return self._heuristic_judge(finding, context, ledger)
        except Exception:
            return self._heuristic_judge(finding, context, ledger)

    def _parse_judge_response(self, text: str, finding: NormalizedFinding) -> TriageDecision:
        """Parse raw model output adhering to evidence-first structured schema."""
        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        data = json.loads(cleaned)
        verdict_str = data.get("model_verdict", "LIKELY_TP")
        conf_str = data.get("model_confidence", "MEDIUM")
        summary = data.get("summary", "Decision based on agent investigation")

        structured_evidence: list[StructuredEvidence] = []
        for item in data.get("structured_evidence", []):
            try:
                role_val = EvidenceRole(item.get("role", "STEP").upper())
                structured_evidence.append(
                    StructuredEvidence(
                        file=item.get("file", finding.file_path),
                        line=int(item.get("line", finding.start_line)),
                        symbol=item.get("symbol", finding.rule_id),
                        role=role_val,
                        description=item.get("description", "Agent cited evidence"),
                    )
                )
            except Exception:
                continue

        verdict = ModelVerdict.LIKELY_FP if "FP" in verdict_str else ModelVerdict.LIKELY_TP
        confidence = ModelConfidence(conf_str.upper()) if conf_str.upper() in ModelConfidence._value2member_map_ else ModelConfidence.MEDIUM

        return TriageDecision(
            structured_evidence=structured_evidence,
            model_verdict=verdict,
            model_confidence=confidence,
            summary=summary,
            model_version="qwen2.5-coder-14b-agent",
            prompt_version=JUDGE_PROMPT_VERSION,
        )

    def _heuristic_judge(
        self,
        finding: NormalizedFinding,
        context: SanitizedContext,
        ledger: EvidenceLedger,
    ) -> TriageDecision:
        """Deterministic evaluation logic based on facts discovered in EvidenceLedger."""
        cwe_list = [str(c).upper() for c in finding.metadata.get("cwe", [])]
        rule_lower = finding.rule_id.lower()

        # Check for atomic transaction in concurrency findings
        for entry in ledger.entries:
            if entry.tool_name == "check_lock_or_transaction":
                if entry.facts.get("has_atomic_transaction") or entry.facts.get("has_lock"):
                    return TriageDecision(
                        structured_evidence=[
                            StructuredEvidence(
                                file=finding.file_path,
                                line=finding.start_line,
                                symbol="transaction.atomic",
                                role=EvidenceRole.GUARD,
                                description="Atomic transaction block prevents TOCTOU race condition",
                            )
                        ],
                        model_verdict=ModelVerdict.LIKELY_FP,
                        model_confidence=ModelConfidence.HIGH,
                        summary="Verified presence of atomic transaction synchronization surrounding state mutation.",
                        model_version="agent-heuristic-judge",
                        prompt_version=JUDGE_PROMPT_VERSION,
                    )

            if entry.tool_name == "get_route_decorators":
                # Check if route has CSRF protection or auth
                if "csrf" in rule_lower and entry.facts.get("has_csrf_exempt") is False:
                    return TriageDecision(
                        structured_evidence=[
                            StructuredEvidence(
                                file=finding.file_path,
                                line=finding.start_line,
                                symbol="csrf_token",
                                role=EvidenceRole.GUARD,
                                description="CSRF protection is not exempt",
                            )
                        ],
                        model_verdict=ModelVerdict.LIKELY_FP,
                        model_confidence=ModelConfidence.HIGH,
                        summary="Route does not exempt CSRF protection; framework middleware enforces token verification.",
                        model_version="agent-heuristic-judge",
                        prompt_version=JUDGE_PROMPT_VERSION,
                    )

            if entry.tool_name == "get_model_schema":
                if "mass" in rule_lower and entry.facts.get("allowlisted_fields"):
                    return TriageDecision(
                        structured_evidence=[
                            StructuredEvidence(
                                file=finding.file_path,
                                line=finding.start_line,
                                symbol="Meta.fields",
                                role=EvidenceRole.GUARD,
                                description="Model defines strict fields allowlist",
                            )
                        ],
                        model_verdict=ModelVerdict.LIKELY_FP,
                        model_confidence=ModelConfidence.HIGH,
                        summary="Model Meta defines explicit fields allowlist preventing unauthorized parameter binding.",
                        model_version="agent-heuristic-judge",
                        prompt_version=JUDGE_PROMPT_VERSION,
                    )

        # Default: Retain True Positive if user controlled taint is present
        return TriageDecision(
            structured_evidence=[
                StructuredEvidence(
                    file=finding.file_path,
                    line=finding.start_line,
                    symbol=finding.rule_id,
                    role=EvidenceRole.SINK,
                    description="Identified potential vulnerable sink in target code",
                )
            ],
            model_verdict=ModelVerdict.LIKELY_TP,
            model_confidence=ModelConfidence.HIGH,
            summary="Evidence ledger did not find valid security controls or constant proofs protecting the vulnerable target.",
            model_version="agent-heuristic-judge",
            prompt_version=JUDGE_PROMPT_VERSION,
        )
