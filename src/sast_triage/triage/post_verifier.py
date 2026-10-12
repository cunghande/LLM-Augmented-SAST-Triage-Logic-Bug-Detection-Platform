"""Deterministic post-LLM verifier cross-checking structured evidence against SanitizedContext."""

from __future__ import annotations

import json
from dataclasses import dataclass

from sast_triage.models import (
    EvidenceRole,
    ModelVerdict,
    NormalizedFinding,
    SanitizedContext,
    StructuredEvidence,
    TriageDecision,
)


@dataclass(frozen=True, slots=True)
class PostVerificationResult:
    """Result of deterministic post-LLM validation."""

    is_valid: bool
    violations: tuple[str, ...]
    escalation_reason: str | None
    verified_decision: TriageDecision


def verify_post_triage_decision(
    decision: TriageDecision,
    context: SanitizedContext,
    finding: NormalizedFinding,
) -> PostVerificationResult:
    """Fail-closed verifier cross-checking LLM citations against safe context facts."""
    violations: list[str] = []

    if not decision.structured_evidence:
        return PostVerificationResult(
            is_valid=True,
            violations=(),
            escalation_reason=None,
            verified_decision=decision,
        )

    context_text = context.sanitized_snippet or ""
    verified_files: set[str] = {finding.file_path.replace("\\", "/")}
    verified_symbols: set[str] = set()
    verified_controls: set[str] = set()
    static_negative_taint = False

    if context_text.lstrip().startswith("{"):
        try:
            payload = json.loads(context_text)
            if isinstance(payload, dict):
                finding_block = payload.get("finding", {})
                if isinstance(finding_block, dict) and "file_path" in finding_block:
                    verified_files.add(str(finding_block["file_path"]).replace("\\", "/"))

                det = payload.get("deterministic_verification", {})
                if isinstance(det, dict):
                    static_negative_taint = bool(det.get("negative_taint_conclusion_proven"))
                    for ctrl in det.get("effective_controls", []):
                        verified_controls.add(str(ctrl).lower())

                code_block = payload.get("relevant_code", {})
                if isinstance(code_block, dict):
                    raw_code = str(code_block.get("code", ""))
                    for token in raw_code.replace("(", " ").replace(")", " ").replace(".", " ").replace("=", " ").split():
                        if token.isidentifier():
                            verified_symbols.add(token.lower())

                sec_controls = payload.get("security_controls", [])
                if isinstance(sec_controls, list):
                    for c in sec_controls:
                        if isinstance(c, dict) and "symbol" in c:
                            sym = str(c["symbol"]).lower()
                            verified_symbols.add(sym)
                            if c.get("effective") is True or c.get("on_taint_path") is True:
                                verified_controls.add(sym)

                for block_name in ("source", "sink"):
                    block = payload.get(block_name)
                    if isinstance(block, dict):
                        if "expression" in block:
                            verified_symbols.add(str(block["expression"]).lower())
                        if "file_path" in block:
                            verified_files.add(str(block["file_path"]).replace("\\", "/"))
        except json.JSONDecodeError:
            pass

    for ev in decision.structured_evidence:
        norm_ev_sym = ev.symbol.lower()

        if verified_symbols and norm_ev_sym not in verified_symbols:
            violations.append(
                f"Symbol '{ev.symbol}' cited by LLM does not exist in SanitizedContext."
            )

        if ev.role == EvidenceRole.GUARD:
            if verified_controls and norm_ev_sym not in verified_controls:
                violations.append(
                    f"LLM claims guard/sanitizer '{ev.symbol}', but static analysis found no verified effective control."
                )

    if decision.model_verdict == ModelVerdict.LIKELY_TP and static_negative_taint:
        violations.append(
            "Model verdict LIKELY_TP directly contradicts verified BOUNDED_LOCAL_NEGATIVE_PROOF."
        )

    if violations:
        downgraded = decision.model_copy(
            update={
                "model_verdict": ModelVerdict.NEEDS_REVIEW,
                "assumptions": [
                    *decision.assumptions,
                    f"Post-LLM verifier rejected citations: {'; '.join(violations)}",
                ],
            }
        )
        return PostVerificationResult(
            is_valid=False,
            violations=tuple(violations),
            escalation_reason=f"Post-LLM verifier rejection: {violations[0]}",
            verified_decision=downgraded,
        )

    return PostVerificationResult(
        is_valid=True,
        violations=(),
        escalation_reason=None,
        verified_decision=decision,
    )
