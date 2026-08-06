"""Conservative PolicyEngine for SAST Triage Platform.

Applies deterministic, conservative rules to convert LLM opinions and pipeline state
into system policy decisions (PolicyDecision).

Security & Conservative Principles:
- Does NOT execute code or call external services.
- Never promotes high-severity Semgrep or non-test Gitleaks findings to FP_CANDIDATE.
- Context unavailable or sanitization issues default to MANUAL_REVIEW.
- Never outputs raw source text, secrets, or exception payloads in reasons.
"""

import json

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    MissingContextReason,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    PolicyDecision,
    ProcessingError,
    ProcessingStage,
    SanitizedContext,
    ScannerType,
    Severity,
    TriageDecision,
)

POLICY_VERSION: str = "conservative-policy-v1"


def _evidence_is_incomplete(context: SanitizedContext) -> bool:
    """Read only the safe completeness flag from a projected evidence package."""
    snippet = context.sanitized_snippet
    if not snippet or not snippet.lstrip().startswith("{"):
        return MissingContextReason.PYTHON_AST_PARSE_FAILED in context.missing_context_reasons
    try:
        payload = json.loads(snippet)
    except json.JSONDecodeError:
        return True
    if not isinstance(payload, dict):
        return True
    completeness = payload.get("context_completeness")
    if not isinstance(completeness, dict):
        return True
    return completeness.get("status") != "complete"


def apply_policy(
    finding: NormalizedFinding,
    context: SanitizedContext,
    triage_decision: TriageDecision | None,
    processing_errors: tuple[ProcessingError, ...] = (),
    artifact_repository_match: ArtifactRepositoryMatch = ArtifactRepositoryMatch.VERIFIED,
) -> PolicyDecision:
    """Apply conservative policy rules to generate a system PolicyDecision.

    Args:
        finding: Target NormalizedFinding.
        context: SanitizedContext for the finding.
        triage_decision: Optional TriageDecision from provider (None if provider failed).
        processing_errors: Tuple of ProcessingError instances collected during pipeline execution.

    Returns:
        A frozen, validated PolicyDecision Pydantic model.

    Raises:
        SastTriageError: On invalid input state or mismatched identifiers.
    """
    # 1. Input Consistency Validation
    if context.finding_id != finding.finding_instance_id:
        raise SastTriageError(
            safe_message="context.finding_id does not match finding.finding_instance_id.",
            error_code="POLICY_INVALID_INPUT",
            retryable=False,
        )

    for err in processing_errors:
        if err.finding_id is not None and err.finding_id != finding.finding_instance_id:
            raise SastTriageError(
                safe_message="processing_errors contains an error with mismatched finding_id.",
                error_code="POLICY_INVALID_INPUT",
                retryable=False,
            )

    # 2. Rule 1 — Provider Failure Check
    if triage_decision is None:
        has_triage_error = any(err.stage == ProcessingStage.TRIAGE for err in processing_errors)
        if not has_triage_error:
            raise SastTriageError(
                safe_message="triage_decision is None but no TRIAGE stage error was provided.",
                error_code="POLICY_INVALID_INPUT",
                retryable=False,
            )

        return PolicyDecision(
            action=PolicyAction.TRIAGE_ERROR,
            reasons=["LLM provider failure occurred during triage stage."],
            policy_version=POLICY_VERSION,
            escalated=False,
            escalation_reason=None,
        )

    if artifact_repository_match == ArtifactRepositoryMatch.MISMATCH:
        raise SastTriageError(
            safe_message="Scanner artifact does not belong to the target repository.",
            error_code="PIPELINE_ARTIFACT_REPOSITORY_MISMATCH",
            retryable=False,
        )
    if artifact_repository_match in (ArtifactRepositoryMatch.UNVERIFIED, ArtifactRepositoryMatch.PARTIAL):
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Scanner artifact repository binding is not fully verified."],
            policy_version=POLICY_VERSION,
            escalated=True,
            escalation_reason="Artifact binding is unverified or partial.",
        )

    # Helper flags for errors
    has_sanitize_error = any(err.stage == ProcessingStage.SANITIZE for err in processing_errors)
    has_sanitization_failed = MissingContextReason.CONTEXT_SANITIZATION_FAILED in context.missing_context_reasons

    # 3. Rule 2 — Context Unavailable
    if not context.context_available:
        escalated = triage_decision.model_verdict in (ModelVerdict.LIKELY_TP, ModelVerdict.LIKELY_FP)
        escalation_reason = (
            "Model verdict was produced on unavailable context." if escalated else None
        )
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Source code context is unavailable for this finding."],
            policy_version=POLICY_VERSION,
            escalated=escalated,
            escalation_reason=escalation_reason,
        )

    # 4. Rule 3 — Existing SANITIZE Stage Errors
    if has_sanitize_error:
        escalated = triage_decision.model_verdict in (ModelVerdict.LIKELY_TP, ModelVerdict.LIKELY_FP)
        escalation_reason = (
            "Model verdict was produced with context sanitization errors." if escalated else None
        )
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Sanitization stage errors require manual review."],
            policy_version=POLICY_VERSION,
            escalated=escalated,
            escalation_reason=escalation_reason,
        )

    # Evidence expansion is advisory to the model but authoritative for policy
    # sufficiency: incomplete paths can never become automatic TP/FP decisions.
    if finding.scanner == ScannerType.SEMGREP and _evidence_is_incomplete(context):
        escalated = triage_decision.model_verdict in (
            ModelVerdict.LIKELY_TP,
            ModelVerdict.LIKELY_FP,
        )
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Context evidence is incomplete after bounded expansion."],
            policy_version=POLICY_VERSION,
            escalated=escalated,
            escalation_reason=(
                "Model verdict was produced without complete source-to-sink evidence."
                if escalated
                else None
            ),
        )

    # 5. Rule 4 — Model Verdict is NEEDS_REVIEW
    if triage_decision.model_verdict == ModelVerdict.NEEDS_REVIEW:
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["LLM provider requested manual review."],
            policy_version=POLICY_VERSION,
            escalated=False,
            escalation_reason=None,
        )

    # 6. Rule 5 — Model Verdict is LIKELY_TP
    if triage_decision.model_verdict == ModelVerdict.LIKELY_TP:
        if triage_decision.model_confidence == ModelConfidence.HIGH:
            return PolicyDecision(
                action=PolicyAction.LIKELY_TP,
                reasons=["Model verdict is LIKELY_TP with HIGH confidence."],
                policy_version=POLICY_VERSION,
                escalated=False,
                escalation_reason=None,
            )

        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Model verdict is LIKELY_TP but confidence is not HIGH."],
            policy_version=POLICY_VERSION,
            escalated=True,
            escalation_reason=f"Model confidence '{triage_decision.model_confidence.value}' is insufficient for automatic TP classification.",
        )

    # 7. Rule 6 — Model Verdict is LIKELY_FP with non-HIGH Confidence
    if triage_decision.model_confidence != ModelConfidence.HIGH:
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Model verdict is LIKELY_FP but confidence is not HIGH."],
            policy_version=POLICY_VERSION,
            escalated=True,
            escalation_reason=f"Model confidence '{triage_decision.model_confidence.value}' is insufficient for FP candidate status.",
        )

    # 8. Rules 7 & 8 — Model Verdict is LIKELY_FP with HIGH Confidence
    # Check truncated context or sanitization failures blocking FP candidate
    if context.truncated or has_sanitization_failed:
        return PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Truncated or sanitized context prevents automatic FP candidate classification."],
            policy_version=POLICY_VERSION,
            escalated=True,
            escalation_reason="Context is truncated or has sanitization issues; FP candidate status is blocked.",
        )

    # Rule 7 — Semgrep Scanner
    if finding.scanner == ScannerType.SEMGREP:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            return PolicyDecision(
                action=PolicyAction.MANUAL_REVIEW,
                reasons=["High-severity Semgrep findings cannot become FP candidates."],
                policy_version=POLICY_VERSION,
                escalated=True,
                escalation_reason=f"Severity '{finding.severity.value}' is too high for automatic FP candidate classification.",
            )

        return PolicyDecision(
            action=PolicyAction.FP_CANDIDATE,
            reasons=["Semgrep finding classified as FP_CANDIDATE."],
            policy_version=POLICY_VERSION,
            escalated=False,
            escalation_reason=None,
        )

    # Rule 8 — Gitleaks Scanner
    allowed_gitleaks_paths = (PathCategory.TEST, PathCategory.FIXTURE, PathCategory.EXAMPLE)
    if context.path_category in allowed_gitleaks_paths:
        return PolicyDecision(
            action=PolicyAction.FP_CANDIDATE,
            reasons=["Gitleaks finding in test, fixture, or example path classified as FP_CANDIDATE."],
            policy_version=POLICY_VERSION,
            escalated=False,
            escalation_reason=None,
        )

    return PolicyDecision(
        action=PolicyAction.MANUAL_REVIEW,
        reasons=["Gitleaks FP candidates are restricted to test, fixture, or example paths."],
        policy_version=POLICY_VERSION,
        escalated=True,
        escalation_reason=f"Path category '{context.path_category.value}' is not eligible for Gitleaks FP candidate status.",
    )
