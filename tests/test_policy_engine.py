"""Unit tests for Conservative PolicyEngine."""

import json

import pytest
from pydantic import ValidationError

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    MissingContextReason,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    ProcessingError,
    ProcessingStage,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
    TriageDecision,
)
from sast_triage.policy.engine import POLICY_VERSION, apply_policy

CANARY = "POLICY_SOURCE_CANARY_DO_NOT_COPY"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    severity: Severity = Severity.HIGH,
    finding_id: str = "find123456789012",
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=scanner,
        finding_type=FindingType.SAST if scanner == ScannerType.SEMGREP else FindingType.SECRET,
        rule_id="rule-01",
        file_path="src/app.py",
        start_line=1,
        end_line=1,
        severity=severity,
        message="Finding message",
    )


def make_context(
    finding_id: str = "find123456789012",
    context_available: bool = True,
    path_category: PathCategory = PathCategory.PRODUCTION,
    truncated: bool = False,
    missing_context_reasons: list[MissingContextReason] | None = None,
) -> SanitizedContext:
    if missing_context_reasons is None:
        missing_context_reasons = [] if context_available else [MissingContextReason.PYTHON_AST_PARSE_FAILED]

    return SanitizedContext(
        finding_id=finding_id,
        sanitized_snippet="def fn(): pass\n" if context_available else None,
        context_strategy=ContextStrategy.PYTHON_FUNCTION if context_available else ContextStrategy.UNAVAILABLE,
        context_start_line=1 if context_available else None,
        context_end_line=5 if context_available else None,
        finding_start_line=1,
        finding_end_line=1,
        path_category=path_category,
        source_kind=SourceKind.WORKTREE,
        context_available=context_available,
        missing_context_reasons=missing_context_reasons,
        truncated=truncated,
    )


def make_complete_taint_context(finding_id: str = "find123456789012") -> SanitizedContext:
    """Create a safe evidence projection proving a complete unsafe taint path."""
    context = make_context(finding_id=finding_id)
    return context.model_copy(
        update={
            "sanitized_snippet": json.dumps(
                {
                    "context_completeness": {"status": "complete"},
                    "deterministic_verification": {
                        "mechanism": "taint_flow",
                        "evidence_complete": True,
                        "has_evidence_conflict": False,
                        "source_user_controlled": True,
                        "source_reaches_sink": True,
                    },
                }
            )
        }
    )


def make_triage_decision(
    verdict: ModelVerdict = ModelVerdict.LIKELY_TP,
    confidence: ModelConfidence = ModelConfidence.HIGH,
    evidence: list[str] | None = None,
) -> TriageDecision:
    if evidence is None:
        evidence = [f"Evidence containing {CANARY}"]

    return TriageDecision(
        model_verdict=verdict,
        model_confidence=confidence,
        summary="Model summary",
        evidence=evidence,
        missing_information=[],
        assumptions=[],
        model_version="fake-triage-v1",
        prompt_version="v1.0",
    )


def make_processing_error(
    stage: ProcessingStage = ProcessingStage.TRIAGE,
    finding_id: str | None = "find123456789012",
) -> ProcessingError:
    return ProcessingError(
        finding_id=finding_id,
        scanner=ScannerType.SEMGREP,
        stage=stage,
        error_code="TEST_ERROR",
        safe_message="Test safe error message",
        retryable=False,
    )


# --- 1. Provider Failure Tests ---


def test_provider_failure_with_triage_error() -> None:
    """Requirement Protected: Null decision with TRIAGE stage error yields PolicyAction.TRIAGE_ERROR.

    Expected Result: action == TRIAGE_ERROR, escalated == False.
    Test Category: Provider Failure
    """
    finding = make_finding()
    ctx = make_context()
    err = make_processing_error(stage=ProcessingStage.TRIAGE)

    res = apply_policy(finding, ctx, triage_decision=None, processing_errors=(err,))

    assert res.action == PolicyAction.TRIAGE_ERROR
    assert res.policy_version == POLICY_VERSION
    assert res.escalated is False
    assert res.escalation_reason is None


def test_provider_failure_without_triage_error_rejected() -> None:
    """Requirement Protected: Null decision without TRIAGE stage error raises POLICY_INVALID_INPUT.

    Expected Result: SastTriageError raised.
    Test Category: Contract Validation
    """
    finding = make_finding()
    ctx = make_context()

    with pytest.raises(SastTriageError) as exc:
        apply_policy(finding, ctx, triage_decision=None, processing_errors=())

    assert exc.value.error_code == "POLICY_INVALID_INPUT"


def test_provider_failure_does_not_create_manual_review() -> None:
    """Requirement Protected: Provider failure produces TRIAGE_ERROR action, NOT MANUAL_REVIEW.

    Expected Result: action == TRIAGE_ERROR.
    Test Category: Provider Failure
    """
    finding = make_finding()
    ctx = make_context()
    err = make_processing_error(stage=ProcessingStage.TRIAGE)

    res = apply_policy(finding, ctx, triage_decision=None, processing_errors=(err,))
    assert res.action != PolicyAction.MANUAL_REVIEW
    assert res.action == PolicyAction.TRIAGE_ERROR


# --- 2. Context Unavailable Tests ---


def test_context_unavailable_likely_tp_escalated() -> None:
    """Requirement Protected: Unavailable context with LIKELY_TP verdict yields MANUAL_REVIEW with escalated=True.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Context Unavailable
    """
    finding = make_finding()
    ctx = make_context(context_available=False)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True
    assert res.escalation_reason is not None


def test_context_unavailable_likely_fp_escalated() -> None:
    """Requirement Protected: Unavailable context with LIKELY_FP verdict yields MANUAL_REVIEW with escalated=True.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Context Unavailable
    """
    finding = make_finding()
    ctx = make_context(context_available=False)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_context_unavailable_needs_review_not_escalated() -> None:
    """Requirement Protected: Unavailable context with NEEDS_REVIEW verdict yields MANUAL_REVIEW with escalated=False.

    Expected Result: action == MANUAL_REVIEW, escalated == False.
    Test Category: Context Unavailable
    """
    finding = make_finding()
    ctx = make_context(context_available=False)
    dec = make_triage_decision(verdict=ModelVerdict.NEEDS_REVIEW)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is False


def test_context_sanitization_failed_yields_manual_review() -> None:
    """Requirement Protected: CONTEXT_SANITIZATION_FAILED in missing reasons forces MANUAL_REVIEW.

    Expected Result: action == MANUAL_REVIEW.
    Test Category: Context Unavailable
    """
    finding = make_finding()
    ctx = make_context(
        context_available=False,
        missing_context_reasons=[MissingContextReason.CONTEXT_SANITIZATION_FAILED],
    )
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


# --- 3. SANITIZE Stage Errors Tests ---


def test_sanitize_error_forces_manual_review() -> None:
    """Requirement Protected: SANITIZE stage error prevents FP_CANDIDATE classification and forces MANUAL_REVIEW.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Sanitize Error Escalation
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.LOW)
    ctx = make_context(path_category=PathCategory.TEST)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)
    err = make_processing_error(stage=ProcessingStage.SANITIZE)

    res = apply_policy(finding, ctx, dec, processing_errors=(err,))

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


# --- 4. TP Behavior Tests ---


def test_likely_tp_high_confidence_classified_tp() -> None:
    """Requirement Protected: LIKELY_TP with HIGH confidence yields PolicyAction.LIKELY_TP.

    Expected Result: action == LIKELY_TP, escalated == False.
    Test Category: TP Classification
    """
    finding = make_finding()
    ctx = make_complete_taint_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.LIKELY_TP
    assert res.escalated is False


def test_likely_tp_configuration_with_complete_sink_evidence_is_tp() -> None:
    """A directly observed unsafe framework configuration does not require dataflow."""
    finding = make_finding().model_copy(
        update={"rule_id": "python.flask.security.audit.secure-set-cookie"}
    )
    context = make_context().model_copy(
        update={
            "sanitized_snippet": json.dumps(
                {
                    "context_completeness": {"status": "complete"},
                    "deterministic_verification": {
                        "mechanism": "configuration",
                        "evidence_complete": True,
                        "has_evidence_conflict": False,
                        "unsafe_configuration_observed": True,
                    },
                }
            )
        }
    )
    decision = make_triage_decision(
        verdict=ModelVerdict.LIKELY_TP,
        confidence=ModelConfidence.HIGH,
    )

    result = apply_policy(finding, context, decision)

    assert result.action == PolicyAction.LIKELY_TP
    assert result.escalated is False


def test_likely_tp_without_deterministic_support_is_manual_review() -> None:
    """High-confidence TP opinions without a proven rule mechanism remain reviewable."""
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True
    assert res.escalation_reason == "Model TP opinion lacks deterministic rule-mechanism support."


def test_likely_tp_medium_confidence_escalated_to_manual_review() -> None:
    """Requirement Protected: LIKELY_TP with MEDIUM confidence is escalated to MANUAL_REVIEW.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: TP Escalation
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.MEDIUM)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_likely_tp_low_confidence_escalated_to_manual_review() -> None:
    """Requirement Protected: LIKELY_TP with LOW confidence is escalated to MANUAL_REVIEW.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: TP Escalation
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.LOW)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


# --- 5. Semgrep FP Behavior Tests ---


def test_semgrep_likely_fp_high_severity_escalated() -> None:
    """Requirement Protected: High-severity Semgrep LIKELY_FP findings cannot become FP candidates.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Semgrep Policy
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.HIGH)
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_semgrep_likely_fp_critical_severity_escalated() -> None:
    """Requirement Protected: Critical-severity Semgrep LIKELY_FP findings cannot become FP candidates.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Semgrep Policy
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.CRITICAL)
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_semgrep_likely_fp_medium_severity_fp_candidate() -> None:
    """Requirement Protected: Medium-severity Semgrep LIKELY_FP finding with HIGH confidence becomes FP_CANDIDATE.

    Expected Result: action == FP_CANDIDATE, escalated == False.
    Test Category: Semgrep Policy
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.MEDIUM)
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.FP_CANDIDATE
    assert res.escalated is False


def test_semgrep_likely_fp_low_severity_fp_candidate() -> None:
    """Requirement Protected: Low-severity Semgrep LIKELY_FP finding with HIGH confidence becomes FP_CANDIDATE.

    Expected Result: action == FP_CANDIDATE, escalated == False.
    Test Category: Semgrep Policy
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.LOW)
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.FP_CANDIDATE
    assert res.escalated is False


def test_semgrep_truncated_context_fp_blocked() -> None:
    """Requirement Protected: Truncated context blocks FP_CANDIDATE status for Semgrep findings.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Truncation Guard
    """
    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.LOW)
    ctx = make_context(truncated=True)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


# --- 6. Gitleaks FP Behavior Tests ---


def test_gitleaks_fp_test_path_candidate() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in TEST path becomes FP_CANDIDATE.

    Expected Result: action == FP_CANDIDATE, escalated == False.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.TEST)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.FP_CANDIDATE
    assert res.escalated is False


def test_gitleaks_fp_fixture_path_candidate() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in FIXTURE path becomes FP_CANDIDATE.

    Expected Result: action == FP_CANDIDATE, escalated == False.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.FIXTURE)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.FP_CANDIDATE
    assert res.escalated is False


def test_gitleaks_fp_example_path_candidate() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in EXAMPLE path becomes FP_CANDIDATE.

    Expected Result: action == FP_CANDIDATE, escalated == False.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.EXAMPLE)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.FP_CANDIDATE
    assert res.escalated is False


def test_gitleaks_fp_production_path_escalated() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in PRODUCTION path cannot become FP_CANDIDATE.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.PRODUCTION)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_gitleaks_fp_unknown_path_escalated() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in UNKNOWN path cannot become FP_CANDIDATE.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.UNKNOWN)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


def test_gitleaks_fp_documentation_path_escalated() -> None:
    """Requirement Protected: Gitleaks LIKELY_FP finding in DOCUMENTATION path cannot become FP_CANDIDATE.

    Expected Result: action == MANUAL_REVIEW, escalated == True.
    Test Category: Gitleaks Policy
    """
    finding = make_finding(scanner=ScannerType.GITLEAKS)
    ctx = make_context(path_category=PathCategory.DOCUMENTATION)
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_FP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is True


# --- 7. Model Review Tests ---


def test_model_needs_review_yields_manual_review() -> None:
    """Requirement Protected: Model verdict NEEDS_REVIEW with valid context yields MANUAL_REVIEW with escalated=False.

    Expected Result: action == MANUAL_REVIEW, escalated == False.
    Test Category: Model Review
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.NEEDS_REVIEW)

    res = apply_policy(finding, ctx, dec)

    assert res.action == PolicyAction.MANUAL_REVIEW
    assert res.escalated is False


# --- 8. Consistency, Immutability & Security Tests ---


def test_mismatched_finding_and_context_id_rejected() -> None:
    """Requirement Protected: Mismatch between finding and context instance IDs is rejected.

    Expected Result: SastTriageError with error_code POLICY_INVALID_INPUT raised.
    Test Category: Input Invariant
    """
    finding = make_finding(finding_id="id-1")
    ctx = make_context(finding_id="id-2")
    dec = make_triage_decision()

    with pytest.raises(SastTriageError) as exc:
        apply_policy(finding, ctx, dec)

    assert exc.value.error_code == "POLICY_INVALID_INPUT"


def test_mismatched_processing_error_finding_id_rejected() -> None:
    """Requirement Protected: Processing error with mismatched finding_id is rejected.

    Expected Result: SastTriageError with error_code POLICY_INVALID_INPUT raised.
    Test Category: Input Invariant
    """
    finding = make_finding(finding_id="id-1")
    ctx = make_context(finding_id="id-1")
    dec = make_triage_decision()
    err = make_processing_error(finding_id="id-2")

    with pytest.raises(SastTriageError) as exc:
        apply_policy(finding, ctx, dec, processing_errors=(err,))

    assert exc.value.error_code == "POLICY_INVALID_INPUT"


def test_policy_engine_does_not_mutate_inputs() -> None:
    """Requirement Protected: apply_policy() does NOT mutate input models.

    Expected Result: Input fields remain identical before and after.
    Test Category: Immutability
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision()

    orig_severity = finding.severity
    apply_policy(finding, ctx, dec)

    assert finding.severity == orig_severity


def test_reasons_do_not_contain_canary_or_model_evidence() -> None:
    """Requirement Protected: PolicyDecision reasons DO NOT copy model evidence or canary.

    Expected Result: CANARY absent from reasons and escalation_reason.
    Test Category: Security Boundary
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.LOW)

    res = apply_policy(finding, ctx, dec)

    assert not any(CANARY in r for r in res.reasons)
    if res.escalation_reason:
        assert CANARY not in res.escalation_reason


def test_policy_decision_frozen() -> None:
    """Requirement Protected: PolicyDecision is a frozen Pydantic model.

    Expected Result: Modifying fields raises ValidationError.
    Test Category: Model Invariant
    """
    finding = make_finding()
    ctx = make_context()
    dec = make_triage_decision(verdict=ModelVerdict.LIKELY_TP, confidence=ModelConfidence.HIGH)

    res = apply_policy(finding, ctx, dec)

    with pytest.raises(ValidationError):
        res.action = PolicyAction.MANUAL_REVIEW  # type: ignore[misc]
