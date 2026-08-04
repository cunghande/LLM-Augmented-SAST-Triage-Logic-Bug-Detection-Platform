"""Unit tests for domain models and security invariants."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sast_triage.models import (
    ArtifactRepositoryMatch,
    ContextStrategy,
    FindingType,
    MissingContextReason,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    PolicyDecision,
    ProcessingError,
    ProcessingStage,
    RunMetadata,
    SanitizedContext,
    ScannerParseResult,
    ScannerType,
    Severity,
    SourceKind,
    TriageDecision,
    TriageInput,
    TriageResult,
)

# --- Fixtures ---


@pytest.fixture
def semgrep_finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="semgrep-001",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.lang.security.audit.eval-use",
        rule_name="Use of eval",
        file_path="app/main.py",
        start_line=15,
        end_line=20,
        severity=Severity.HIGH,
        message="Dynamic code execution via eval() detected.",
        snippet="eval(user_input)",
        metadata={"cwe": "CWE-95"},
    )


@pytest.fixture
def gitleaks_finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="gitleaks-001",
        scanner=ScannerType.GITLEAKS,
        finding_type=FindingType.SECRET,
        rule_id="aws-access-key",
        rule_name="AWS Access Key",
        file_path="config/settings.py",
        start_line=5,
        end_line=5,
        severity=Severity.UNKNOWN,
        message="AWS Access Key ID found",
        snippet="AWS_KEY = '<REDACTED_SECRET>'",
        metadata={"secret_category": "cloud_credential"},
    )


@pytest.fixture
def valid_context(semgrep_finding: NormalizedFinding) -> SanitizedContext:
    return SanitizedContext(
        finding_id=semgrep_finding.finding_instance_id,
        sanitized_snippet="def process():\n    eval(user_input)",
        context_strategy=ContextStrategy.PYTHON_FUNCTION,
        context_start_line=10,
        context_end_line=25,
        finding_start_line=15,
        finding_end_line=20,
        enclosing_function="process",
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
        missing_context_reasons=[],
        redactions_applied=0,
        redaction_types=[],
        truncated=False,
    )


@pytest.fixture
def valid_triage_decision() -> TriageDecision:
    return TriageDecision(
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="User input flows directly into eval() without sanitization.",
        evidence=["eval(user_input) call at line 15"],
        missing_information=[],
        assumptions=["user_input comes from request param"],
        model_version="fake-llm-v1",
        prompt_version="1.0.0",
    )


@pytest.fixture
def valid_policy_decision() -> PolicyDecision:
    return PolicyDecision(
        action=PolicyAction.LIKELY_TP,
        reasons=["High confidence LIKELY_TP on production code"],
        policy_version="1.0.0",
        escalated=False,
    )


# --- Tests: NormalizedFinding ---


def test_normalized_finding_semgrep_valid(semgrep_finding: NormalizedFinding) -> None:
    assert semgrep_finding.scanner == ScannerType.SEMGREP
    assert semgrep_finding.finding_type == FindingType.SAST
    assert semgrep_finding.file_path == "app/main.py"


def test_normalized_finding_gitleaks_valid(gitleaks_finding: NormalizedFinding) -> None:
    assert gitleaks_finding.scanner == ScannerType.GITLEAKS
    assert gitleaks_finding.finding_type == FindingType.SECRET
    assert "<REDACTED_SECRET>" in gitleaks_finding.snippet


def test_normalized_finding_rejects_type_mismatch() -> None:
    with pytest.raises(ValidationError, match="SEMGREP scanner findings must have SAST"):
        NormalizedFinding(
            finding_instance_id="err-1",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SECRET,  # Invalid for Semgrep
            rule_id="rule",
            file_path="app.py",
            start_line=1,
            severity=Severity.HIGH,
            message="msg",
            snippet="snip",
        )

    with pytest.raises(ValidationError, match="GITLEAKS scanner findings must have SECRET"):
        NormalizedFinding(
            finding_instance_id="err-2",
            scanner=ScannerType.GITLEAKS,
            finding_type=FindingType.SAST,  # Invalid for Gitleaks
            rule_id="rule",
            file_path="app.py",
            start_line=1,
            severity=Severity.HIGH,
            message="msg",
            snippet="snip",
        )


def test_normalized_finding_rejects_absolute_path() -> None:
    with pytest.raises(ValidationError, match="relative path"):
        NormalizedFinding(
            finding_instance_id="abs-1",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="rule",
            file_path="/var/www/app/main.py",
            start_line=1,
            severity=Severity.HIGH,
            message="msg",
            snippet="code",
        )


def test_normalized_finding_rejects_invalid_lines() -> None:
    with pytest.raises(ValidationError, match="start_line must be greater than 0"):
        NormalizedFinding(
            finding_instance_id="line-0",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="rule",
            file_path="app.py",
            start_line=0,
            severity=Severity.HIGH,
            message="msg",
            snippet="code",
        )

    with pytest.raises(ValidationError, match="end_line must be greater than or equal to start_line"):
        NormalizedFinding(
            finding_instance_id="end-line-err",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="rule",
            file_path="app.py",
            start_line=10,
            end_line=5,
            severity=Severity.HIGH,
            message="msg",
            snippet="code",
        )


def test_normalized_finding_frozen(semgrep_finding: NormalizedFinding) -> None:
    with pytest.raises(ValidationError):
        semgrep_finding.start_line = 99  # type: ignore[misc]


def test_normalized_finding_serialization_no_raw_secrets(gitleaks_finding: NormalizedFinding) -> None:
    dumped = gitleaks_finding.model_dump_json()
    assert "Secret" not in dumped
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped


# --- Tests: SanitizedContext ---


def test_sanitized_context_python_function_valid(valid_context: SanitizedContext) -> None:
    assert valid_context.context_strategy == ContextStrategy.PYTHON_FUNCTION
    assert valid_context.context_available is True
    assert valid_context.sanitized_snippet is not None


def test_sanitized_context_line_window_valid() -> None:
    ctx = SanitizedContext(
        finding_id="f-002",
        sanitized_snippet="print('hello')",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=5,
        finding_start_line=2,
        finding_end_line=2,
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )
    assert ctx.context_strategy == ContextStrategy.LINE_WINDOW


def test_sanitized_context_unavailable_valid() -> None:
    ctx = SanitizedContext(
        finding_id="f-003",
        sanitized_snippet=None,
        context_strategy=ContextStrategy.UNAVAILABLE,
        finding_start_line=10,
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=False,
        missing_context_reasons=[MissingContextReason.SOURCE_FILE_NOT_FOUND],
    )
    assert ctx.context_available is False
    assert ctx.missing_context_reasons == [MissingContextReason.SOURCE_FILE_NOT_FOUND]


def test_sanitized_context_sanitization_failed_reason() -> None:
    ctx = SanitizedContext(
        finding_id="f-004",
        sanitized_snippet=None,
        context_strategy=ContextStrategy.UNAVAILABLE,
        finding_start_line=10,
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=False,
        missing_context_reasons=[MissingContextReason.CONTEXT_SANITIZATION_FAILED],
    )
    assert ctx.context_available is False
    assert ctx.missing_context_reasons == [MissingContextReason.CONTEXT_SANITIZATION_FAILED]
    assert ctx.missing_context_reasons[0].value == "CONTEXT_SANITIZATION_FAILED"
    assert ctx.sanitized_snippet is None


def test_sanitized_context_consistency_checks() -> None:
    # UNAVAILABLE strategy must have context_available=False
    with pytest.raises(ValidationError, match="context_available must be False"):
        SanitizedContext(
            finding_id="f-err",
            sanitized_snippet=None,
            context_strategy=ContextStrategy.UNAVAILABLE,
            finding_start_line=10,
            path_category=PathCategory.UNKNOWN,
            source_kind=SourceKind.WORKTREE,
            context_available=True,  # Invalid
            missing_context_reasons=[MissingContextReason.SOURCE_FILE_NOT_FOUND],
        )

    # Active strategy requires line range to encompass finding
    with pytest.raises(ValidationError, match="context_start_line must be <= finding_start_line"):
        SanitizedContext(
            finding_id="f-err-2",
            sanitized_snippet="code",
            context_strategy=ContextStrategy.LINE_WINDOW,
            context_start_line=20,  # Starts AFTER finding
            context_end_line=30,
            finding_start_line=10,
            path_category=PathCategory.PRODUCTION,
            source_kind=SourceKind.WORKTREE,
            context_available=True,
        )


def test_sanitized_context_redactions_applied_non_negative() -> None:
    with pytest.raises(ValidationError, match="redactions_applied cannot be negative"):
        SanitizedContext(
            finding_id="f-neg",
            sanitized_snippet="code",
            context_strategy=ContextStrategy.LINE_WINDOW,
            context_start_line=1,
            context_end_line=10,
            finding_start_line=5,
            path_category=PathCategory.PRODUCTION,
            source_kind=SourceKind.WORKTREE,
            context_available=True,
            redactions_applied=-1,
        )


# --- Tests: TriageInput ---


def test_triage_input_valid(
    semgrep_finding: NormalizedFinding, valid_context: SanitizedContext
) -> None:
    t_input = TriageInput(
        finding=semgrep_finding,
        context=valid_context,
        prompt_version="1.0.0",
        output_schema_version="1.0.0",
        prompt_type="semgrep_triage",
    )
    assert t_input.finding.finding_instance_id == valid_context.finding_id


def test_triage_input_mismatched_finding_id(
    semgrep_finding: NormalizedFinding, valid_context: SanitizedContext
) -> None:
    mismatched_context = valid_context.model_copy(update={"finding_id": "different-id"})
    with pytest.raises(ValidationError, match="must match finding.finding_instance_id"):
        TriageInput(
            finding=semgrep_finding,
            context=mismatched_context,
            prompt_version="1.0.0",
            output_schema_version="1.0.0",
            prompt_type="semgrep_triage",
        )


# --- Tests: TriageDecision ---


def test_triage_decision_valid(valid_triage_decision: TriageDecision) -> None:
    assert valid_triage_decision.model_verdict == ModelVerdict.LIKELY_TP
    assert isinstance(valid_triage_decision.evidence, list)
    assert not hasattr(valid_triage_decision, "action")


def test_triage_decision_frozen(valid_triage_decision: TriageDecision) -> None:
    with pytest.raises(ValidationError):
        valid_triage_decision.summary = "New summary"  # type: ignore[misc]


# --- Tests: PolicyDecision ---


def test_policy_decision_valid(valid_policy_decision: PolicyDecision) -> None:
    assert valid_policy_decision.action == PolicyAction.LIKELY_TP
    assert len(valid_policy_decision.reasons) > 0


def test_policy_decision_requires_reasons() -> None:
    with pytest.raises(ValidationError, match="reasons must not be empty"):
        PolicyDecision(
            action=PolicyAction.LIKELY_TP,
            reasons=[],
            policy_version="1.0.0",
            escalated=False,
        )


def test_policy_decision_requires_escalation_reason() -> None:
    with pytest.raises(ValidationError, match="escalation_reason is required when escalated is True"):
        PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Low confidence"],
            policy_version="1.0.0",
            escalated=True,
            escalation_reason=None,
        )


# --- Tests: TriageResult ---


def test_triage_result_success_case(
    semgrep_finding: NormalizedFinding,
    valid_triage_decision: TriageDecision,
    valid_policy_decision: PolicyDecision,
) -> None:
    res = TriageResult(
        finding=semgrep_finding,
        context_summary="PYTHON_FUNCTION context, lines 10-25, function process_payment.",
        triage_decision=valid_triage_decision,
        policy_decision=valid_policy_decision,
        processing_errors=[],
        processed_at=datetime.now(UTC),
    )
    assert res.triage_decision is not None
    assert res.policy_decision.action == PolicyAction.LIKELY_TP
    assert res.context_summary == "PYTHON_FUNCTION context, lines 10-25, function process_payment."


def test_triage_result_no_sanitized_context_field(
    semgrep_finding: NormalizedFinding,
    valid_triage_decision: TriageDecision,
    valid_policy_decision: PolicyDecision,
    valid_context: SanitizedContext,
) -> None:
    # 1. Verify sanitized_context is not an attribute
    res = TriageResult(
        finding=semgrep_finding,
        context_summary="LINE_WINDOW context, lines 1-10.",
        triage_decision=valid_triage_decision,
        policy_decision=valid_policy_decision,
        processed_at=datetime.now(UTC),
    )
    assert not hasattr(res, "sanitized_context")

    # 2. Verify passing extra sanitized_context parameter is rejected by extra="forbid"
    with pytest.raises(ValidationError):
        TriageResult(
            finding=semgrep_finding,
            sanitized_context=valid_context,  # type: ignore[call-arg]
            context_summary="LINE_WINDOW context, lines 1-10.",
            triage_decision=valid_triage_decision,
            policy_decision=valid_policy_decision,
            processed_at=datetime.now(UTC),
        )


def test_triage_result_serialization_no_source_snippet(
    semgrep_finding: NormalizedFinding,
    valid_triage_decision: TriageDecision,
    valid_policy_decision: PolicyDecision,
) -> None:
    res = TriageResult(
        finding=semgrep_finding,
        context_summary="REDACTED_LINE_WINDOW context, lines 5-15.",
        triage_decision=valid_triage_decision,
        policy_decision=valid_policy_decision,
        processed_at=datetime.now(UTC),
    )
    dump_json = res.model_dump_json()

    assert "sanitized_context" not in dump_json
    assert "sanitized_snippet" not in dump_json
    assert "limited_imports" not in dump_json
    assert "limited_decorators" not in dump_json


def test_triage_result_context_summary_nullable_or_whitespace_check(
    semgrep_finding: NormalizedFinding,
    valid_triage_decision: TriageDecision,
    valid_policy_decision: PolicyDecision,
) -> None:
    # context_summary can be None
    res_none = TriageResult(
        finding=semgrep_finding,
        context_summary=None,
        triage_decision=valid_triage_decision,
        policy_decision=valid_policy_decision,
        processed_at=datetime.now(UTC),
    )
    assert res_none.context_summary is None

    # whitespace-only context_summary is rejected
    with pytest.raises(ValidationError, match="must not be empty or whitespace only"):
        TriageResult(
            finding=semgrep_finding,
            context_summary="   ",
            triage_decision=valid_triage_decision,
            policy_decision=valid_policy_decision,
            processed_at=datetime.now(UTC),
        )


def test_missing_context_reason_contains_source_file_read_error() -> None:
    assert MissingContextReason.SOURCE_FILE_READ_ERROR.value == "SOURCE_FILE_READ_ERROR"


def test_triage_result_provider_failure_case(
    semgrep_finding: NormalizedFinding,
) -> None:
    error_record = ProcessingError(
        finding_id=semgrep_finding.finding_instance_id,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.TRIAGE,
        error_code="LLM_TIMEOUT",
        safe_message="Triage provider timed out.",
        retryable=True,
    )
    error_policy = PolicyDecision(
        action=PolicyAction.TRIAGE_ERROR,
        reasons=["Provider failure resulting in null decision"],
        policy_version="1.0.0",
        escalated=False,
    )
    res = TriageResult(
        finding=semgrep_finding,
        context_summary=None,
        triage_decision=None,
        policy_decision=error_policy,
        processing_errors=[error_record],
        processed_at=datetime.now(UTC),
    )
    assert res.triage_decision is None
    assert res.policy_decision.action == PolicyAction.TRIAGE_ERROR


def test_triage_result_rejects_null_decision_without_triage_error_action(
    semgrep_finding: NormalizedFinding,
    valid_policy_decision: PolicyDecision,
) -> None:
    with pytest.raises(ValidationError, match="policy_decision.action must be TRIAGE_ERROR"):
        TriageResult(
            finding=semgrep_finding,
            context_summary=None,
            triage_decision=None,  # Null decision
            policy_decision=valid_policy_decision,  # Action is LIKELY_TP (invalid!)
            processing_errors=[],
            processed_at=datetime.now(UTC),
        )


# --- Tests: RunMetadata ---


def test_run_metadata_valid() -> None:
    now = datetime.now(UTC)
    meta = RunMetadata(
        run_id="run-123",
        repository_name="my-repo",
        repository_identifier="my-repo-id",
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
        scanners_attempted=[ScannerType.SEMGREP, ScannerType.GITLEAKS],
        scanners_succeeded=[ScannerType.SEMGREP],
        policy_version="1.0.0",
        triage_provider="fake",
        tool_version="0.1.0",
        cli_mode="triage",
        started_at=now,
        completed_at=now,
        total_findings_parsed=5,
        findings_triaged_ok=4,
        findings_with_errors=1,
    )
    assert meta.total_findings_parsed == 5


def test_run_metadata_rejects_completed_before_started() -> None:
    now = datetime.now(UTC)
    earlier = datetime.fromtimestamp(now.timestamp() - 100, tz=UTC)
    with pytest.raises(ValidationError, match="completed_at cannot be earlier than started_at"):
        RunMetadata(
            run_id="run-err",
            repository_name="repo",
            repository_identifier="repo-id",
            artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
            scanners_attempted=[ScannerType.SEMGREP],
            scanners_succeeded=[ScannerType.SEMGREP],
            policy_version="1.0.0",
            triage_provider="fake",
            tool_version="0.1.0",
            cli_mode="triage",
            started_at=now,
            completed_at=earlier,
        )


def test_run_metadata_rejects_absolute_repo_path() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="absolute path"):
        RunMetadata(
            run_id="run-abs",
            repository_name="/home/user/my-repo",  # Absolute path!
            repository_identifier="repo-id",
            artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
            scanners_attempted=[ScannerType.SEMGREP],
            scanners_succeeded=[ScannerType.SEMGREP],
            policy_version="1.0.0",
            triage_provider="fake",
            tool_version="0.1.0",
            cli_mode="triage",
            started_at=now,
            completed_at=now,
        )


def test_triage_result_provider_failure_requires_triage_stage_error(
    semgrep_finding: NormalizedFinding,
) -> None:
    error_policy = PolicyDecision(
        action=PolicyAction.TRIAGE_ERROR,
        reasons=["Provider failure"],
        policy_version="1.0.0",
        escalated=False,
    )
    # Failure case: missing stage=TRIAGE error
    non_triage_error = ProcessingError(
        finding_id=semgrep_finding.finding_instance_id,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,  # Not TRIAGE!
        error_code="PARSE_ERR",
        safe_message="Parse error.",
    )
    with pytest.raises(ValidationError, match="stage=TRIAGE"):
        TriageResult(
            finding=semgrep_finding,
            context_summary=None,
            triage_decision=None,
            policy_decision=error_policy,
            processing_errors=[non_triage_error],
            processed_at=datetime.now(UTC),
        )


def test_triage_result_triage_error_action_requires_non_empty_errors(
    semgrep_finding: NormalizedFinding,
    valid_triage_decision: TriageDecision,
) -> None:
    error_policy = PolicyDecision(
        action=PolicyAction.TRIAGE_ERROR,
        reasons=["Policy error"],
        policy_version="1.0.0",
        escalated=False,
    )
    with pytest.raises(ValidationError, match="processing_errors must not be empty"):
        TriageResult(
            finding=semgrep_finding,
            context_summary=None,
            triage_decision=valid_triage_decision,  # Decision present but action is TRIAGE_ERROR
            policy_decision=error_policy,
            processing_errors=[],  # Empty errors!
            processed_at=datetime.now(UTC),
        )


def test_run_metadata_allows_namespace_identifier() -> None:
    now = datetime.now(UTC)
    meta = RunMetadata(
        run_id="run-ns",
        repository_name="payment-service",
        repository_identifier="team/payment-service",  # Namespace identifier is valid!
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
        scanners_attempted=[ScannerType.SEMGREP],
        scanners_succeeded=[ScannerType.SEMGREP],
        policy_version="1.0.0",
        triage_provider="fake",
        tool_version="0.1.0",
        cli_mode="triage",
        started_at=now,
        completed_at=now,
    )
    assert meta.repository_identifier == "team/payment-service"


def test_run_metadata_rejects_control_characters() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="control characters"):
        RunMetadata(
            run_id="run-ctrl",
            repository_name="my-repo\n",
            repository_identifier="repo-id",
            artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
            scanners_attempted=[ScannerType.SEMGREP],
            scanners_succeeded=[ScannerType.SEMGREP],
            policy_version="1.0.0",
            triage_provider="fake",
            tool_version="0.1.0",
            cli_mode="triage",
            started_at=now,
            completed_at=now,
        )


# --- Test: Security Canary & Extra Field Rejection ---


def test_security_canary_not_leaked_in_serialized_models(
    gitleaks_finding: NormalizedFinding, valid_context: SanitizedContext
) -> None:
    CANARY_SUPER_SECRET_DO_NOT_LEAK = "CANARY_SUPER_SECRET_DO_NOT_LEAK"

    # Verify canary is absent from finding dump
    finding_json = gitleaks_finding.model_dump_json()
    assert CANARY_SUPER_SECRET_DO_NOT_LEAK not in finding_json

    # Verify canary is absent from context dump
    context_json = valid_context.model_dump_json()
    assert CANARY_SUPER_SECRET_DO_NOT_LEAK not in context_json

    matching_context = valid_context.model_copy(
        update={"finding_id": gitleaks_finding.finding_instance_id}
    )

    # Construct TriageInput and check dump
    t_input = TriageInput(
        finding=gitleaks_finding,
        context=matching_context,
        prompt_version="1.0.0",
        output_schema_version="1.0.0",
        prompt_type="gitleaks_triage",
    )
    assert CANARY_SUPER_SECRET_DO_NOT_LEAK not in t_input.model_dump_json()


def test_public_models_reject_extra_secret_fields(semgrep_finding: NormalizedFinding) -> None:
    # Verify extra fields like Secret, raw_match, raw_source are rejected by extra="forbid"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedFinding(
            finding_instance_id="f-extra",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="rule",
            file_path="app.py",
            start_line=1,
            severity=Severity.HIGH,
            message="msg",
            snippet="code",
            Secret="CANARY_SUPER_SECRET",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedFinding(
            finding_instance_id="f-extra2",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="rule",
            file_path="app.py",
            start_line=1,
            severity=Severity.HIGH,
            message="msg",
            snippet="code",
            raw_match="raw_secret_here",  # type: ignore[call-arg]
        )


# --- Tests: ScannerParseResult ---


def test_scanner_parse_result_empty_valid() -> None:
    result = ScannerParseResult()
    assert result.findings == ()
    assert result.errors == ()


def test_scanner_parse_result_with_findings(semgrep_finding: NormalizedFinding) -> None:
    result = ScannerParseResult(findings=(semgrep_finding,))
    assert len(result.findings) == 1
    assert result.findings[0].scanner == ScannerType.SEMGREP
    assert result.errors == ()


def test_scanner_parse_result_frozen_collections(semgrep_finding: NormalizedFinding) -> None:
    result = ScannerParseResult(findings=(semgrep_finding,))
    # Tuple is immutable — cannot append
    with pytest.raises(AttributeError):
        result.findings.append(semgrep_finding)  # type: ignore[attr-defined]
    # Frozen model — cannot reassign field
    with pytest.raises(ValidationError):
        result.findings = ()  # type: ignore[misc]
