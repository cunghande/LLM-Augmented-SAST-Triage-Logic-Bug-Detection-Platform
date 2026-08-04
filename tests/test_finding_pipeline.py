"""Unit and integration tests for per-finding triage pipeline."""

from datetime import UTC
from pathlib import Path

import pytest
from pydantic import ValidationError

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    PolicyAction,
    ProcessingStage,
    ScannerType,
    Severity,
    TriageResult,
)
from sast_triage.pipeline.finding import (
    triage_finding,
)
from sast_triage.triage.fake_provider import (
    FakeTriageProvider,
    FakeTriageProviderMode,
)

CANARY = "PIPELINE_SOURCE_CANARY_DO_NOT_LEAK"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    file_path: str = "app/service.py",
    start_line: int = 5,
    end_line: int | None = None,
    severity: Severity = Severity.HIGH,
    finding_id: str = "find123456789012",
) -> NormalizedFinding:
    actual_end = start_line if end_line is None else end_line
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=scanner,
        finding_type=FindingType.SAST if scanner == ScannerType.SEMGREP else FindingType.SECRET,
        rule_id="rule-01",
        file_path=file_path,
        start_line=start_line,
        end_line=actual_end,
        severity=severity,
        message="Finding message",
        snippet="snippet",
    )


# --- Group 1: Happy Path Tests ---


def test_pipeline_semgrep_ast_success_tp(tmp_path: Path) -> None:
    """Requirement Protected: Semgrep AST finding with fake.tp.high yields PolicyAction.LIKELY_TP.

    Pipeline Stages: read -> scope -> select -> sanitize -> input -> fake_provider -> policy.
    Expected Result: policy_decision.action == LIKELY_TP, context_summary present, no errors.
    Test Category: Happy Path
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app" / "service.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "class Service:\n    def process(self):\n        password = 'pass'\n        return True\n",
        encoding="utf-8",
    )

    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/service.py", start_line=3)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.tp.high")

    assert isinstance(res, TriageResult)
    assert res.policy_decision.action == PolicyAction.LIKELY_TP
    assert res.triage_decision is not None
    assert res.context_summary is not None
    assert "PYTHON_FUNCTION" in res.context_summary
    assert res.processing_errors == []


def test_pipeline_semgrep_ast_fallback_manual_review(tmp_path: Path) -> None:
    """Requirement Protected: Broken Python syntax falls back to LINE_WINDOW, returning MANUAL_REVIEW with fake.review.low.

    Pipeline Stages: read -> scope (fails) -> select (LINE_WINDOW) -> sanitize -> input -> provider -> policy.
    Expected Result: policy_decision.action == MANUAL_REVIEW, strategy LINE_WINDOW.
    Test Category: Fallback Path
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app" / "broken.py"
    source.parent.mkdir(parents=True)
    source.write_text("def broken_syntax(:\n    pass\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/broken.py", start_line=2)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.review.low")

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert "LINE_WINDOW" in res.context_summary


def test_pipeline_gitleaks_fixture_path_fp_candidate(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks finding in FIXTURE path with fake.fp.high yields PolicyAction.FP_CANDIDATE.

    Pipeline Stages: read -> select -> sanitize -> input -> provider -> policy.
    Expected Result: policy_decision.action == FP_CANDIDATE.
    Test Category: Happy Path
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "tests" / "fixtures" / "mock_secret.py"
    source.parent.mkdir(parents=True)
    source.write_text("API_KEY = 'secret'\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.GITLEAKS, file_path="tests/fixtures/mock_secret.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.fp.high")

    assert res.policy_decision.action == PolicyAction.FP_CANDIDATE
    assert "REDACTED_LINE_WINDOW" in res.context_summary


def test_pipeline_triage_result_has_no_sanitized_context_field(tmp_path: Path) -> None:
    """Requirement Protected: TriageResult object does NOT contain sanitized_context field.

    Pipeline Stages: full pipeline.
    Expected Result: hasattr(res, 'sanitized_context') is False.
    Test Category: Contract Invariant
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.py"
    source.write_text("x = 1\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="main.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert not hasattr(res, "sanitized_context")
    dump_json = res.model_dump_json()
    assert "sanitized_context" not in dump_json
    assert "sanitized_snippet" not in dump_json
    assert "limited_imports" not in dump_json
    assert "limited_decorators" not in dump_json


# --- Group 2: Recoverable Context Errors ---


def test_pipeline_source_file_missing_recovered(tmp_path: Path) -> None:
    """Requirement Protected: Missing source file generates CONTEXT ProcessingError and resolves to MANUAL_REVIEW.

    Pipeline Stages: read (fails) -> unavailable context -> provider (NEEDS_REVIEW+LOW) -> policy (MANUAL_REVIEW).
    Expected Result: PolicyAction.MANUAL_REVIEW, ProcessingError stage CONTEXT.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    finding = make_finding(file_path="nonexistent.py", start_line=10)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.context_summary == "Context unavailable."
    assert len(res.processing_errors) == 1
    assert res.processing_errors[0].stage == ProcessingStage.CONTEXT
    assert res.processing_errors[0].error_code == "CONTEXT_SOURCE_FILE_NOT_FOUND"


def test_pipeline_path_outside_repository_recovered(tmp_path: Path) -> None:
    """Requirement Protected: Path traversal outside repository generates CONTEXT ProcessingError and MANUAL_REVIEW.

    Expected Result: PolicyAction.MANUAL_REVIEW, error_code CONTEXT_PATH_OUTSIDE_REPOSITORY.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    finding = make_finding(file_path="../outside.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.processing_errors[0].error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_pipeline_source_file_too_large_recovered(tmp_path: Path) -> None:
    """Requirement Protected: File exceeding max_file_size_bytes generates CONTEXT_SOURCE_FILE_TOO_LARGE.

    Expected Result: PolicyAction.MANUAL_REVIEW, error_code CONTEXT_SOURCE_FILE_TOO_LARGE.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "large.py"
    source.write_text("x = 1\n" * 1000, encoding="utf-8")

    finding = make_finding(file_path="large.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, max_file_size_bytes=100)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.processing_errors[0].error_code == "CONTEXT_SOURCE_FILE_TOO_LARGE"


def test_pipeline_source_read_permission_error_recovered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement Protected: PermissionError during file reading generates CONTEXT_SOURCE_READ_ERROR.

    Expected Result: PolicyAction.MANUAL_REVIEW, error_code CONTEXT_SOURCE_READ_ERROR.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "perm.py"
    source.write_text("code = 1\n", encoding="utf-8")

    orig_stat = Path.stat

    def mock_stat(self, *args, **kwargs):
        if self.name == "perm.py":
            raise PermissionError("Access denied")
        return orig_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", mock_stat)

    finding = make_finding(file_path="perm.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.processing_errors[0].error_code == "CONTEXT_SOURCE_READ_ERROR"


# --- Group 3: Sanitization Tests ---


def test_pipeline_credential_literal_redacted_before_provider(tmp_path: Path) -> None:
    """Requirement Protected: Credential literal in source code is redacted before reaching provider.

    Expected Result: Redacted snippet passed to provider.
    Test Category: Sanitization Security
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("password = 'super_secret_pass_123'\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.tp.high")

    assert res.policy_decision.action == PolicyAction.LIKELY_TP
    assert "super_secret_pass_123" not in res.model_dump_json()


def test_pipeline_forbidden_value_leak_failure_forces_manual_review(tmp_path: Path) -> None:
    """Requirement Protected: Unredactable forbidden value triggers CONTEXT_SANITIZATION_FAILED and MANUAL_REVIEW.

    Expected Result: PolicyAction.MANUAL_REVIEW, ProcessingError stage SANITIZE.
    Test Category: Sanitization Failure
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "unredactable.py"
    source.write_text("# Custom comment: MY_FORBIDDEN_TOKEN_99\ndef fn(): pass\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="unredactable.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, forbidden_values=("MY_FORBIDDEN_TOKEN_99",))

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert any(err.stage == ProcessingStage.SANITIZE for err in res.processing_errors)
    assert "MY_FORBIDDEN_TOKEN_99" not in res.model_dump_json()


# --- Group 4: Provider Failure Tests ---


def test_pipeline_provider_timeout_yields_triage_error(tmp_path: Path) -> None:
    """Requirement Protected: Provider timeout results in triage_decision=None and PolicyAction.TRIAGE_ERROR.

    Expected Result: triage_decision is None, policy_decision.action == TRIAGE_ERROR, stage TRIAGE error present.
    Test Category: Provider Failure
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    finding = make_finding(file_path="main.py", start_line=1)
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_TIMEOUT)

    res = triage_finding(finding, repo, provider)

    assert res.triage_decision is None
    assert res.policy_decision.action == PolicyAction.TRIAGE_ERROR
    assert any(err.stage == ProcessingStage.TRIAGE for err in res.processing_errors)


def test_pipeline_provider_error_yields_triage_error(tmp_path: Path) -> None:
    """Requirement Protected: Provider internal error results in triage_decision=None and PolicyAction.TRIAGE_ERROR.

    Expected Result: triage_decision is None, policy_decision.action == TRIAGE_ERROR.
    Test Category: Provider Failure
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "main.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    finding = make_finding(file_path="main.py", start_line=1)
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_PROVIDER_ERROR)

    res = triage_finding(finding, repo, provider)

    assert res.triage_decision is None
    assert res.policy_decision.action == PolicyAction.TRIAGE_ERROR


# --- Group 5: Policy Behavior & Fallback Tests ---


def test_pipeline_policy_semgrep_high_severity_fp_escalated(tmp_path: Path) -> None:
    """Requirement Protected: High-severity Semgrep LIKELY_FP finding is escalated to MANUAL_REVIEW.

    Expected Result: PolicyAction.MANUAL_REVIEW, escalated == True.
    Test Category: Policy Rule
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("eval(x)\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.HIGH, file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.fp.high")

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.policy_decision.escalated is True


def test_pipeline_policy_semgrep_medium_severity_fp_candidate(tmp_path: Path) -> None:
    """Requirement Protected: Medium-severity Semgrep LIKELY_FP finding becomes FP_CANDIDATE.

    Expected Result: PolicyAction.FP_CANDIDATE.
    Test Category: Policy Rule
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.MEDIUM, file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.fp.high")

    assert res.policy_decision.action == PolicyAction.FP_CANDIDATE


def test_pipeline_policy_failure_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement Protected: Exception during apply_policy generates POLICY ProcessingError and fallback decision.

    Expected Result: policy_decision.action == TRIAGE_ERROR, ProcessingError stage POLICY.
    Test Category: Policy Fallback
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")

    def mock_apply_policy(*args, **kwargs):
        raise SastTriageError(
            safe_message="Simulated policy engine crash.",
            error_code="POLICY_INTERNAL_CRASH",
            retryable=False,
        )

    monkeypatch.setattr("sast_triage.pipeline.finding.apply_policy", mock_apply_policy)

    finding = make_finding(file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.TRIAGE_ERROR
    assert res.policy_decision.reasons == ["Policy evaluation failed."]
    assert any(err.stage == ProcessingStage.POLICY for err in res.processing_errors)


# --- Group 6: Configuration Errors Tests ---


def test_config_negative_line_window_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Negative line window configuration raises PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised, error_code == PIPELINE_INVALID_CONFIGURATION.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    finding = make_finding()
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, line_window_before=-1)

    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


def test_config_invalid_file_size_rejected(tmp_path: Path) -> None:
    """Requirement Protected: max_file_size_bytes <= 0 raises PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    finding = make_finding()
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, max_file_size_bytes=0)

    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


def test_config_empty_prompt_version_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Empty prompt_version raises PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    finding = make_finding()
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, prompt_version="   ")

    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


# --- Group 7: Security & Invariant Tests ---


def test_canary_not_leaked_in_triage_result_serialization(tmp_path: Path) -> None:
    """Requirement Protected: Secret canary in source code is NEVER leaked into TriageResult serialization.

    Expected Result: CANARY absent from dump_json, dict, repr, str.
    Test Category: Security Boundary
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "secret.py"
    source.write_text(f"# Comment: {CANARY}\ndef fn(): pass\n", encoding="utf-8")

    finding = make_finding(file_path="secret.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)
    dump_json = res.model_dump_json()

    assert CANARY not in res.context_summary
    assert CANARY not in dump_json
    assert CANARY not in repr(res)
    assert CANARY not in str(res)


def test_triage_result_timing_and_frozen(tmp_path: Path) -> None:
    """Requirement Protected: processed_at is UTC-aware, duration is non-negative, and TriageResult is frozen.

    Expected Result: processed_at.tzinfo is UTC, duration >= 0, ValidationError on field mutation.
    Test Category: Result Invariants
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")

    finding = make_finding(file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.processed_at.tzinfo == UTC
    assert res.processing_duration_ms is not None and res.processing_duration_ms >= 0

    with pytest.raises(ValidationError):
        res.context_summary = "mutated"  # type: ignore[misc]


def test_pipeline_unsupported_encoding_recovered(tmp_path: Path) -> None:
    """Requirement Protected: Unsupported encoding generates CONTEXT_SOURCE_UNSUPPORTED_ENCODING.

    Expected Result: PolicyAction.MANUAL_REVIEW, error_code CONTEXT_SOURCE_UNSUPPORTED_ENCODING.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "binary.py"
    source.write_bytes(b"\x80\x81\x82\x83\xff\xfe")

    finding = make_finding(file_path="binary.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.processing_errors[0].error_code == "CONTEXT_SOURCE_UNSUPPORTED_ENCODING"


def test_pipeline_invalid_finding_line_range_recovered(tmp_path: Path) -> None:
    """Requirement Protected: Finding line beyond file line count generates INVALID_FINDING_LINE_RANGE.

    Expected Result: PolicyAction.MANUAL_REVIEW, error_code CONTEXT_INVALID_FINDING_LINE_RANGE.
    Test Category: Recoverable Error
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "short.py"
    source.write_text("line1\nline2\n", encoding="utf-8")

    finding = make_finding(file_path="short.py", start_line=999)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.processing_errors[0].error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_pipeline_gitleaks_unknown_path_escalated(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks LIKELY_FP in UNKNOWN path is escalated to MANUAL_REVIEW.

    Expected Result: PolicyAction.MANUAL_REVIEW, escalated == True.
    Test Category: Policy Edge Case
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "src" / "secret.py"
    source.parent.mkdir(parents=True)
    source.write_text("KEY = 'val'\n", encoding="utf-8")

    finding = make_finding(scanner=ScannerType.GITLEAKS, file_path="src/secret.py", start_line=1)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.fp.high")

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.policy_decision.escalated is True


def test_pipeline_truncated_context_escalated(tmp_path: Path) -> None:
    """Requirement Protected: Truncated context prevents FP_CANDIDATE classification and escalates to MANUAL_REVIEW.

    Expected Result: PolicyAction.MANUAL_REVIEW, escalated == True.
    Test Category: Policy Truncation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "large.py"
    source.write_text("line\n" * 500, encoding="utf-8")

    finding = make_finding(scanner=ScannerType.SEMGREP, severity=Severity.MEDIUM, file_path="large.py", start_line=250)
    provider = FakeTriageProvider()

    res = triage_finding(finding, repo, provider, prompt_type="fake.fp.high", max_context_characters=100)

    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.policy_decision.escalated is True
    assert "truncated" in res.context_summary


def test_config_invalid_limits_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Invalid scope, context chars, or import lines limits raise PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised with PIPELINE_INVALID_CONFIGURATION.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    finding = make_finding()
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, max_scope_lines=0)
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, max_context_characters=-10)
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, max_import_lines=-1)
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


def test_config_invalid_forbidden_values_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Invalid or placeholder elements in forbidden_values raise PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    finding = make_finding()
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider, forbidden_values=("<REDACTED_SECRET>",))
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


def test_unrecoverable_context_error_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement Protected: Unrecoverable context error (not in allowlist) propagates directly without recovery.

    Expected Result: SastTriageError raised directly, no TriageResult created.
    Test Category: Contract Error Propagation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")

    def mock_read_repo_source(*args, **kwargs):
        raise SastTriageError(
            safe_message="Invalid size limit parameter.",
            error_code="CONTEXT_INVALID_SIZE_LIMIT",  # Not in recoverable allowlist!
            retryable=False,
        )

    monkeypatch.setattr("sast_triage.pipeline.finding.read_repository_source", mock_read_repo_source)

    finding = make_finding(file_path="app.py", start_line=1)
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_finding(finding, repo, provider)

    assert exc.value.error_code == "CONTEXT_INVALID_SIZE_LIMIT"
