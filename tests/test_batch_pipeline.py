"""Unit and integration tests for multi-finding batch triage pipeline."""

import uuid
from datetime import UTC
from pathlib import Path

import pytest
from pydantic import ValidationError

from sast_triage import __version__ as TOOL_VERSION
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    BatchResult,
    FindingType,
    NormalizedFinding,
    PolicyAction,
    ProcessingError,
    ProcessingStage,
    ScannerParseResult,
    ScannerType,
    Severity,
)
from sast_triage.pipeline.batch import triage_batch
from sast_triage.policy.engine import POLICY_VERSION
from sast_triage.triage.fake_provider import (
    FakeTriageProvider,
    FakeTriageProviderMode,
)

CANARY = "PIPELINE_SOURCE_CANARY_DO_NOT_LEAK"


def make_semgrep_finding(
    finding_id: str = "semgrep-001",
    file_path: str = "app/service.py",
    start_line: int = 1,
    severity: Severity = Severity.MEDIUM,
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="eval-use",
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        severity=severity,
        message="Semgrep message",
    )


def make_gitleaks_finding(
    finding_id: str = "gitleaks-001",
    file_path: str = "tests/fixtures/secrets.py",
    start_line: int = 1,
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=ScannerType.GITLEAKS,
        finding_type=FindingType.SECRET,
        rule_id="aws-key",
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        severity=Severity.UNKNOWN,
        message="Gitleaks message",
    )


# --- Group 1: Basic Batch Tests ---


def test_batch_single_semgrep_finding(tmp_path: Path) -> None:
    """Requirement Protected: Single Semgrep finding produces one TriageResult in BatchResult.

    Expected Result: len(results) == 1, scanners_attempted == [SEMGREP], scanners_succeeded == [SEMGREP].
    Test Category: Basic Batch
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "service.py").write_text("eval(x)\n", encoding="utf-8")

    f1 = make_semgrep_finding()
    semgrep_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert isinstance(batch_res, BatchResult)
    assert len(batch_res.results) == 1
    assert batch_res.results[0].finding.finding_instance_id == "semgrep-001"
    assert batch_res.run_metadata.scanners_attempted == [ScannerType.SEMGREP]
    assert batch_res.run_metadata.scanners_succeeded == [ScannerType.SEMGREP]


def test_batch_single_gitleaks_finding(tmp_path: Path) -> None:
    """Requirement Protected: Single Gitleaks finding produces one TriageResult in BatchResult.

    Expected Result: len(results) == 1, scanners_attempted == [GITLEAKS].
    Test Category: Basic Batch
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "secrets.py").write_text("KEY = 'val'\n", encoding="utf-8")

    f1 = make_gitleaks_finding()
    gitleaks_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, gitleaks_result=gitleaks_res, repository_identifier="my-repo")

    assert len(batch_res.results) == 1
    assert batch_res.run_metadata.scanners_attempted == [ScannerType.GITLEAKS]


def test_batch_semgrep_and_gitleaks_deterministic_order(tmp_path: Path) -> None:
    """Requirement Protected: Semgrep findings processed first, followed by Gitleaks findings in parser order.

    Expected Result: results[0] is semgrep, results[1] is gitleaks.
    Test Category: Result Ordering
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "service.py").write_text("eval(x)\n", encoding="utf-8")
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "secrets.py").write_text("KEY = 'val'\n", encoding="utf-8")

    f1 = make_semgrep_finding(finding_id="semgrep-01")
    f2 = make_gitleaks_finding(finding_id="gitleaks-01")

    semgrep_res = ScannerParseResult(findings=(f1,), errors=())
    gitleaks_res = ScannerParseResult(findings=(f2,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        semgrep_result=semgrep_res,
        gitleaks_result=gitleaks_res,
        repository_identifier="my-repo",
    )

    assert len(batch_res.results) == 2
    assert batch_res.results[0].finding.finding_instance_id == "semgrep-01"
    assert batch_res.results[1].finding.finding_instance_id == "gitleaks-01"


def test_batch_empty_scanner_results(tmp_path: Path) -> None:
    """Requirement Protected: Empty ScannerParseResults provided produce valid empty BatchResult.

    Expected Result: results == [], total_findings_parsed == 0, scanners_succeeded == [SEMGREP, GITLEAKS].
    Test Category: Basic Batch
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    semgrep_res = ScannerParseResult(findings=(), errors=())
    gitleaks_res = ScannerParseResult(findings=(), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        semgrep_result=semgrep_res,
        gitleaks_result=gitleaks_res,
        repository_identifier="my-repo",
    )

    assert batch_res.results == []
    assert batch_res.run_metadata.total_findings_parsed == 0
    assert batch_res.run_metadata.findings_triaged_ok == 0
    assert batch_res.run_metadata.findings_with_errors == 0
    assert set(batch_res.run_metadata.scanners_succeeded) == {ScannerType.SEMGREP, ScannerType.GITLEAKS}


# --- Group 2: Scanner Status & Errors Tests ---


def test_scanner_input_none_not_attempted(tmp_path: Path) -> None:
    """Requirement Protected: Scanner input None is not included in scanners_attempted.

    Expected Result: scanners_attempted == [SEMGREP].
    Test Category: Scanner Status
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "service.py").write_text("x = 1\n", encoding="utf-8")

    f1 = make_semgrep_finding()
    semgrep_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert ScannerType.GITLEAKS not in batch_res.run_metadata.scanners_attempted
    assert ScannerType.GITLEAKS not in batch_res.run_metadata.scanners_succeeded


def test_scanner_artifact_level_parse_error_not_succeeded(tmp_path: Path) -> None:
    """Requirement Protected: Artifact-level PARSE error causes scanner to be attempted but NOT succeeded.

    Expected Result: SEMGREP in scanners_attempted, NOT in scanners_succeeded.
    Test Category: Scanner Status
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    artifact_err = ProcessingError(
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_INVALID_JSON",
        safe_message="Malformed JSON file.",
    )
    semgrep_res = ScannerParseResult(findings=(), errors=(artifact_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert ScannerType.SEMGREP in batch_res.run_metadata.scanners_attempted
    assert ScannerType.SEMGREP not in batch_res.run_metadata.scanners_succeeded
    assert len(batch_res.scanner_errors) == 1
    assert batch_res.scanner_errors[0].error_code == "PARSE_INVALID_JSON"


def test_scanner_record_level_error_allows_succeeded(tmp_path: Path) -> None:
    """Requirement Protected: Record-level PARSE error allows scanner to be marked as succeeded.

    Expected Result: SEMGREP in scanners_succeeded, record_err in scanner_errors.
    Test Category: Scanner Status
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "service.py").write_text("x = 1\n", encoding="utf-8")

    f1 = make_semgrep_finding()
    record_err = ProcessingError(
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_RECORD_MISSING_FIELD",
        safe_message="Record skipped missing rule_id.",
    )
    semgrep_res = ScannerParseResult(findings=(f1,), errors=(record_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert ScannerType.SEMGREP in batch_res.run_metadata.scanners_succeeded
    assert len(batch_res.scanner_errors) == 1
    assert batch_res.scanner_errors[0].error_code == "PARSE_RECORD_MISSING_FIELD"


def test_scanner_sanitize_error_in_gitleaks_result_retained(tmp_path: Path) -> None:
    """Requirement Protected: SANITIZE error in Gitleaks parser result is retained in scanner_errors and scanner succeeds.

    Expected Result: GITLEAKS in scanners_succeeded, SANITIZE error in scanner_errors.
    Test Category: Scanner Status
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    sanitize_err = ProcessingError(
        scanner=ScannerType.GITLEAKS,
        stage=ProcessingStage.SANITIZE,
        error_code="GITLEAKS_PRE_REDACT_FAILED",
        safe_message="Failed to pre-redact secret.",
    )
    gitleaks_res = ScannerParseResult(findings=(), errors=(sanitize_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, gitleaks_result=gitleaks_res, repository_identifier="my-repo")

    assert ScannerType.GITLEAKS in batch_res.run_metadata.scanners_succeeded
    assert len(batch_res.scanner_errors) == 1


# --- Group 3: Finding Isolation Tests ---


def test_finding_isolation_source_missing_does_not_stop_batch(tmp_path: Path) -> None:
    """Requirement Protected: Missing source for first finding does NOT stop triage of second finding.

    Expected Result: len(results) == 2, results[0] has CONTEXT error, results[1] triaged ok.
    Test Category: Finding Isolation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "ok.py").write_text("x = 1\n", encoding="utf-8")

    f_missing = make_semgrep_finding(finding_id="f-missing", file_path="missing.py")
    f_ok = make_semgrep_finding(finding_id="f-ok", file_path="app/ok.py")

    semgrep_res = ScannerParseResult(findings=(f_missing, f_ok), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert len(batch_res.results) == 2
    assert batch_res.results[0].finding.finding_instance_id == "f-missing"
    assert len(batch_res.results[0].processing_errors) == 1
    assert batch_res.results[1].finding.finding_instance_id == "f-ok"
    assert len(batch_res.results[1].processing_errors) == 0


def test_finding_isolation_provider_timeout_mode(tmp_path: Path) -> None:
    """Requirement Protected: Provider timeout mode creates TRIAGE_ERROR for all findings, batch finishes.

    Expected Result: len(results) == 2, all policy actions are TRIAGE_ERROR, batch returns.
    Test Category: Finding Isolation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "s1.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "app" / "s2.py").write_text("y = 2\n", encoding="utf-8")

    f1 = make_semgrep_finding(finding_id="f-01", file_path="app/s1.py")
    f2 = make_semgrep_finding(finding_id="f-02", file_path="app/s2.py")

    semgrep_res = ScannerParseResult(findings=(f1, f2), errors=())
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_TIMEOUT)

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert len(batch_res.results) == 2
    assert batch_res.results[0].policy_decision.action == PolicyAction.TRIAGE_ERROR
    assert batch_res.results[1].policy_decision.action == PolicyAction.TRIAGE_ERROR


# --- Group 4: Count Semantics Tests ---


def test_batch_count_semantics(tmp_path: Path) -> None:
    """Requirement Protected: total_findings_parsed, findings_triaged_ok, findings_with_errors counts are exact.

    Expected Result: parsed=3, ok=2 (includes MANUAL_REVIEW without errors), with_errors=1.
    Test Category: Count Semantics
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "ok1.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "app" / "ok2.py").write_text("y = 2\n", encoding="utf-8")

    f_ok = make_semgrep_finding(finding_id="f-ok", file_path="app/ok1.py")
    f_manual = make_semgrep_finding(finding_id="f-manual", file_path="app/ok2.py")
    f_err = make_semgrep_finding(finding_id="f-err", file_path="missing.py")

    semgrep_res = ScannerParseResult(findings=(f_ok, f_manual, f_err), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        semgrep_result=semgrep_res,
        repository_identifier="my-repo",
        prompt_type="fake.default",  # Yields NEEDS_REVIEW -> MANUAL_REVIEW (no errors -> triaged_ok)
    )

    meta = batch_res.run_metadata
    assert meta.total_findings_parsed == 3
    assert meta.findings_triaged_ok == 2
    assert meta.findings_with_errors == 1


# --- Group 5: RunMetadata Assembly Tests ---


def test_run_metadata_assembly_fields(tmp_path: Path) -> None:
    """Requirement Protected: RunMetadata fields are correctly assembled and run_id is a valid UUIDv4.

    Expected Result: run_id valid UUID, repository_name == 'repo', tool_version == TOOL_VERSION, timestamps UTC-aware.
    Test Category: RunMetadata Assembly
    """
    repo = tmp_path / "my_project_repo"
    repo.mkdir()

    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        repository_identifier="org/my_project_repo",
        commit_sha="abc123def",
        working_tree_state="clean",
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
    )

    meta = batch_res.run_metadata
    assert uuid.UUID(meta.run_id)  # Valid UUIDv4
    assert meta.repository_name == "my_project_repo"
    assert meta.repository_identifier == "org/my_project_repo"
    assert meta.commit_sha == "abc123def"
    assert meta.working_tree_state == "clean"
    assert meta.tool_version == TOOL_VERSION
    assert meta.triage_provider == "fake"
    assert meta.policy_version == POLICY_VERSION
    assert meta.cli_mode == "triage"
    assert meta.started_at.tzinfo == UTC
    assert meta.completed_at.tzinfo == UTC
    assert meta.completed_at >= meta.started_at


# --- Group 6: Security & Invariant Tests ---


def test_canary_not_in_batch_result_serialization(tmp_path: Path) -> None:
    """Requirement Protected: Secret canary in finding context is NEVER leaked into BatchResult serialization.

    Expected Result: CANARY absent from model_dump_json(), dict, repr, str.
    Test Category: Security Boundary
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "secret.py").write_text(f"# Comment: {CANARY}\nx = 1\n", encoding="utf-8")

    f1 = make_semgrep_finding(file_path="app/secret.py")
    semgrep_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")
    dump_json = batch_res.model_dump_json()

    assert CANARY not in dump_json
    assert CANARY not in repr(batch_res)
    assert CANARY not in str(batch_res)


def test_batch_result_frozen_and_caller_dict_unmutated(tmp_path: Path) -> None:
    """Requirement Protected: BatchResult is frozen and caller-owned dictionary maps are defensively copied.

    Expected Result: ValidationError on BatchResult mutation, caller_versions unmutated.
    Test Category: Result Invariants
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    caller_versions = {"semgrep": "1.50.0"}
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        repository_identifier="my-repo",
        scanner_versions=caller_versions,
    )

    assert batch_res.run_metadata.scanner_versions == {"semgrep": "1.50.0"}
    caller_versions["semgrep"] = "2.0.0"
    assert batch_res.run_metadata.scanner_versions == {"semgrep": "1.50.0"}

    with pytest.raises(ValidationError):
        batch_res.scanner_errors = []  # type: ignore[misc]


# --- Group 7: Configuration Validation & Scanner Identity Tests ---


def test_scanner_identity_mismatch_semgrep_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Passing a Gitleaks finding into semgrep_result raises PIPELINE_SCANNER_RESULT_MISMATCH.

    Expected Result: SastTriageError raised with PIPELINE_SCANNER_RESULT_MISMATCH.
    Test Category: Scanner Identity Validation
    """
    repo = tmp_path / "repo"
    g_finding = make_gitleaks_finding()
    semgrep_res = ScannerParseResult(findings=(g_finding,), errors=())
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert exc.value.error_code == "PIPELINE_SCANNER_RESULT_MISMATCH"


def test_scanner_identity_mismatch_gitleaks_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Passing a Semgrep finding into gitleaks_result raises PIPELINE_SCANNER_RESULT_MISMATCH.

    Expected Result: SastTriageError raised with PIPELINE_SCANNER_RESULT_MISMATCH.
    Test Category: Scanner Identity Validation
    """
    repo = tmp_path / "repo"
    s_finding = make_semgrep_finding()
    gitleaks_res = ScannerParseResult(findings=(s_finding,), errors=())
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, gitleaks_result=gitleaks_res, repository_identifier="my-repo")

    assert exc.value.error_code == "PIPELINE_SCANNER_RESULT_MISMATCH"


def test_invalid_repository_identifier_rejected(tmp_path: Path) -> None:
    """Requirement Protected: Empty or absolute path repository_identifier raises PIPELINE_INVALID_CONFIGURATION.

    Expected Result: SastTriageError raised.
    Test Category: Configuration Validation
    """
    repo = tmp_path / "repo"
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, repository_identifier="   ")
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, repository_identifier="/var/repo")
    assert exc.value.error_code == "PIPELINE_INVALID_CONFIGURATION"


def test_scanner_identity_mismatch_gitleaks_err_in_semgrep(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks ProcessingError in semgrep_result.errors raises PIPELINE_SCANNER_RESULT_MISMATCH.

    Expected Result: SastTriageError raised with PIPELINE_SCANNER_RESULT_MISMATCH.
    Test Category: Scanner Identity Validation
    """
    repo = tmp_path / "repo"
    err = ProcessingError(
        scanner=ScannerType.GITLEAKS,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_INVALID_JSON",
        safe_message="Mismatch",
    )
    semgrep_res = ScannerParseResult(findings=(), errors=(err,))
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert exc.value.error_code == "PIPELINE_SCANNER_RESULT_MISMATCH"


def test_scanner_identity_none_error_allowed(tmp_path: Path) -> None:
    """Requirement Protected: ProcessingError with scanner=None in semgrep_result is allowed.

    Expected Result: Batch completed without identity mismatch error.
    Test Category: Scanner Identity Validation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    err = ProcessingError(
        scanner=None,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_GLOBAL_ERROR",
        safe_message="Global artifact parse warning",
    )
    semgrep_res = ScannerParseResult(findings=(), errors=(err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")
    assert len(batch_res.scanner_errors) == 1
    assert batch_res.scanner_errors[0].scanner is None


def test_scanner_unknown_parse_error_not_succeeded(tmp_path: Path) -> None:
    """Requirement Protected: An unknown PARSE error code causes scanner to fail parse (fail-closed).

    Expected Result: SEMGREP in scanners_attempted but NOT in scanners_succeeded.
    Test Category: Fail-Closed Scanner Semantics
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    err = ProcessingError(
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_UNKNOWN_NEW_ERROR",
        safe_message="New parser error",
    )
    semgrep_res = ScannerParseResult(findings=(), errors=(err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")
    assert ScannerType.SEMGREP in batch_res.run_metadata.scanners_attempted
    assert ScannerType.SEMGREP not in batch_res.run_metadata.scanners_succeeded


def test_batch_mixed_valid_invalid_valid_records(tmp_path: Path) -> None:
    """Requirement Protected: Valid + record error + valid records allow scanner to succeed.

    Expected Result: SEMGREP in scanners_succeeded, record_err in scanner_errors, len(results) == 2.
    Test Category: Record Error Handling
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "s1.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "app" / "s2.py").write_text("y = 2\n", encoding="utf-8")

    f1 = make_semgrep_finding(finding_id="f1", file_path="app/s1.py")
    f2 = make_semgrep_finding(finding_id="f2", file_path="app/s2.py")
    record_err = ProcessingError(
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_RECORD_INVALID_FIELD",
        safe_message="Record 2 skipped",
    )

    semgrep_res = ScannerParseResult(findings=(f1, f2), errors=(record_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")
    assert ScannerType.SEMGREP in batch_res.run_metadata.scanners_succeeded
    assert len(batch_res.results) == 2
    assert len(batch_res.scanner_errors) == 1


def test_batch_runs_generate_different_run_ids(tmp_path: Path) -> None:
    """Requirement Protected: Multiple calls to triage_batch generate distinct run_id UUIDs.

    Expected Result: res1.run_metadata.run_id != res2.run_metadata.run_id.
    Test Category: RunMetadata Invariants
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    provider = FakeTriageProvider()

    res1 = triage_batch(repo, provider, repository_identifier="my-repo")
    res2 = triage_batch(repo, provider, repository_identifier="my-repo")

    assert res1.run_metadata.run_id != res2.run_metadata.run_id


def test_batch_per_finding_error_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requirement Protected: Unrecoverable exception from triage_finding propagates directly and stops batch.

    Expected Result: SastTriageError raised from triage_batch.
    Test Category: Error Propagation
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    f1 = make_semgrep_finding()
    semgrep_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    def mock_triage_finding(*args, **kwargs):
        raise SastTriageError(
            safe_message="Pipeline internal failure.",
            error_code="PIPELINE_INTERNAL_FAILURE",
            retryable=False,
        )

    monkeypatch.setattr("sast_triage.pipeline.batch.triage_finding", mock_triage_finding)

    with pytest.raises(SastTriageError) as exc:
        triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert exc.value.error_code == "PIPELINE_INTERNAL_FAILURE"


# --- Task 4.4.1 Batch Diagnostic Linkage Tests ---


def test_batch_gitleaks_sanitize_error_prevents_fp_candidate(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks parser SANITIZE error linked via finding_id prevents FP_CANDIDATE in batch.

    Expected Result: PolicyAction.MANUAL_REVIEW, findings_with_errors == 1, findings_triaged_ok == 0.
    Test Category: Task 4.4.1 Batch Diagnostic Linkage
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "secrets.py").write_text("KEY = 'val'\n", encoding="utf-8")

    f1 = make_gitleaks_finding(finding_id="g-01", file_path="tests/fixtures/secrets.py")
    sanitize_err = ProcessingError(
        finding_id="g-01",
        scanner=ScannerType.GITLEAKS,
        stage=ProcessingStage.SANITIZE,
        error_code="GITLEAKS_PRE_REDACT_FAILED",
        safe_message="Failed to redact secret.",
    )
    gitleaks_res = ScannerParseResult(findings=(f1,), errors=(sanitize_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        gitleaks_result=gitleaks_res,
        repository_identifier="my-repo",
        prompt_type="fake.fp.high",  # Provider would normally yield LIKELY_FP -> FP_CANDIDATE
    )

    assert len(batch_res.results) == 1
    res = batch_res.results[0]
    assert res.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert res.policy_decision.escalated is True
    assert len(res.processing_errors) == 1
    assert res.processing_errors[0].error_code == "GITLEAKS_PRE_REDACT_FAILED"
    assert batch_res.run_metadata.findings_with_errors == 1
    assert batch_res.run_metadata.findings_triaged_ok == 0
    assert ScannerType.GITLEAKS in batch_res.run_metadata.scanners_succeeded


def test_batch_clean_gitleaks_fixture_remains_fp_candidate(tmp_path: Path) -> None:
    """Requirement Protected: Clean Gitleaks fixture finding without SANITIZE error remains FP_CANDIDATE.

    Expected Result: PolicyAction.FP_CANDIDATE, findings_triaged_ok == 1.
    Test Category: Task 4.4.1 Batch Diagnostic Linkage
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "secrets.py").write_text("KEY = 'val'\n", encoding="utf-8")

    f1 = make_gitleaks_finding(finding_id="g-01", file_path="tests/fixtures/secrets.py")
    gitleaks_res = ScannerParseResult(findings=(f1,), errors=())
    provider = FakeTriageProvider()

    batch_res = triage_batch(
        repo,
        provider,
        gitleaks_result=gitleaks_res,
        repository_identifier="my-repo",
        prompt_type="fake.fp.high",
    )

    assert len(batch_res.results) == 1
    assert batch_res.results[0].policy_decision.action == PolicyAction.FP_CANDIDATE
    assert batch_res.run_metadata.findings_triaged_ok == 1
    assert batch_res.run_metadata.findings_with_errors == 0


def test_batch_orphan_finding_id_error_retained_in_scanner_errors(tmp_path: Path) -> None:
    """Requirement Protected: Error with orphan finding_id is kept in scanner_errors and NOT attached to any TriageResult.

    Expected Result: len(scanner_errors) == 1, len(results[0].processing_errors) == 0.
    Test Category: Orphan Error Handling
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "s1.py").write_text("x = 1\n", encoding="utf-8")

    f1 = make_semgrep_finding(finding_id="f-01", file_path="app/s1.py")
    orphan_err = ProcessingError(
        finding_id="nonexistent-finding-999",
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_RECORD_INVALID_FIELD",
        safe_message="Orphan record error",
    )
    semgrep_res = ScannerParseResult(findings=(f1,), errors=(orphan_err,))
    provider = FakeTriageProvider()

    batch_res = triage_batch(repo, provider, semgrep_result=semgrep_res, repository_identifier="my-repo")

    assert len(batch_res.scanner_errors) == 1
    assert batch_res.scanner_errors[0].finding_id == "nonexistent-finding-999"
    assert len(batch_res.results[0].processing_errors) == 0
