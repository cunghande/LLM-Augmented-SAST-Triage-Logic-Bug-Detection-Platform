"""Tests for JSON report writer (Task 4.5A).

Covers:
- Happy path serialization correctness.
- Security schema: no forbidden fields in output.
- Forbidden value leak detection (canary tests).
- Output path / overwrite / atomic write behavior.
- Immutability and no side-effects guarantees.
- Operational error handling.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    BatchResult,
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PolicyAction,
    PolicyDecision,
    ProcessingError,
    ProcessingStage,
    RunMetadata,
    ScannerType,
    Severity,
    TriageDecision,
    TriageResult,
)
from sast_triage.reporting.json_reporter import write_json_report

# ---------------------------------------------------------------------------
# Security canary
# ---------------------------------------------------------------------------

REPORT_CANARY = "REPORT_SECRET_CANARY_DO_NOT_LEAK"

# ---------------------------------------------------------------------------
# Test fixtures helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
_LATER = datetime(2025, 6, 1, 12, 1, 0, tzinfo=UTC)


def _make_run_metadata(**overrides: Any) -> RunMetadata:
    """Create a minimal valid RunMetadata for testing."""
    defaults: dict[str, Any] = {
        "run_id": str(uuid.uuid4()),
        "repository_name": "test-repo",
        "repository_identifier": "org/test-repo",
        "artifact_repository_match": ArtifactRepositoryMatch.VERIFIED,
        "scanners_attempted": [ScannerType.SEMGREP],
        "scanners_succeeded": [ScannerType.SEMGREP],
        "policy_version": "1.0",
        "triage_provider": "FakeTriageProvider",
        "tool_version": "0.1.0",
        "cli_mode": "triage",
        "started_at": _NOW,
        "completed_at": _LATER,
        "total_findings_parsed": 1,
        "findings_triaged_ok": 1,
        "findings_with_errors": 0,
    }
    defaults.update(overrides)
    return RunMetadata(**defaults)


def _make_semgrep_finding(
    finding_id: str = "semgrep-001",
    file_path: str = "app/service.py",
    severity: Severity = Severity.MEDIUM,
) -> NormalizedFinding:
    """Create a minimal valid Semgrep NormalizedFinding."""
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="eval-use",
        file_path=file_path,
        start_line=10,
        end_line=10,
        severity=severity,
        message="Use of eval is dangerous.",
        metadata={"cwe": "CWE-78"},
    )


def _make_policy_decision(action: PolicyAction = PolicyAction.MANUAL_REVIEW) -> PolicyDecision:
    """Create a minimal valid PolicyDecision."""
    return PolicyDecision(
        action=action,
        reasons=["No triage decision available"],
        policy_version="1.0",
        escalated=False,
    )


def _make_triage_decision() -> TriageDecision:
    """Create a valid TriageDecision."""
    return TriageDecision(
        model_verdict=ModelVerdict.NEEDS_REVIEW,
        model_confidence=ModelConfidence.MEDIUM,
        summary="Insufficient context to determine.",
        model_version="fake-model-v1",
        prompt_version="v1",
    )


def _make_triage_result(
    finding: NormalizedFinding | None = None,
    *,
    context_summary: str | None = "Function uses eval.",
    policy_action: PolicyAction = PolicyAction.MANUAL_REVIEW,
) -> TriageResult:
    """Create a minimal valid TriageResult (MANUAL_REVIEW, no triage error)."""
    if finding is None:
        finding = _make_semgrep_finding()
    return TriageResult(
        finding=finding,
        context_summary=context_summary,
        triage_decision=_make_triage_decision(),
        policy_decision=_make_policy_decision(policy_action),
        processing_errors=[],
        processed_at=_LATER,
        processing_duration_ms=42,
    )


def _make_triage_error_result(finding: NormalizedFinding | None = None) -> TriageResult:
    """Create a TriageResult representing a TRIAGE_ERROR (no triage_decision)."""
    if finding is None:
        finding = _make_semgrep_finding()
    err = ProcessingError(
        finding_id=finding.finding_instance_id,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.TRIAGE,
        error_code="TRIAGE_PROVIDER_TIMEOUT",
        safe_message="Provider timed out.",
        retryable=True,
    )
    return TriageResult(
        finding=finding,
        context_summary=None,
        triage_decision=None,
        policy_decision=PolicyDecision(
            action=PolicyAction.TRIAGE_ERROR,
            reasons=["Provider timeout"],
            policy_version="1.0",
            escalated=False,
        ),
        processing_errors=[err],
        processed_at=_LATER,
    )





def _make_batch_result(
    *,
    results: list[TriageResult] | None = None,
    scanner_errors: list[ProcessingError] | None = None,
    **meta_overrides: Any,
) -> BatchResult:
    """Build a complete BatchResult for testing."""
    if results is None:
        results = [_make_triage_result()]
    if scanner_errors is None:
        scanner_errors = []
    defaults = {
        "total_findings_parsed": len(results),
        "findings_triaged_ok": sum(
            1 for r in results if r.policy_decision.action != PolicyAction.TRIAGE_ERROR
        ),
        "findings_with_errors": sum(
            1 for r in results if r.processing_errors
        ),
    }
    defaults.update(meta_overrides)
    meta = _make_run_metadata(**defaults)
    return BatchResult(run_metadata=meta, results=results, scanner_errors=scanner_errors)


# ---------------------------------------------------------------------------
# Group 1: Happy Path
# ---------------------------------------------------------------------------


def test_happy_path_writes_file(tmp_path: Path) -> None:
    """Test name: test_happy_path_writes_file
    Requirement: Reporter writes a JSON file to the given output path.
    Expected result: output file exists after write_json_report returns.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    result = write_json_report(batch, out)
    assert out.exists()
    assert result == out.resolve()


def test_happy_path_file_parseable(tmp_path: Path) -> None:
    """Test name: test_happy_path_file_parseable
    Requirement: Written file must be parseable by json.loads.
    Expected result: json.loads(out.read_text()) succeeds without exception.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)


def test_happy_path_run_metadata_present(tmp_path: Path) -> None:
    """Test name: test_happy_path_run_metadata_present
    Requirement: Serialized JSON must contain 'run_metadata' key.
    Expected result: parsed['run_metadata'] is a dict.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert "run_metadata" in parsed
    assert isinstance(parsed["run_metadata"], dict)


def test_happy_path_results_present(tmp_path: Path) -> None:
    """Test name: test_happy_path_results_present
    Requirement: Serialized JSON must contain 'results' key.
    Expected result: parsed['results'] is a list.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert "results" in parsed
    assert isinstance(parsed["results"], list)
    assert len(parsed["results"]) == 1


def test_happy_path_scanner_errors_present(tmp_path: Path) -> None:
    """Test name: test_happy_path_scanner_errors_present
    Requirement: Serialized JSON must contain 'scanner_errors' key.
    Expected result: parsed['scanner_errors'] is a list.
    Test category: happy path
    """
    batch = _make_batch_result(scanner_errors=[])
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert "scanner_errors" in parsed
    assert isinstance(parsed["scanner_errors"], list)


def test_happy_path_enum_serialized_as_string(tmp_path: Path) -> None:
    """Test name: test_happy_path_enum_serialized_as_string
    Requirement: Enum values must serialize as their string values, not numeric indices.
    Expected result: scanner value is "SEMGREP" string.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    # Check scanner inside findings
    finding_data = parsed["results"][0]["finding"]
    assert finding_data["scanner"] == "SEMGREP"
    assert finding_data["finding_type"] == "SAST"
    assert finding_data["severity"] == "MEDIUM"
    # Check in run_metadata
    assert parsed["run_metadata"]["scanners_attempted"] == ["SEMGREP"]


def test_happy_path_datetime_iso8601(tmp_path: Path) -> None:
    """Test name: test_happy_path_datetime_iso8601
    Requirement: datetime fields must serialize as ISO 8601 strings.
    Expected result: started_at is parseable as datetime.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    started_str = parsed["run_metadata"]["started_at"]
    assert isinstance(started_str, str)
    # Must be parseable
    parsed_dt = datetime.fromisoformat(started_str)
    assert parsed_dt is not None


def test_happy_path_unicode_preserved(tmp_path: Path) -> None:
    """Test name: test_happy_path_unicode_preserved
    Requirement: Unicode characters in string fields must be preserved, not escaped.
    Expected result: Vietnamese characters in message appear as-is.
    Test category: happy path
    """
    finding = _make_semgrep_finding()
    # Vietnamese unicode in policy reason
    result = TriageResult(
        finding=finding,
        context_summary="Hàm sử dụng eval — nguy hiểm.",
        triage_decision=_make_triage_decision(),
        policy_decision=PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=["Cần xem xét thêm"],
            policy_version="1.0",
            escalated=False,
        ),
        processing_errors=[],
        processed_at=_LATER,
    )
    batch = _make_batch_result(results=[result])
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw_text = out.read_text(encoding="utf-8")
    # Verify Unicode is not escaped (ensure_ascii=False)
    assert "Hàm sử dụng eval" in raw_text
    assert "Cần xem xét thêm" in raw_text


def test_happy_path_trailing_newline(tmp_path: Path) -> None:
    """Test name: test_happy_path_trailing_newline
    Requirement: Written file must end with a newline character.
    Expected result: file content ends with '\\n'.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    content = out.read_bytes()
    assert content.endswith(b"\n")


def test_happy_path_return_path(tmp_path: Path) -> None:
    """Test name: test_happy_path_return_path
    Requirement: Return value must be the resolved output Path.
    Expected result: returned path equals output_path.resolve().
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    returned = write_json_report(batch, out)
    assert returned == out.resolve()
    assert isinstance(returned, Path)


# ---------------------------------------------------------------------------
# Group 2: Security Schema Checks
# ---------------------------------------------------------------------------


def test_schema_no_sanitized_context(tmp_path: Path) -> None:
    """Test name: test_schema_no_sanitized_context
    Requirement: 'sanitized_context' must never appear in JSON output.
    Expected result: key absent from entire JSON text.
    Test category: security
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    assert "sanitized_context" not in raw


def test_schema_no_sanitized_snippet(tmp_path: Path) -> None:
    """Test name: test_schema_no_sanitized_snippet
    Requirement: 'sanitized_snippet' must never appear in JSON output.
    Expected result: key absent from entire JSON text.
    Test category: security
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    assert "sanitized_snippet" not in raw


def test_schema_no_raw_source_or_selected_text(tmp_path: Path) -> None:
    """Test name: test_schema_no_raw_source_or_selected_text
    Requirement: 'raw_source', 'source_snippet', 'selected_text' must never appear.
    Expected result: all three keys absent from JSON text.
    Test category: security
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    assert "raw_source" not in raw
    assert "source_snippet" not in raw
    assert "selected_text" not in raw


def test_schema_forbidden_key_in_injected_dict_rejected(tmp_path: Path) -> None:
    """Test name: test_schema_forbidden_key_in_injected_dict_rejected
    Requirement: If a forbidden key appears via Pydantic serialization (simulated),
    the forbidden field check must reject before writing.
    Expected result: SastTriageError with REPORT_FORBIDDEN_FIELD; file not created.
    Test category: security
    """
    from sast_triage.reporting.json_reporter import _check_forbidden_keys

    bad_dict: dict = {"results": [{"sanitized_context": "should not exist"}]}
    with pytest.raises(SastTriageError) as exc_info:
        _check_forbidden_keys(bad_dict)
    assert exc_info.value.error_code == "REPORT_FORBIDDEN_FIELD"
    # Key name may appear in message, but no value
    assert "sanitized_context" in exc_info.value.safe_message


def test_schema_nested_forbidden_key_rejected(tmp_path: Path) -> None:
    """Test name: test_schema_nested_forbidden_key_rejected
    Requirement: Forbidden keys nested deep in the dict tree must also be detected.
    Expected result: SastTriageError with REPORT_FORBIDDEN_FIELD.
    Test category: security
    """
    from sast_triage.reporting.json_reporter import _check_forbidden_keys

    deep_dict: dict = {"a": {"b": [{"function_body": "def foo(): pass"}]}}
    with pytest.raises(SastTriageError) as exc_info:
        _check_forbidden_keys(deep_dict)
    assert exc_info.value.error_code == "REPORT_FORBIDDEN_FIELD"


def test_schema_scanner_raw_artifact_absent(tmp_path: Path) -> None:
    """Test name: test_schema_scanner_raw_artifact_absent
    Requirement: No scanner raw artifact content must appear in the report.
    Expected result: 'raw_match' and 'Secret' keys absent from JSON.
    Test category: security
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    assert "raw_match" not in raw
    assert '"Secret"' not in raw


def test_schema_absolute_repository_path_absent(tmp_path: Path) -> None:
    """Test name: test_schema_absolute_repository_path_absent
    Requirement: Absolute repository root must not appear in the report.
    Expected result: tmp_path absolute path not in JSON.
    Test category: security
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    # The NormalizedFinding only carries relative file_path, not absolute repo root.
    # Verify that the absolute tmp_path prefix is not in the report.
    assert str(tmp_path).replace("\\", "/") not in raw


# ---------------------------------------------------------------------------
# Group 3: Forbidden Values (Canary)
# ---------------------------------------------------------------------------


def test_canary_in_report_data_prevents_write(tmp_path: Path) -> None:
    """Test name: test_canary_in_report_data_prevents_write
    Requirement: If forbidden canary value appears in report-facing data,
    write_json_report must not write the file.
    Expected result: SastTriageError(REPORT_LEAK_CHECK_FAILED); file not created.
    Test category: security
    """
    # Inject canary into a safe report-facing field (repository_identifier).
    batch = _make_batch_result(repository_identifier=f"org/{REPORT_CANARY}")
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=(REPORT_CANARY,))

    assert exc_info.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert not out.exists(), "Output file must NOT be created when leak check fails"


def test_canary_not_in_exception_message(tmp_path: Path) -> None:
    """Test name: test_canary_not_in_exception_message
    Requirement: Exception message must not contain the forbidden canary value.
    Expected result: REPORT_CANARY string absent from exception message.
    Test category: security
    """
    batch = _make_batch_result(repository_identifier=f"org/{REPORT_CANARY}")
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=(REPORT_CANARY,))

    assert REPORT_CANARY not in exc_info.value.safe_message
    assert REPORT_CANARY not in str(exc_info.value)


def test_canary_in_policy_reason_prevents_write(tmp_path: Path) -> None:
    """Test name: test_canary_in_policy_reason_prevents_write
    Requirement: Canary in a policy reason (safe_message equivalent) must be detected.
    Expected result: SastTriageError(REPORT_LEAK_CHECK_FAILED); file not created.
    Test category: security
    """
    finding = _make_semgrep_finding()
    result = TriageResult(
        finding=finding,
        context_summary="Normal context.",
        triage_decision=_make_triage_decision(),
        policy_decision=PolicyDecision(
            action=PolicyAction.MANUAL_REVIEW,
            reasons=[f"Reason contains {REPORT_CANARY}"],
            policy_version="1.0",
            escalated=False,
        ),
        processing_errors=[],
        processed_at=_LATER,
    )
    batch = _make_batch_result(results=[result])
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=(REPORT_CANARY,))

    assert exc_info.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert not out.exists()


def test_canary_in_safe_message_prevents_write(tmp_path: Path) -> None:
    """Test name: test_canary_in_safe_message_prevents_write
    Requirement: Canary in a ProcessingError.safe_message must be detected.
    Expected result: SastTriageError(REPORT_LEAK_CHECK_FAILED); file not created.
    Test category: security
    """
    finding = _make_semgrep_finding()
    proc_err = ProcessingError(
        finding_id=finding.finding_instance_id,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.TRIAGE,
        error_code="TRIAGE_PROVIDER_TIMEOUT",
        safe_message=f"Timeout: {REPORT_CANARY}",
        retryable=True,
    )
    result = TriageResult(
        finding=finding,
        context_summary=None,
        triage_decision=None,
        policy_decision=PolicyDecision(
            action=PolicyAction.TRIAGE_ERROR,
            reasons=["Provider timeout"],
            policy_version="1.0",
            escalated=False,
        ),
        processing_errors=[proc_err],
        processed_at=_LATER,
    )
    batch = _make_batch_result(
        results=[result],
        findings_triaged_ok=0,
        findings_with_errors=1,
    )
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=(REPORT_CANARY,))

    assert exc_info.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert not out.exists()


def test_empty_forbidden_value_rejected(tmp_path: Path) -> None:
    """Test name: test_empty_forbidden_value_rejected
    Requirement: Empty string in forbidden_values must raise REPORT_INVALID_INPUT.
    Expected result: SastTriageError(REPORT_INVALID_INPUT) before any I/O.
    Test category: validation
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=("",))

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_whitespace_only_forbidden_value_rejected(tmp_path: Path) -> None:
    """Test name: test_whitespace_only_forbidden_value_rejected
    Requirement: Whitespace-only string in forbidden_values must raise REPORT_INVALID_INPUT.
    Expected result: SastTriageError(REPORT_INVALID_INPUT).
    Test category: validation
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=("   ",))

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_known_safe_placeholder_in_forbidden_values_rejected(tmp_path: Path) -> None:
    """Test name: test_known_safe_placeholder_in_forbidden_values_rejected
    Requirement: Known-safe redaction placeholders must not be used as forbidden values.
    Expected result: SastTriageError(REPORT_INVALID_INPUT) for <REDACTED_SECRET>.
    Test category: validation
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, forbidden_values=("<REDACTED_SECRET>",))

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_duplicate_forbidden_values_handled_deterministically(tmp_path: Path) -> None:
    """Test name: test_duplicate_forbidden_values_handled_deterministically
    Requirement: Duplicate forbidden values must be processed without error or mutation.
    Expected result: write succeeds (no canary in report), duplicates silently deduplicated.
    Test category: validation
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    canary_not_in_report = "SAFE_CANARY_NOT_IN_ANY_FIELD"

    # Provide duplicates — should not cause an error or false positive.
    write_json_report(
        batch, out, forbidden_values=(canary_not_in_report, canary_not_in_report)
    )
    assert out.exists()


# ---------------------------------------------------------------------------
# Group 4: Output / Overwrite Behavior
# ---------------------------------------------------------------------------


def test_missing_parent_dir_raises(tmp_path: Path) -> None:
    """Test name: test_missing_parent_dir_raises
    Requirement: If parent directory does not exist, raise REPORT_INVALID_INPUT.
    Expected result: SastTriageError(REPORT_INVALID_INPUT).
    Test category: filesystem failure
    """
    batch = _make_batch_result()
    out = tmp_path / "nonexistent" / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out)

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_parent_is_file_raises(tmp_path: Path) -> None:
    """Test name: test_parent_is_file_raises
    Requirement: If parent path is a file (not a directory), raise REPORT_INVALID_INPUT.
    Expected result: SastTriageError(REPORT_INVALID_INPUT).
    Test category: filesystem failure
    """
    # Create a file where the parent would be
    fake_parent = tmp_path / "file_not_dir"
    fake_parent.write_text("I am a file", encoding="utf-8")
    out = fake_parent / "report.json"

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(_make_batch_result(), out)

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_output_path_is_directory_raises(tmp_path: Path) -> None:
    """Test name: test_output_path_is_directory_raises
    Requirement: If output_path points to an existing directory, raise REPORT_INVALID_INPUT.
    Expected result: SastTriageError(REPORT_INVALID_INPUT).
    Test category: filesystem failure
    """
    batch = _make_batch_result()
    out_dir = tmp_path / "output_dir"
    out_dir.mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out_dir)

    assert exc_info.value.error_code == "REPORT_INVALID_INPUT"


def test_overwrite_false_existing_file_raises(tmp_path: Path) -> None:
    """Test name: test_overwrite_false_existing_file_raises
    Requirement: overwrite=False with existing output file must raise REPORT_OUTPUT_EXISTS.
    Expected result: SastTriageError(REPORT_OUTPUT_EXISTS).
    Test category: filesystem failure
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    out.write_text("existing content", encoding="utf-8")

    with pytest.raises(SastTriageError) as exc_info:
        write_json_report(batch, out, overwrite=False)

    assert exc_info.value.error_code == "REPORT_OUTPUT_EXISTS"
    # Original file must be untouched
    assert out.read_text(encoding="utf-8") == "existing content"


def test_overwrite_true_replaces_file(tmp_path: Path) -> None:
    """Test name: test_overwrite_true_replaces_file
    Requirement: overwrite=True must replace an existing file with new JSON.
    Expected result: file content is new valid JSON, original content gone.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    out.write_text("old content", encoding="utf-8")

    write_json_report(batch, out, overwrite=True)

    new_content = out.read_text(encoding="utf-8")
    assert new_content != "old content"
    parsed = json.loads(new_content)
    assert "run_metadata" in parsed


def test_existing_output_not_corrupted_on_write_failure(tmp_path: Path) -> None:
    """Test name: test_existing_output_not_corrupted_on_write_failure
    Requirement: If write fails, the existing output file must not be corrupted.
    Expected result: original content remains intact; SastTriageError raised.
    Test category: filesystem failure
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    original_content = '{"original": "content"}\n'
    out.write_text(original_content, encoding="utf-8")

    # Simulate os.replace failure — write to tmp succeeds but replace fails.
    with patch("sast_triage.reporting.json_reporter.os.replace") as mock_replace:
        mock_replace.side_effect = OSError("Permission denied")
        with pytest.raises(SastTriageError) as exc_info:
            write_json_report(batch, out, overwrite=True)

    assert exc_info.value.error_code == "REPORT_WRITE_ERROR"
    # Original file must be unchanged.
    assert out.read_text(encoding="utf-8") == original_content


def test_temp_file_cleaned_up_on_write_failure(tmp_path: Path) -> None:
    """Test name: test_temp_file_cleaned_up_on_write_failure
    Requirement: Temporary file must be deleted if the atomic rename fails.
    Expected result: No .tmp files remain in parent directory after failure.
    Test category: filesystem failure
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with patch("sast_triage.reporting.json_reporter.os.replace") as mock_replace:
        mock_replace.side_effect = OSError("Disk full")
        with pytest.raises(SastTriageError):
            write_json_report(batch, out, overwrite=True)

    # No .tmp files should remain
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == [], f"Temp files not cleaned up: {tmp_files}"


# ---------------------------------------------------------------------------
# Group 5: Immutability / No Side Effects
# ---------------------------------------------------------------------------


def test_batch_result_not_mutated(tmp_path: Path) -> None:
    """Test name: test_batch_result_not_mutated
    Requirement: BatchResult must not be mutated by write_json_report.
    Expected result: BatchResult fields identical before and after the call.
    Test category: immutability
    """
    batch = _make_batch_result()
    original_run_id = batch.run_metadata.run_id
    original_results_count = len(batch.results)
    out = tmp_path / "report.json"

    write_json_report(batch, out)

    assert batch.run_metadata.run_id == original_run_id
    assert len(batch.results) == original_results_count


def test_caller_forbidden_values_not_mutated(tmp_path: Path) -> None:
    """Test name: test_caller_forbidden_values_not_mutated
    Requirement: Caller's forbidden_values tuple must not be mutated.
    Expected result: Same tuple identity/content after the call.
    Test category: immutability
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    canary_not_in_report = "SAFE_CANARY_ABSENT_FROM_REPORT"
    fv: tuple[str, ...] = (canary_not_in_report,)
    original_fv = fv

    write_json_report(batch, out, forbidden_values=fv)

    assert fv is original_fv
    assert fv == (canary_not_in_report,)


def test_no_extra_files_created(tmp_path: Path) -> None:
    """Test name: test_no_extra_files_created
    Requirement: Reporter must not create any files besides the final output file.
    Expected result: Only 'report.json' exists in tmp_path after successful write.
    Test category: immutability
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    write_json_report(batch, out)

    all_files = list(tmp_path.iterdir())
    assert len(all_files) == 1
    assert all_files[0].name == "report.json"


# ---------------------------------------------------------------------------
# Group 6: Operational Errors
# ---------------------------------------------------------------------------


def test_serialization_error_is_caught_and_wrapped(tmp_path: Path) -> None:
    """Test name: test_serialization_error_is_caught_and_wrapped
    Requirement: If model_dump or json encoding raises an unexpected exception, wrap in SastTriageError.
    Expected result: SastTriageError with REPORT_SERIALIZATION_ERROR.
    Test category: operational error
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with (
        patch("sast_triage.reporting.json_reporter.json.dumps", side_effect=RuntimeError("unexpected")),
        pytest.raises(SastTriageError) as exc_info,
    ):
        write_json_report(batch, out)

    assert exc_info.value.error_code in (
        "REPORT_SERIALIZATION_ERROR",
        "REPORT_WRITE_ERROR",
    )


def test_keyboard_interrupt_not_caught(tmp_path: Path) -> None:
    """Test name: test_keyboard_interrupt_not_caught
    Requirement: KeyboardInterrupt must propagate unhandled.
    Expected result: KeyboardInterrupt is raised, not wrapped in SastTriageError.
    Test category: operational error
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with (
        patch("sast_triage.reporting.json_reporter.json.dumps", side_effect=KeyboardInterrupt),
        pytest.raises(KeyboardInterrupt),
    ):
        write_json_report(batch, out)


def test_system_exit_not_caught(tmp_path: Path) -> None:
    """Test name: test_system_exit_not_caught
    Requirement: SystemExit must propagate unhandled.
    Expected result: SystemExit is raised, not wrapped in SastTriageError.
    Test category: operational error
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"

    with (
        patch("sast_triage.reporting.json_reporter.json.dumps", side_effect=SystemExit(1)),
        pytest.raises(SystemExit),
    ):
        write_json_report(batch, out)


# ---------------------------------------------------------------------------
# Group 7: Edge Cases / Full Coverage
# ---------------------------------------------------------------------------


def test_empty_results_list_serializes_correctly(tmp_path: Path) -> None:
    """Test name: test_empty_results_list_serializes_correctly
    Requirement: BatchResult with no findings must serialize without error.
    Expected result: results == [] in JSON output.
    Test category: happy path
    """
    meta = _make_run_metadata(
        total_findings_parsed=0,
        findings_triaged_ok=0,
        findings_with_errors=0,
        scanners_attempted=[ScannerType.SEMGREP],
        scanners_succeeded=[ScannerType.SEMGREP],
    )
    batch = BatchResult(run_metadata=meta, results=[], scanner_errors=[])
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["results"] == []


def test_multiple_findings_in_results(tmp_path: Path) -> None:
    """Test name: test_multiple_findings_in_results
    Requirement: Multiple TriageResults serialize correctly with distinct finding IDs.
    Expected result: results list contains 2 entries with correct finding_instance_ids.
    Test category: happy path
    """
    f1 = _make_semgrep_finding("finding-001", file_path="app/a.py")
    f2 = _make_semgrep_finding("finding-002", file_path="app/b.py")
    r1 = _make_triage_result(f1)
    r2 = _make_triage_result(f2)

    meta = _make_run_metadata(
        total_findings_parsed=2,
        findings_triaged_ok=2,
        findings_with_errors=0,
        scanners_attempted=[ScannerType.SEMGREP],
        scanners_succeeded=[ScannerType.SEMGREP],
    )
    batch = BatchResult(run_metadata=meta, results=[r1, r2], scanner_errors=[])
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))

    assert len(parsed["results"]) == 2
    ids = [r["finding"]["finding_instance_id"] for r in parsed["results"]]
    assert "finding-001" in ids
    assert "finding-002" in ids


def test_triage_error_result_serializes(tmp_path: Path) -> None:
    """Test name: test_triage_error_result_serializes
    Requirement: TriageResult with triage_decision=None (TRIAGE_ERROR) serializes.
    Expected result: triage_decision is null in JSON; policy action is TRIAGE_ERROR.
    Test category: happy path
    """
    result = _make_triage_error_result()
    meta = _make_run_metadata(
        total_findings_parsed=1,
        findings_triaged_ok=0,
        findings_with_errors=1,
    )
    batch = BatchResult(run_metadata=meta, results=[result], scanner_errors=[])
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))

    result_data = parsed["results"][0]
    assert result_data["triage_decision"] is None
    assert result_data["policy_decision"]["action"] == "TRIAGE_ERROR"


def test_scanner_errors_serialize(tmp_path: Path) -> None:
    """Test name: test_scanner_errors_serialize
    Requirement: scanner_errors in BatchResult serialize with correct fields.
    Expected result: scanner_errors[0] has error_code, stage, safe_message.
    Test category: happy path
    """
    parse_err = ProcessingError(
        finding_id=None,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code="SEMGREP_PARSE_FAILED",
        safe_message="JSON parse failure.",
        retryable=False,
    )
    meta = _make_run_metadata(
        total_findings_parsed=0,
        findings_triaged_ok=0,
        findings_with_errors=0,
    )
    batch = BatchResult(run_metadata=meta, results=[], scanner_errors=[parse_err])
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))

    assert len(parsed["scanner_errors"]) == 1
    err_data = parsed["scanner_errors"][0]
    assert err_data["error_code"] == "SEMGREP_PARSE_FAILED"
    assert err_data["stage"] == "PARSE"
    assert err_data["safe_message"] == "JSON parse failure."


def test_context_summary_none_serializes_as_null(tmp_path: Path) -> None:
    """Test name: test_context_summary_none_serializes_as_null
    Requirement: context_summary=None must serialize to JSON null.
    Expected result: context_summary field is null in JSON.
    Test category: happy path
    """
    result = _make_triage_error_result()  # has context_summary=None
    meta = _make_run_metadata(
        total_findings_parsed=1,
        findings_triaged_ok=0,
        findings_with_errors=1,
    )
    batch = BatchResult(run_metadata=meta, results=[result], scanner_errors=[])
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["results"][0]["context_summary"] is None


def test_indented_output(tmp_path: Path) -> None:
    """Test name: test_indented_output
    Requirement: JSON output must be formatted with 2-space indentation (human-readable).
    Expected result: File content contains lines with 2-space indent.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw = out.read_text(encoding="utf-8")
    # 2-space indent means we'll see "  " at start of indented lines
    lines = raw.splitlines()
    indented_lines = [l for l in lines if l.startswith("  ")]
    assert len(indented_lines) > 0


def test_utf8_encoding(tmp_path: Path) -> None:
    """Test name: test_utf8_encoding
    Requirement: Output file must be valid UTF-8 encoded.
    Expected result: File bytes decode as UTF-8 without error.
    Test category: happy path
    """
    batch = _make_batch_result()
    out = tmp_path / "report.json"
    write_json_report(batch, out)
    raw_bytes = out.read_bytes()
    # Should not raise
    decoded = raw_bytes.decode("utf-8")
    assert len(decoded) > 0


def test_safe_projection_excludes_snippet_and_preserves_safe_fields(tmp_path: Path) -> None:
    """The default report uses an explicit finding allowlist."""
    canary = "SEMGREP_SNIPPET_CANARY_DO_NOT_REPORT"
    finding = NormalizedFinding(
        finding_instance_id="semgrep-projection-1",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.lang.security.audit.eval-detected",
        rule_name="dangerous-eval",
        file_path="app/service.py",
        start_line=10,
        end_line=12,
        severity=Severity.HIGH,
        message="Unsafe evaluation.",
        metadata={"cwe": ["CWE-95"], "category": "security"},
    )
    batch = _make_batch_result(
        results=[_make_triage_result(finding, context_summary="Safe summary")]
    )
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    parsed = json.loads(out.read_text(encoding="utf-8"))
    projected_finding = parsed["results"][0]["finding"]

    assert set(projected_finding) == {
        "finding_instance_id", "scanner", "finding_type", "rule_id",
        "rule_name", "file_path", "start_line", "end_line", "severity",
        "message", "metadata",
    }
    assert "snippet" not in projected_finding
    assert canary not in out.read_text(encoding="utf-8")
    assert projected_finding["metadata"] == {"cwe": ["CWE-95"], "category": "security"}
    assert parsed["results"][0]["context_summary"] == "Safe summary"


def test_safe_projection_handles_gitleaks_and_retains_batch_contract(tmp_path: Path) -> None:
    """Gitleaks snippets are excluded while decisions, errors, metadata and order remain."""
    gitleaks_finding = NormalizedFinding(
        finding_instance_id="gitleaks-projection-1",
        scanner=ScannerType.GITLEAKS,
        finding_type=FindingType.SECRET,
        rule_id="generic-api-key",
        rule_name="Generic API Key",
        file_path="tests/fixtures/secrets.py",
        start_line=3,
        end_line=3,
        severity=Severity.UNKNOWN,
        message="Potential secret.",
        metadata={"secret_category": "api_key"},
    )
    first = _make_triage_result(_make_semgrep_finding("first"), context_summary="first context")
    second = _make_triage_error_result(gitleaks_finding)
    scanner_error = ProcessingError(
        scanner=ScannerType.GITLEAKS,
        stage=ProcessingStage.PARSE,
        error_code="PARSE_WARNING",
        safe_message="A safe parser diagnostic.",
    )
    batch = _make_batch_result(
        results=[first, second],
        scanner_errors=[scanner_error],
        total_findings_parsed=2,
        findings_triaged_ok=1,
        findings_with_errors=1,
        scanners_attempted=[ScannerType.SEMGREP, ScannerType.GITLEAKS],
        scanners_succeeded=[ScannerType.SEMGREP, ScannerType.GITLEAKS],
    )
    before = batch.model_dump(mode="json")
    out = tmp_path / "report.json"

    write_json_report(batch, out)
    content = out.read_text(encoding="utf-8")
    parsed = json.loads(content)

    assert [item["finding"]["finding_instance_id"] for item in parsed["results"]] == [
        "first", "gitleaks-projection-1"
    ]
    assert parsed["results"][1]["triage_decision"] is None
    assert parsed["results"][1]["policy_decision"]["action"] == "TRIAGE_ERROR"
    assert parsed["results"][1]["processing_errors"][0]["error_code"] == "TRIAGE_PROVIDER_TIMEOUT"
    assert parsed["scanner_errors"][0]["safe_message"] == "A safe parser diagnostic."
    assert parsed["run_metadata"]["repository_identifier"] == "org/test-repo"
    assert "<REDACTED_SECRET>" not in content
    assert batch.model_dump(mode="json") == before
    assert content.endswith("\n")
    assert "\n  \"results\"" in content

    forbidden_keys = {
        "snippet", "sanitized_context", "sanitized_snippet", "raw_source",
        "source_snippet", "selected_text", "raw_match", "Secret", "function_body",
    }

    def walk(value: Any) -> list[str]:
        if isinstance(value, dict):
            return list(value) + [key for child in value.values() for key in walk(child)]
        if isinstance(value, list):
            return [key for child in value for key in walk(child)]
        return []

    assert forbidden_keys.isdisjoint(walk(parsed))
