"""Tests for Semgrep JSON artifact parser."""

from pathlib import Path

from sast_triage.models import (
    FindingType,
    ScannerType,
    Severity,
)
from sast_triage.parsers.semgrep import parse_semgrep_json

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep"


# --- Artifact-level tests ---


def test_valid_single_creates_one_finding() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    assert len(result.findings) == 1
    assert len(result.errors) == 0


def test_valid_single_mapping() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    assert f.scanner == ScannerType.SEMGREP
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "python.lang.security.audit.eval-use.eval-use"
    assert f.file_path == "app/services/calculator.py"
    assert f.start_line == 24
    assert f.end_line == 24
    assert f.message == "Detected call to eval(). Dynamic code execution is unsafe."
    assert f.snippet == "result = eval(user_input)"


def test_valid_single_severity_mapping() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    # ERROR -> HIGH
    assert f.severity == Severity.HIGH


def test_valid_single_metadata_allowlist() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    allowed_keys = {"cwe", "owasp", "technology", "category", "confidence", "references"}
    assert set(f.metadata.keys()).issubset(allowed_keys)
    assert "cwe" in f.metadata
    assert "owasp" in f.metadata
    assert "technology" in f.metadata
    assert "references" in f.metadata


def test_valid_multiple_creates_correct_count() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_multiple.json")
    assert len(result.findings) == 2
    assert len(result.errors) == 0


def test_valid_multiple_severity_mapping() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_multiple.json")
    # First: ERROR -> HIGH
    assert result.findings[0].severity == Severity.HIGH
    # Second: WARNING -> MEDIUM
    assert result.findings[1].severity == Severity.MEDIUM


def test_valid_multiple_unique_finding_ids() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_multiple.json")
    ids = [f.finding_instance_id for f in result.findings]
    assert len(ids) == len(set(ids)), "finding_instance_ids must be unique"


def test_empty_results_returns_empty() -> None:
    result = parse_semgrep_json(FIXTURES / "empty.json")
    assert result.findings == ()
    assert result.errors == ()


def test_malformed_json_creates_error() -> None:
    result = parse_semgrep_json(FIXTURES / "malformed.json")
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.error_code == "PARSE_INVALID_JSON"
    assert err.scanner == ScannerType.SEMGREP


def test_missing_required_fields_creates_errors() -> None:
    result = parse_semgrep_json(FIXTURES / "missing_required_fields.json")
    # Both records in the fixture are missing required fields
    # (one missing check_id, one missing path)
    assert len(result.findings) == 0
    assert len(result.errors) == 2
    error_codes = {e.error_code for e in result.errors}
    assert "PARSE_RECORD_MISSING_FIELD" in error_codes


def test_file_not_found_creates_error() -> None:
    result = parse_semgrep_json(Path("nonexistent_file_abc123.json"))
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.error_code == "PARSE_FILE_NOT_FOUND"
    assert err.scanner == ScannerType.SEMGREP
    assert err.retryable is False


def test_parser_returns_tuples() -> None:
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    assert isinstance(result.findings, tuple)
    assert isinstance(result.errors, tuple)


def test_parser_output_has_no_raw_artifact(tmp_path: Path) -> None:
    """Verify serialized output contains no raw artifact content."""
    result = parse_semgrep_json(FIXTURES / "valid_single.json")
    dumped = result.model_dump_json()
    # Should not contain Semgrep-specific raw fields
    assert '"version"' not in dumped or '"1.170.0"' not in dumped
    assert '"check_id"' not in dumped
    assert '"extra"' not in dumped


def test_parser_does_not_mutate_fixture() -> None:
    """Parser must not modify the fixture file."""
    fixture = FIXTURES / "valid_single.json"
    content_before = fixture.read_text(encoding="utf-8")
    parse_semgrep_json(fixture)
    content_after = fixture.read_text(encoding="utf-8")
    assert content_before == content_after


# --- Edge cases ---


def test_invalid_root_type(tmp_path: Path) -> None:
    """Top-level JSON that is not an object."""
    f = tmp_path / "array_root.json"
    f.write_text('[{"check_id": "x"}]', encoding="utf-8")
    result = parse_semgrep_json(f)
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_INVALID_ROOT"


def test_results_not_array(tmp_path: Path) -> None:
    """results field is not an array."""
    f = tmp_path / "results_string.json"
    f.write_text('{"results": "not_array"}', encoding="utf-8")
    result = parse_semgrep_json(f)
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_RESULTS_INVALID"


def test_results_missing(tmp_path: Path) -> None:
    """Semgrep artifact with no results key."""
    f = tmp_path / "no_results.json"
    f.write_text('{"version": "1.0"}', encoding="utf-8")
    result = parse_semgrep_json(f)
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_RESULTS_MISSING"


def test_bad_record_does_not_crash_good_records(tmp_path: Path) -> None:
    """A bad record among valid ones produces errors + valid findings."""
    f = tmp_path / "mixed.json"
    f.write_text(
        """{
  "results": [
    {
      "check_id": "valid.rule",
      "path": "valid.py",
      "start": {"line": 1},
      "extra": {"message": "Valid finding", "severity": "INFO", "lines": "x=1"}
    },
    {
      "path": "no_check_id.py",
      "start": {"line": 5},
      "extra": {"message": "Bad record"}
    }
  ]
}""",
        encoding="utf-8",
    )
    result = parse_semgrep_json(f)
    assert len(result.findings) == 1
    assert len(result.errors) == 1
    assert result.findings[0].rule_id == "valid.rule"
    assert result.findings[0].severity == Severity.LOW  # INFO -> LOW
    assert result.errors[0].error_code == "PARSE_RECORD_MISSING_FIELD"


def test_safe_message_has_no_raw_content() -> None:
    """Error safe_message must not contain raw JSON or tracebacks."""
    result = parse_semgrep_json(FIXTURES / "malformed.json")
    for err in result.errors:
        assert "Traceback" not in err.safe_message
        assert "check_id" not in err.safe_message
        assert "{" not in err.safe_message
