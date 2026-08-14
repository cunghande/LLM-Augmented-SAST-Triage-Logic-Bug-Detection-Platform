"""Tests for Safe Gitleaks JSON artifact parser."""

import json
from pathlib import Path

from sast_triage.models import (
    FindingType,
    ScannerType,
    Severity,
)
from sast_triage.parsers.gitleaks import parse_gitleaks_json

FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
CANARY = "CANARY_SUPER_SECRET_DO_NOT_LEAK"


# --- Fixture-based Tests ---


def test_valid_single_creates_one_finding() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    assert len(result.findings) == 1
    assert len(result.errors) == 0


def test_valid_single_scanner_and_type() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    assert f.scanner == ScannerType.GITLEAKS
    assert f.finding_type == FindingType.SECRET
    assert f.severity == Severity.UNKNOWN


def test_valid_single_mapping() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    assert f.rule_id == "aws-access-key"
    assert f.file_path == "config/aws_settings.py"
    assert f.start_line == 12
    assert f.end_line == 12
    assert f.rule_name == "AWS Access Key"
    assert f.message == "AWS Access Key"


def test_valid_single_redaction_applied() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    f = result.findings[0]
    assert "snippet" not in f.model_dump()
    assert CANARY not in f.model_dump_json()


def test_canary_absent_from_all_representations() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    finding = result.findings[0]

    # Verify canary not present in any representation or dump
    assert CANARY not in result.model_dump_json()
    assert CANARY not in str(result.model_dump())
    assert CANARY not in repr(result)
    assert CANARY not in str(result)
    assert CANARY not in repr(finding)
    assert CANARY not in finding.model_dump_json()

    for err in result.errors:
        assert CANARY not in err.safe_message
        assert CANARY not in repr(err)


def test_valid_multiple_creates_correct_count() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_multiple.json")
    assert len(result.findings) == 2
    assert len(result.errors) == 0


def test_valid_multiple_metadata_allowlist() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_multiple.json")
    f = result.findings[0]
    allowed_keys = {"entropy", "rule_description"}
    assert set(f.metadata.keys()).issubset(allowed_keys)
    assert "entropy" in f.metadata
    assert "rule_description" in f.metadata
    assert f.metadata["entropy"] == 4.52


def test_empty_array_returns_empty() -> None:
    result = parse_gitleaks_json(FIXTURES / "empty.json")
    assert result.findings == ()
    assert result.errors == ()


def test_malformed_json_creates_error() -> None:
    result = parse_gitleaks_json(FIXTURES / "malformed.json")
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_INVALID_JSON"


def test_missing_required_fields_creates_errors() -> None:
    result = parse_gitleaks_json(FIXTURES / "missing_required_fields.json")
    assert len(result.findings) == 0
    assert len(result.errors) == 2
    for err in result.errors:
        assert err.error_code == "PARSE_RECORD_MISSING_FIELD"


def test_file_not_found_creates_error() -> None:
    result = parse_gitleaks_json(Path("nonexistent_gitleaks_abc123.json"))
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_FILE_NOT_FOUND"


def test_parser_does_not_mutate_fixture() -> None:
    fixture = FIXTURES / "valid_single.json"
    content_before = fixture.read_text(encoding="utf-8")
    parse_gitleaks_json(fixture)
    content_after = fixture.read_text(encoding="utf-8")
    assert content_before == content_after


def test_no_raw_secret_fields_in_public_models() -> None:
    result = parse_gitleaks_json(FIXTURES / "valid_single.json")
    dumped = result.model_dump_json()
    assert '"Secret"' not in dumped
    assert '"Match"' not in dumped
    assert '"Author"' not in dumped
    assert '"Commit"' not in dumped
    assert '"Fingerprint"' not in dumped


# --- Edge Case Payload Tests (via tmp_path) ---


def test_redaction_no_match_fallback(tmp_path: Path) -> None:
    """Secret is provided but not found inside Match string."""
    payload = [
        {
            "RuleID": "test-rule",
            "File": "src/config.py",
            "StartLine": 5,
            "Secret": "SECRET_NOT_IN_MATCH",
            "Match": "API_KEY = UNRELATED_VALUE",
        }
    ]
    f = tmp_path / "no_match.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 1
    f_out = result.findings[0]
    assert "snippet" not in f_out.model_dump()
    assert "UNRELATED_VALUE" not in f_out.model_dump_json()

    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.error_code == "SANITIZE_SECRET_REDACTION_NO_MATCH"
    assert err.stage.value == "SANITIZE"
    assert "SECRET_NOT_IN_MATCH" not in err.safe_message


def test_missing_secret_value_fallback(tmp_path: Path) -> None:
    """Secret is null or whitespace."""
    payload = [
        {
            "RuleID": "test-rule",
            "File": "src/config.py",
            "StartLine": 5,
            "Secret": "   ",
            "Match": "API_KEY = SOME_RAW_VALUE",
        }
    ]
    f = tmp_path / "missing_secret.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 1
    f_out = result.findings[0]
    assert "snippet" not in f_out.model_dump()
    assert "SOME_RAW_VALUE" not in f_out.model_dump_json()

    assert len(result.errors) == 1
    assert result.errors[0].error_code == "SANITIZE_SECRET_VALUE_MISSING"


def test_missing_match_string_fallback(tmp_path: Path) -> None:
    """Match is missing or null."""
    payload = [
        {
            "RuleID": "test-rule",
            "File": "src/config.py",
            "StartLine": 5,
            "Secret": "SOME_SECRET_VAL",
        }
    ]
    f = tmp_path / "missing_match.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 1
    f_out = result.findings[0]
    assert "snippet" not in f_out.model_dump()

    assert len(result.errors) == 1
    assert result.errors[0].error_code == "SANITIZE_SECRET_MATCH_MISSING"


def test_invalid_end_line_fallback(tmp_path: Path) -> None:
    """EndLine < StartLine or non-integer still creates finding and logs PARSE error."""
    payload = [
        {
            "RuleID": "test-rule",
            "File": "src/config.py",
            "StartLine": 10,
            "EndLine": 5,  # EndLine < StartLine
            "Secret": CANARY,
            "Match": f"KEY={CANARY}",
        }
    ]
    f = tmp_path / "invalid_end_line.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 1
    f_out = result.findings[0]
    assert f_out.start_line == 10
    assert f_out.end_line == 10  # Defaulted to StartLine

    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.error_code == "PARSE_RECORD_INVALID_FIELD"
    assert err.stage.value == "PARSE"


def test_missing_description_fallback(tmp_path: Path) -> None:
    """Missing description uses fallback message and rule_name=None."""
    payload = [
        {
            "RuleID": "generic-secret",
            "File": "src/app.py",
            "StartLine": 1,
            "Secret": CANARY,
            "Match": f"VAL={CANARY}",
        }
    ]
    f = tmp_path / "no_desc.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 1
    f_out = result.findings[0]
    assert f_out.rule_name is None
    assert f_out.message == "Gitleaks finding for rule generic-secret"


def test_invalid_root_type(tmp_path: Path) -> None:
    """Top-level JSON is dict instead of list."""
    f = tmp_path / "dict_root.json"
    f.write_text('{"RuleID": "test"}', encoding="utf-8")

    result = parse_gitleaks_json(f)
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "PARSE_INVALID_ROOT"
