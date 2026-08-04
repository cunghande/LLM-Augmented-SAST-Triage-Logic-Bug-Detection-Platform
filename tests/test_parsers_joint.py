"""Joint audit test suite for Semgrep and Gitleaks parsers.

Verifies common output contracts, scanner-specific behavior, record isolation,
sequential parser independence, metadata allowlist enforcement, sanitize error linkage,
and security canary non-leakage.
"""

import json
from pathlib import Path
from unittest.mock import patch

from sast_triage.models import (
    ProcessingStage,
    ScannerParseResult,
    ScannerType,
)
from sast_triage.parsers.gitleaks import parse_gitleaks_json
from sast_triage.parsers.semgrep import parse_semgrep_json

SEMGREP_FIXTURES = Path(__file__).parent / "fixtures" / "semgrep"
GITLEAKS_FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
CANARY = "CANARY_SUPER_SECRET_DO_NOT_LEAK"


# --- 1. Common Output Contract ---


def test_common_output_contract_types() -> None:
    sg_res = parse_semgrep_json(SEMGREP_FIXTURES / "valid_single.json")
    gl_res = parse_gitleaks_json(GITLEAKS_FIXTURES / "valid_single.json")

    assert isinstance(sg_res, ScannerParseResult)
    assert isinstance(gl_res, ScannerParseResult)

    assert isinstance(sg_res.findings, tuple)
    assert isinstance(sg_res.errors, tuple)
    assert isinstance(gl_res.findings, tuple)
    assert isinstance(gl_res.errors, tuple)

    # Check no raw artifact or absolute path in dumps
    sg_dump = sg_res.model_dump_json()
    gl_dump = gl_res.model_dump_json()

    assert "version" not in sg_dump or "1.170.0" not in sg_dump
    assert "Commit" not in gl_dump
    assert "Author" not in gl_dump
    assert "C:\\" not in sg_dump and "/home/" not in sg_dump
    assert "C:\\" not in gl_dump and "/home/" not in gl_dump


# --- 2. Empty Report Behavior ---


def test_empty_reports_both_scanners() -> None:
    sg_res = parse_semgrep_json(SEMGREP_FIXTURES / "empty.json")
    gl_res = parse_gitleaks_json(GITLEAKS_FIXTURES / "empty.json")

    assert sg_res.findings == ()
    assert sg_res.errors == ()
    assert gl_res.findings == ()
    assert gl_res.errors == ()


# --- 3. Sequential Parser Independence ---


def test_sequential_independence_semgrep_malformed_then_gitleaks_valid() -> None:
    sg_res = parse_semgrep_json(SEMGREP_FIXTURES / "malformed.json")
    assert len(sg_res.findings) == 0
    assert len(sg_res.errors) == 1
    assert sg_res.errors[0].error_code == "PARSE_INVALID_JSON"

    gl_res = parse_gitleaks_json(GITLEAKS_FIXTURES / "valid_single.json")
    assert len(gl_res.findings) == 1
    assert len(gl_res.errors) == 0
    assert gl_res.findings[0].scanner == ScannerType.GITLEAKS


def test_sequential_independence_gitleaks_malformed_then_semgrep_valid() -> None:
    gl_res = parse_gitleaks_json(GITLEAKS_FIXTURES / "malformed.json")
    assert len(gl_res.findings) == 0
    assert len(gl_res.errors) == 1
    assert gl_res.errors[0].error_code == "PARSE_INVALID_JSON"

    sg_res = parse_semgrep_json(SEMGREP_FIXTURES / "valid_single.json")
    assert len(sg_res.findings) == 1
    assert len(sg_res.errors) == 0
    assert sg_res.findings[0].scanner == ScannerType.SEMGREP


# --- 4. Mixed Record Isolation ---


def test_semgrep_mixed_records(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "check_id": "rule.one",
                "path": "app/first.py",
                "start": {"line": 10},
                "extra": {"message": "First finding", "severity": "ERROR"},
            },
            {
                "path": "app/second.py",  # Missing check_id!
                "start": {"line": 20},
                "extra": {"message": "Invalid record"},
            },
            {
                "check_id": "rule.three",
                "path": "app/third.py",
                "start": {"line": 30},
                "extra": {"message": "Third finding", "severity": "WARNING"},
            },
        ]
    }
    f = tmp_path / "semgrep_mixed.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_semgrep_json(f)
    assert len(res.findings) == 2
    assert len(res.errors) == 1

    # Finding 1 & 3 mapped in order
    assert res.findings[0].rule_id == "rule.one"
    assert res.findings[0].file_path == "app/first.py"
    assert res.findings[1].rule_id == "rule.three"
    assert res.findings[1].file_path == "app/third.py"

    # Error references index 1
    err = res.errors[0]
    assert err.error_code == "PARSE_RECORD_MISSING_FIELD"
    assert "result[1]" in err.safe_message
    assert "{" not in err.safe_message


def test_gitleaks_mixed_records(tmp_path: Path) -> None:
    payload = [
        {
            "RuleID": "rule-one",
            "File": "app/first.py",
            "StartLine": 10,
            "Secret": CANARY,
            "Match": f"KEY={CANARY}",
        },
        {
            "RuleID": "rule-two",
            # Missing File!
            "StartLine": 20,
            "Secret": CANARY,
            "Match": f"KEY={CANARY}",
        },
        {
            "RuleID": "rule-three",
            "File": "app/third.py",
            "StartLine": 30,
            "Secret": CANARY,
            "Match": f"KEY={CANARY}",
        },
    ]
    f = tmp_path / "gitleaks_mixed.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_gitleaks_json(f)
    assert len(res.findings) == 2
    assert len(res.errors) == 1

    # Finding 1 & 3 mapped in order
    assert res.findings[0].rule_id == "rule-one"
    assert res.findings[0].file_path == "app/first.py"
    assert res.findings[1].rule_id == "rule-three"
    assert res.findings[1].file_path == "app/third.py"

    # Error references record[1]
    err = res.errors[0]
    assert err.error_code == "PARSE_RECORD_MISSING_FIELD"
    assert "record[1]" in err.safe_message
    assert "CANARY" not in err.safe_message


# --- 5. Metadata Allowlist & Security Test ---


def test_semgrep_metadata_allowlist_drops_unknown_nested_keys(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "check_id": "rule.secure",
                "path": "app/main.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Secure check",
                    "severity": "INFO",
                    "metadata": {
                        "cwe": ["CWE-200"],
                        "confidence": "HIGH",
                        "unknown_sensitive_field": {
                            "token": CANARY,
                        },
                    },
                },
            }
        ]
    }
    f = tmp_path / "semgrep_metadata.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_semgrep_json(f)
    assert len(res.findings) == 1
    f_out = res.findings[0]

    assert "unknown_sensitive_field" not in f_out.metadata
    assert "cwe" in f_out.metadata
    assert "confidence" in f_out.metadata
    assert CANARY not in f_out.model_dump_json()
    assert CANARY not in res.model_dump_json()


def test_gitleaks_metadata_allowlist_drops_unknown_keys(tmp_path: Path) -> None:
    payload = [
        {
            "RuleID": "gitleaks-rule",
            "File": "config/secret.py",
            "StartLine": 5,
            "Description": "Generic Secret",
            "Entropy": 4.8,
            "Secret": CANARY,
            "Match": f"SECRET={CANARY}",
            "Author": f"author_{CANARY}@example.com",
            "Commit": CANARY,
            "unknown_key": {"canary": CANARY},
        }
    ]
    f = tmp_path / "gitleaks_metadata.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_gitleaks_json(f)
    assert len(res.findings) == 1
    f_out = res.findings[0]

    assert set(f_out.metadata.keys()) == {"entropy", "rule_description"}
    assert "unknown_key" not in f_out.metadata
    assert "Author" not in f_out.metadata
    assert "Commit" not in f_out.metadata

    assert CANARY not in f_out.model_dump_json()
    assert CANARY not in res.model_dump_json()
    assert CANARY not in repr(res)
    assert CANARY not in str(res)


# --- 6. SANITIZE Error Linkage ---


def test_gitleaks_sanitize_error_linkage(tmp_path: Path) -> None:
    """When a finding is created with SANITIZE error, error.finding_id matches finding.finding_instance_id."""
    payload = [
        {
            "RuleID": "aws-key",
            "File": "app/settings.py",
            "StartLine": 10,
            "Secret": "SECRET_NOT_IN_MATCH",
            "Match": "KEY=SOMETHING_ELSE",
        }
    ]
    f = tmp_path / "sanitize_linkage.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_gitleaks_json(f)
    assert len(res.findings) == 1
    assert len(res.errors) == 1

    finding = res.findings[0]
    error = res.errors[0]

    assert error.stage == ProcessingStage.SANITIZE
    assert error.error_code == "SANITIZE_SECRET_REDACTION_NO_MATCH"
    assert error.finding_id == finding.finding_instance_id


def test_gitleaks_parse_record_error_finding_id_is_none(tmp_path: Path) -> None:
    """When required fields fail, no finding is created and error.finding_id is None."""
    payload = [
        {
            "RuleID": "aws-key",
            # Missing File!
            "StartLine": 10,
        }
    ]
    f = tmp_path / "parse_error_no_finding_id.json"
    f.write_text(json.dumps(payload), encoding="utf-8")

    res = parse_gitleaks_json(f)
    assert len(res.findings) == 0
    assert len(res.errors) == 1
    assert res.errors[0].finding_id is None


# --- 7. Finding Instance ID Distinction ---


def test_finding_instance_ids_distinct_for_same_rule_file_line() -> None:
    """Identical rule_id, file_path, start_line produce DIFFERENT finding_instance_ids across scanners."""
    rule_id = "common-rule"
    file_path = "app/main.py"
    start_line = 10
    end_line = 10

    sg_payload = {
        "results": [
            {
                "check_id": rule_id,
                "path": file_path,
                "start": {"line": start_line},
                "end": {"line": end_line},
                "extra": {"message": "msg", "severity": "ERROR"},
            }
        ]
    }
    gl_payload = [
        {
            "RuleID": rule_id,
            "File": file_path,
            "StartLine": start_line,
            "EndLine": end_line,
            "Secret": "XYZ_SECRET_KEY_123",
            "Match": "KEY=XYZ_SECRET_KEY_123",
        }
    ]

    p_sg = Path("semgrep_tmp.json")
    p_gl = Path("gitleaks_tmp.json")

    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "read_bytes", return_value=json.dumps(sg_payload).encode("utf-8")
    ):
        res_sg = parse_semgrep_json(p_sg)

    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "read_bytes", return_value=json.dumps(gl_payload).encode("utf-8")
    ):
        res_gl = parse_gitleaks_json(p_gl)

    assert len(res_sg.findings) == 1
    assert len(res_gl.findings) == 1

    sg_id = res_sg.findings[0].finding_instance_id
    gl_id = res_gl.findings[0].finding_instance_id

    assert sg_id != gl_id, "Finding IDs must differ between Semgrep and Gitleaks"


# --- 8. Input Immutability ---


def test_parsers_do_not_mutate_fixture_files() -> None:
    sg_file = SEMGREP_FIXTURES / "valid_single.json"
    gl_file = GITLEAKS_FIXTURES / "valid_single.json"

    sg_bytes_before = sg_file.read_bytes()
    gl_bytes_before = gl_file.read_bytes()

    parse_semgrep_json(sg_file)
    parse_gitleaks_json(gl_file)

    assert sg_file.read_bytes() == sg_bytes_before
    assert gl_file.read_bytes() == gl_bytes_before


# --- 9. PermissionError Handling ---


def test_permission_error_handling_semgrep(tmp_path: Path) -> None:
    p = tmp_path / "locked.json"
    p.touch()

    with patch.object(Path, "read_bytes", side_effect=PermissionError("Permission denied")):
        res = parse_semgrep_json(p)

    assert res.findings == ()
    assert len(res.errors) == 1
    err = res.errors[0]
    assert err.scanner == ScannerType.SEMGREP
    assert err.stage == ProcessingStage.PARSE
    assert err.error_code == "PARSE_FILE_READ_ERROR"
    assert err.retryable is False
    assert "Traceback" not in err.safe_message


def test_permission_error_handling_gitleaks(tmp_path: Path) -> None:
    p = tmp_path / "locked.json"
    p.touch()

    with patch.object(Path, "read_bytes", side_effect=PermissionError("Permission denied")):
        res = parse_gitleaks_json(p)

    assert res.findings == ()
    assert len(res.errors) == 1
    err = res.errors[0]
    assert err.scanner == ScannerType.GITLEAKS
    assert err.stage == ProcessingStage.PARSE
    assert err.error_code == "PARSE_FILE_READ_ERROR"
    assert err.retryable is False
    assert "Traceback" not in err.safe_message
