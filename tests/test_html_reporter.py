"""Tests for the standalone, source-free HTML security report."""

from datetime import UTC, datetime
from pathlib import Path

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
    RunMetadata,
    ScannerType,
    Severity,
    TriageDecision,
    TriageResult,
)
from sast_triage.reporting.html_reporter import write_html_report

NOW = datetime(2025, 1, 1, tzinfo=UTC)


def _batch(*, injected: str = "") -> BatchResult:
    finding = NormalizedFinding(
        finding_instance_id="logic-1",
        scanner=ScannerType.MODULE2,
        finding_type=FindingType.SAST,
        rule_id="module2.logic.mass-assignment",
        rule_name="Mass assignment candidate",
        file_path="app/routes.py",
        start_line=20,
        end_line=22,
        severity=Severity.HIGH,
        message=f"Untrusted request fields reach a model update.{injected}",
        metadata={
            "logic_class": "mass_assignment",
            "component": "app",
            "entrypoint": "update_profile",
            "source_kind": "request.json",
            "sink_kind": "model.update",
            "guards": ["field_allowlist"],
            "trace": [
                "source:request.json@20",
                "guard:field_allowlist@21",
                "sink:model.update@22",
            ],
            "cwe": "CWE-915",
            "risk_score": 4.2,
            "risk_level": "CRITICAL",
            "risk_factors": {"exposure": 0.9, "severity": 0.9},
            "remediation": "Allowlist writable fields before updating the model.",
            "validation_checklist": ["Reject an unauthorized is_admin field."],
        },
    )
    decision = TriageDecision(
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Unauthorized attributes may be modified.",
        evidence=["A bounded source-to-sink flow was identified."],
        missing_information=[],
        assumptions=[],
        model_version="model-v1",
        prompt_version="prompt-v13",
    )
    result = TriageResult(
        finding=finding,
        context_summary="Safe context summary.",
        triage_decision=decision,
        policy_decision=PolicyDecision(
            action=PolicyAction.LIKELY_TP,
            reasons=["Validated evidence supports likely true positive."],
            policy_version="policy-v1",
            escalated=False,
        ),
        processed_at=NOW,
    )
    metadata = RunMetadata(
        run_id="run-1",
        repository_name="sample-repo",
        repository_identifier="org/sample-repo",
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
        scanners_attempted=[ScannerType.MODULE2],
        scanners_succeeded=[ScannerType.MODULE2],
        analysis_backend="joern",
        analysis_backend_version="4.0.600",
        cpg_build_status="complete",
        policy_version="policy-v1",
        triage_provider="fake",
        tool_version="tool-v1",
        cli_mode="scan-and-triage",
        started_at=NOW,
        completed_at=NOW,
        total_findings_parsed=1,
        findings_triaged_ok=1,
    )
    return BatchResult(run_metadata=metadata, results=[result])


def test_html_report_contains_security_sections_and_source_to_sink_trace(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.html"

    write_html_report(_batch(), output)
    report = output.read_text(encoding="utf-8")

    assert report.startswith("<!doctype html>")
    assert '<html lang="vi">' in report
    for section in (
        "Chi tiết lỗ hổng được phát hiện",
        "Mô tả",
        "Tác động",
        "Thành phần bị ảnh hưởng",
        "Bằng chứng Source-to-Sink",
        "Tái hiện và xác minh an toàn",
        "Hướng khắc phục đề xuất",
        "Thông báo gốc từ scanner",
    ):
        assert section in report
    assert "CWE-915" in report
    assert "4.2/5.0" in report
    assert "Nguồn: request.json@20" in report
    assert "Kiểm soát: field_allowlist@21" in report
    assert "Điểm nguy hiểm: model.update@22" in report
    assert "Backend: joern" in report


def test_html_report_escapes_untrusted_values(tmp_path: Path) -> None:
    output = tmp_path / "report.html"

    write_html_report(_batch(injected='<script>alert("x")</script>'), output)
    report = output.read_text(encoding="utf-8")

    assert '<script>alert("x")</script>' not in report
    assert "&lt;script&gt;alert(&quot;" in report


def test_html_report_uses_source_free_joern_summary_when_metadata_has_no_trace(
    tmp_path: Path,
) -> None:
    batch = _batch()
    original = batch.results[0]
    finding = original.finding.model_copy(update={"metadata": {}})
    result = original.model_copy(
        update={
            "finding": finding,
            "context_summary": (
                "Joern CPG evidence complete; source api/input.py:5; "
                "sink db/query.py:30; đường source–sink api/input.py:5 → "
                "service/user.py:18 → db/query.py:30; control require_user; "
                "Agent dừng vì EVIDENCE_SUFFICIENT."
            ),
        }
    )
    output = tmp_path / "report.html"

    write_html_report(batch.model_copy(update={"results": [result]}), output)
    report = output.read_text(encoding="utf-8")

    assert "Nguồn: api/input.py:5" in report
    assert "Luồng: service/user.py:18" in report
    assert "Kiểm soát: require_user" in report
    assert "Điểm nguy hiểm: db/query.py:30" in report


def test_html_report_renders_all_detailed_cross_file_paths(tmp_path: Path) -> None:
    batch = _batch()
    result = batch.results[0].model_copy(
        update={
            "evidence_details": {
                "paths": [
                    {
                        "path_type": "cross_file",
                        "files": ["api/routes.py", "db/query.py"],
                        "steps": [
                            {
                                "order": 1,
                                "kind": "source",
                                "symbol": "user_id",
                                "file_path": "api/routes.py",
                                "line": 8,
                            },
                            {
                                "order": 2,
                                "kind": "sink",
                                "symbol": "execute",
                                "file_path": "db/query.py",
                                "line": 44,
                            },
                        ],
                    },
                    {
                        "path_type": "cross_file",
                        "files": ["api/routes.py", "shared/input.py", "db/query.py"],
                        "steps": [
                            {
                                "order": 1,
                                "kind": "source",
                                "symbol": "user_id",
                                "file_path": "api/routes.py",
                                "line": 8,
                            },
                            {
                                "order": 2,
                                "kind": "flow",
                                "symbol": "normalize",
                                "file_path": "shared/input.py",
                                "line": 13,
                            },
                            {
                                "order": 3,
                                "kind": "sink",
                                "symbol": "execute",
                                "file_path": "db/query.py",
                                "line": 44,
                            },
                        ],
                    },
                ],
                "callers": [
                    {"symbol": "route", "file_path": "api/routes.py", "line": 7}
                ],
                "completeness": {
                    "status": "complete",
                    "limitations": [],
                    "missing_information": [],
                },
            }
        }
    )
    output = tmp_path / "report.html"

    write_html_report(batch.model_copy(update={"results": [result]}), output)
    report = output.read_text(encoding="utf-8")

    assert "Đường dữ liệu 1" in report
    assert "Đường dữ liệu 2" in report
    assert "shared/input.py:13" in report
    assert "Call chain / entrypoint" in report


def test_html_report_fails_closed_on_forbidden_value(tmp_path: Path) -> None:
    canary = "HTML_REPORT_SECRET_CANARY"
    output = tmp_path / "report.html"

    with pytest.raises(SastTriageError) as raised:
        write_html_report(
            _batch(injected=canary),
            output,
            forbidden_values=(canary,),
        )

    assert raised.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert canary not in str(raised.value)
    assert not output.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_html_report_respects_overwrite_false(tmp_path: Path) -> None:
    output = tmp_path / "report.html"
    output.write_text("old", encoding="utf-8")

    with pytest.raises(SastTriageError) as raised:
        write_html_report(_batch(), output, overwrite=False)

    assert raised.value.error_code == "REPORT_OUTPUT_EXISTS"
    assert output.read_text(encoding="utf-8") == "old"
