"""Tests for the safe Markdown reporter."""

import json
from datetime import UTC, datetime
from pathlib import Path
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
from sast_triage.reporting.markdown_reporter import write_markdown_report

NOW = datetime(2025, 1, 1, tzinfo=UTC)


def _finding(identifier: str, scanner: ScannerType, _source_canary: str) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=identifier,
        scanner=scanner,
        finding_type=FindingType.SAST if scanner == ScannerType.SEMGREP else FindingType.SECRET,
        rule_id="rule-id",
        rule_name="rule name",
        file_path="tests/app.py",
        start_line=2,
        end_line=3,
        severity=Severity.HIGH if scanner == ScannerType.SEMGREP else Severity.UNKNOWN,
        message="scanner message",
        metadata={"secret_category": "api_key"} if scanner == ScannerType.GITLEAKS else {},
    )


def _batch(results: list[TriageResult]) -> BatchResult:
    metadata = RunMetadata(
        run_id="run-1",
        repository_name="repo",
        repository_identifier="org/repo",
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
        scanners_attempted=[ScannerType.SEMGREP, ScannerType.GITLEAKS],
        scanners_succeeded=[ScannerType.SEMGREP, ScannerType.GITLEAKS],
        policy_version="policy-v1",
        triage_provider="fake",
        tool_version="tool-v1",
        cli_mode="triage",
        started_at=NOW,
        completed_at=NOW,
        total_findings_parsed=len(results),
        findings_triaged_ok=sum(r.policy_decision.action != PolicyAction.TRIAGE_ERROR for r in results),
        findings_with_errors=sum(bool(r.processing_errors) for r in results),
    )
    return BatchResult(run_metadata=metadata, results=results, scanner_errors=[])


def _result(finding: NormalizedFinding, action: PolicyAction = PolicyAction.MANUAL_REVIEW) -> TriageResult:
    decision = TriageDecision(
        model_verdict=ModelVerdict.NEEDS_REVIEW,
        model_confidence=ModelConfidence.MEDIUM,
        summary="Chưa đủ bằng chứng để xác nhận luồng dữ liệu tới điểm sử dụng nguy hiểm.",
        evidence=["Nguồn: dữ liệu đầu vào chưa xác định.", "Điểm sử dụng: cần kiểm tra trực tiếp."],
        missing_information=["Cần xác minh caller truyền dữ liệu nào vào hàm."],
        assumptions=["Giả định context hiện tại chưa bao phủ caller."],
        model_version="model-v1",
        prompt_version="prompt-v1",
    )
    return TriageResult(
        finding=finding,
        context_summary="safe context summary",
        triage_decision=decision,
        policy_decision=PolicyDecision(
            action=action,
            reasons=["policy reason"],
            policy_version="policy-v1",
            escalated=False,
        ),
        processing_errors=[],
        processed_at=NOW,
        processing_duration_ms=4,
    )


def test_report_contains_required_sections_counts_and_safe_findings(tmp_path: Path) -> None:
    batch = _batch([
        _result(_finding("s-1", ScannerType.SEMGREP, "SEMGREP_SOURCE_CANARY")),
        _result(_finding("g-1", ScannerType.GITLEAKS, "GITLEAKS_SECRET_CANARY"), PolicyAction.FP_CANDIDATE),
    ])
    output = tmp_path / "report.md"

    write_markdown_report(batch, output)
    text = output.read_text(encoding="utf-8")

    for section in (
        "# Báo cáo SAST Triage",
        "## 1. Tóm tắt điều hành",
        "## 2. Cấu hình và khả năng tái lập",
        "## 3. Cách đọc verdict và action",
        "## 4. Hàng đợi review",
        "## 5. Chi tiết từng finding",
        "## 6. Lỗi scanner",
        "## 7. Ghi chú bảo mật và giới hạn",
    ):
        assert section in text
    assert "| LIKELY\\_TP — Có khả năng là lỗ hổng thật | 0 |" in text
    assert "| FP\\_CANDIDATE — Ứng viên false positive — không tự động đóng | 1 |" in text
    assert "| MANUAL\\_REVIEW — Cần chuyên gia review thủ công | 1 |" in text
    assert "| Finding ID | s\\-1 |" in text
    assert "| Finding ID | g\\-1 |" in text
    assert "safe context summary" in text
    assert "#### Phân tích của LLM" in text
    assert "Chưa đủ bằng chứng để xác nhận luồng dữ liệu" in text
    assert "Nguồn\\: dữ liệu đầu vào chưa xác định\\." in text
    assert "Cần xác minh caller truyền dữ liệu nào vào hàm\\." in text
    assert "Giả định context hiện tại chưa bao phủ caller\\." in text
    assert "không phải response thô" in text
    assert "SEMGREP_SOURCE_CANARY" not in text
    assert "GITLEAKS_SECRET_CANARY" not in text


def test_dynamic_values_are_neutralized_and_no_forbidden_fields_render(tmp_path: Path) -> None:
    finding = _finding("id\n# fake", ScannerType.SEMGREP, "source")
    finding = finding.model_copy(update={"message": "# h\n- list [link](https://example.com) <script>x</script> ```code```"})
    batch = _batch([_result(finding)])
    output = tmp_path / "report.md"

    write_markdown_report(batch, output)
    text = output.read_text(encoding="utf-8")

    assert "\n# fake" not in text
    assert "\n- list" not in text
    assert "[link](https://example.com)" not in text
    assert "<script>" not in text
    assert "```code```" not in text
    assert "source" not in text
    assert "snippet" not in text


def test_llm_explanation_is_neutralized_before_rendering(tmp_path: Path) -> None:
    finding = _finding("id", ScannerType.SEMGREP, "source")
    result = _result(finding)
    assert result.triage_decision is not None
    decision = result.triage_decision.model_copy(
        update={
            "summary": "# fake heading\n<script>alert(1)</script>",
            "evidence": ["[fake link](https://example.com)"],
            "missing_information": ["- injected list"],
            "assumptions": ["```injected block```"],
        }
    )
    batch = _batch([result.model_copy(update={"triage_decision": decision})])
    output = tmp_path / "report.md"

    write_markdown_report(batch, output)
    text = output.read_text(encoding="utf-8")

    assert "\n# fake heading" not in text
    assert "<script>" not in text
    assert "[fake link](https://example.com)" not in text
    assert "\n- injected list" not in text
    assert "```injected block```" not in text


def test_forbidden_value_inside_llm_explanation_fails_closed(tmp_path: Path) -> None:
    canary = "LLM_EXPLANATION_CANARY_DO_NOT_LEAK"
    finding = _finding("id", ScannerType.SEMGREP, "source")
    result = _result(finding)
    assert result.triage_decision is not None
    decision = result.triage_decision.model_copy(update={"evidence": [canary]})
    batch = _batch([result.model_copy(update={"triage_decision": decision})])
    output = tmp_path / "report.md"

    with pytest.raises(SastTriageError) as exc_info:
        write_markdown_report(batch, output, forbidden_values=(canary,))

    assert exc_info.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert canary not in str(exc_info.value)
    assert not output.exists()


def test_forbidden_value_fails_closed_without_echo_or_temp_file(tmp_path: Path) -> None:
    canary = "MARKDOWN_REPORT_CANARY_DO_NOT_LEAK"
    finding = _finding("id", ScannerType.SEMGREP, "source")
    batch = _batch([_result(finding)]).model_copy(
        update={"run_metadata": _batch([_result(finding)]).run_metadata.model_copy(update={"repository_name": canary})}
    )
    output = tmp_path / "report.md"

    with pytest.raises(SastTriageError) as exc_info:
        write_markdown_report(batch, output, forbidden_values=(canary,))
    assert exc_info.value.error_code == "REPORT_LEAK_CHECK_FAILED"
    assert canary not in str(exc_info.value)
    assert not output.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_overwrite_and_failure_preserve_destination(tmp_path: Path) -> None:
    batch = _batch([_result(_finding("id", ScannerType.SEMGREP, "source"))])
    output = tmp_path / "report.md"
    output.write_text("old", encoding="utf-8")

    with pytest.raises(SastTriageError) as exc_info:
        write_markdown_report(batch, output, overwrite=False)
    assert exc_info.value.error_code == "REPORT_OUTPUT_EXISTS"
    assert output.read_text(encoding="utf-8") == "old"

    with (
        patch("sast_triage.reporting.markdown_reporter.os.replace", side_effect=OSError("denied")),
        pytest.raises(SastTriageError) as exc_info,
    ):
        write_markdown_report(batch, output)
    assert exc_info.value.error_code == "REPORT_WRITE_ERROR"
    assert output.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob("*.tmp")) == []


def test_empty_report_is_valid_utf8_and_input_is_not_mutated(tmp_path: Path) -> None:
    batch = _batch([])
    before = json.dumps(batch.model_dump(mode="json"), sort_keys=True)
    output = tmp_path / "report.md"

    write_markdown_report(batch, output)
    assert "| Finding đã parse | 0 |" in output.read_text(encoding="utf-8")
    assert output.read_bytes().decode("utf-8").endswith("\n")
    assert json.dumps(batch.model_dump(mode="json"), sort_keys=True) == before


def test_scanner_errors_are_rendered_as_safe_fields(tmp_path: Path) -> None:
    batch = _batch([]).model_copy(
        update={
            "scanner_errors": [
                ProcessingError(
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_INVALID_JSON",
                    safe_message="Scanner artifact could not be parsed.",
                    retryable=False,
                )
            ]
        }
    )
    output = tmp_path / "report.md"

    write_markdown_report(batch, output)
    text = output.read_text(encoding="utf-8")

    assert "## 6. Lỗi scanner" in text
    assert r"PARSE\_INVALID\_JSON" in text
    assert r"Scanner artifact could not be parsed\." in text
