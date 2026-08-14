"""Sinh báo cáo Markdown tiếng Việt an toàn dành cho security reviewer."""

import os
import tempfile
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError
from sast_triage.models import BatchResult, PolicyAction

_KNOWN_SAFE_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "<REDACTED_SECRET>",
        "<REDACTED_PRIVATE_KEY_BLOCK>",
        "<REDACTED_GITLEAKS_FINDING_LINE>",
    }
)

_MARKDOWN_ESCAPABLE: frozenset[str] = frozenset(r"\`*_{}[]()#+-.!|>~=:/")

_EC_INVALID_INPUT = "REPORT_INVALID_INPUT"
_EC_OUTPUT_EXISTS = "REPORT_OUTPUT_EXISTS"
_EC_LEAK_CHECK_FAILED = "REPORT_LEAK_CHECK_FAILED"
_EC_WRITE_ERROR = "REPORT_WRITE_ERROR"

_ACTION_LABELS: dict[str, str] = {
    "TRIAGE_ERROR": "Lỗi xử lý triage — cần kiểm tra hệ thống",
    "MANUAL_REVIEW": "Cần chuyên gia review thủ công",
    "LIKELY_TP": "Có khả năng là lỗ hổng thật",
    "FP_CANDIDATE": "Ứng viên false positive — không tự động đóng",
}

_VERDICT_LABELS: dict[str, str] = {
    "LIKELY_TP": "LLM đánh giá có khả năng là true positive",
    "LIKELY_FP": "LLM đánh giá có khả năng là false positive",
    "NEEDS_REVIEW": "LLM chưa đủ bằng chứng để kết luận",
}

_CONFIDENCE_LABELS: dict[str, str] = {
    "HIGH": "Cao",
    "MEDIUM": "Trung bình",
    "LOW": "Thấp",
}

_STAGE_LABELS: dict[str, str] = {
    "PARSE": "Đọc và chuẩn hóa artifact",
    "CONTEXT": "Trích xuất ngữ cảnh",
    "SANITIZE": "Làm sạch dữ liệu",
    "TRIAGE": "Phân tích bằng LLM",
    "POLICY": "Áp dụng chính sách",
    "REPORT": "Sinh báo cáo",
    "BINDING": "Xác minh repository–artifact",
}

_POLICY_TEXT_VI: dict[str, str] = {
    "LLM provider failure occurred during triage stage.": (
        "Provider LLM gặp lỗi trong giai đoạn triage."
    ),
    "Scanner artifact repository binding is not fully verified.": (
        "Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ."
    ),
    "Artifact binding is unverified or partial.": (
        "Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần."
    ),
    "Source code context is unavailable for this finding.": (
        "Không có ngữ cảnh mã nguồn khả dụng cho finding này."
    ),
    "Model verdict was produced on unavailable context.": (
        "LLM đã đưa ra verdict khi không có ngữ cảnh khả dụng."
    ),
    "Sanitization stage errors require manual review.": (
        "Lỗi trong giai đoạn làm sạch dữ liệu bắt buộc phải review thủ công."
    ),
    "Model verdict was produced with context sanitization errors.": (
        "LLM đã đưa ra verdict trong khi ngữ cảnh có lỗi làm sạch dữ liệu."
    ),
    "Context evidence is incomplete after bounded expansion.": (
        "Bằng chứng ngữ cảnh vẫn chưa đầy đủ sau khi mở rộng trong giới hạn an toàn."
    ),
    "Model verdict was produced without complete source-to-sink evidence.": (
        "LLM đã đưa ra verdict khi bằng chứng từ nguồn đến điểm sử dụng nguy hiểm chưa đầy đủ."
    ),
    "LLM provider requested manual review.": "LLM yêu cầu chuyên gia review thủ công.",
    "Model verdict is LIKELY_TP with HIGH confidence.": (
        "LLM đánh giá LIKELY_TP với độ tin cậy HIGH."
    ),
    "Model verdict is LIKELY_TP but confidence is not HIGH.": (
        "LLM đánh giá LIKELY_TP nhưng độ tin cậy chưa đạt HIGH."
    ),
    "Model verdict is LIKELY_FP but confidence is not HIGH.": (
        "LLM đánh giá LIKELY_FP nhưng độ tin cậy chưa đạt HIGH."
    ),
    "Truncated or sanitized context prevents automatic FP candidate classification.": (
        "Ngữ cảnh bị cắt bớt hoặc có vấn đề làm sạch nên không được phân loại thành ứng viên FP."
    ),
    "Context is truncated or has sanitization issues; FP candidate status is blocked.": (
        "Ngữ cảnh bị cắt bớt hoặc có vấn đề làm sạch; trạng thái ứng viên FP đã bị chặn."
    ),
    "High-severity Semgrep findings cannot become FP candidates.": (
        "Finding Semgrep severity cao không được trở thành ứng viên FP."
    ),
    "Semgrep finding classified as FP_CANDIDATE.": (
        "Finding Semgrep được phân loại là ứng viên FP."
    ),
    "Gitleaks finding in test, fixture, or example path classified as FP_CANDIDATE.": (
        "Finding Gitleaks trong đường dẫn test, fixture hoặc example được phân loại là ứng viên FP."
    ),
    "Gitleaks FP candidates are restricted to test, fixture, or example paths.": (
        "Ứng viên FP của Gitleaks chỉ được phép trong đường dẫn test, fixture hoặc example."
    ),
}

_REVIEW_GUIDANCE: dict[PolicyAction, tuple[str, ...]] = {
    PolicyAction.TRIAGE_ERROR: (
        "Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding.",
        "Không được bỏ finding; chuyển sang review thủ công nếu không thể chạy lại triage.",
    ),
    PolicyAction.MANUAL_REVIEW: (
        "Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu.",
        "Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP.",
        "Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review.",
    ),
    PolicyAction.LIKELY_TP: (
        "Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard/sanitizer liên quan.",
        "Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục.",
    ),
    PolicyAction.FP_CANDIDATE: (
        "Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm.",
        "Không đóng finding chỉ dựa trên verdict của LLM; cần reviewer xác nhận.",
    ),
}

_ACTION_PRIORITY: dict[PolicyAction, int] = {
    PolicyAction.TRIAGE_ERROR: 0,
    PolicyAction.MANUAL_REVIEW: 1,
    PolicyAction.LIKELY_TP: 2,
    PolicyAction.FP_CANDIDATE: 3,
}

_SEVERITY_PRIORITY: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}


def _safe_text(value: object) -> str:
    """Đưa dữ liệu không tin cậy về một dòng Markdown trung tính."""
    text = "null" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return "".join(
        f"\\{character}" if character in _MARKDOWN_ESCAPABLE else character
        for character in text
    )


def _safe_values(values: list[str] | None, *, empty: str = "Không có") -> str:
    """Hiển thị danh sách chuỗi không tin cậy trên một dòng an toàn."""
    if not values:
        return empty
    return "; ".join(_safe_text(value) for value in values)


def _safe_mapping(values: dict[str, Any] | None) -> str:
    """Hiển thị mapping nhỏ theo thứ tự ổn định mà không tạo Markdown mới."""
    if not values:
        return "Không có"
    return "; ".join(
        f"{_safe_text(key)}={_safe_text(value)}" for key, value in sorted(values.items())
    )


def _line_range(start_line: int, end_line: int | None) -> str:
    """Hiển thị khoảng dòng gọn, không tạo hậu tố ``None``."""
    if end_line is None or end_line == start_line:
        return str(start_line)
    return f"{start_line}–{end_line}"


def _rule_text(rule_id: str, rule_name: str | None) -> str:
    """Ghép rule ID và tên rule khi tên tồn tại."""
    if rule_name is None or not rule_name.strip():
        return rule_id
    return f"{rule_id} — {rule_name}"


def _yes_no(value: bool) -> str:
    """Đổi boolean thành câu trả lời tiếng Việt dễ đọc."""
    return "Có" if value else "Không"


def _translated_policy_text(value: str | None) -> str:
    """Dịch các thông báo policy đã biết; giữ an toàn thông báo động chưa biết."""
    if value is None:
        return "Không có"
    translated = _POLICY_TEXT_VI.get(value)
    if translated is not None:
        return _safe_text(translated)
    if value.startswith("Model confidence '") and "TP classification" in value:
        return _safe_text("Độ tin cậy của LLM chưa đủ để tự động phân loại TP.")
    if value.startswith("Model confidence '") and "FP candidate" in value:
        return _safe_text("Độ tin cậy của LLM chưa đủ để trở thành ứng viên FP.")
    if value.startswith("Severity '"):
        return _safe_text("Severity quá cao để tự động phân loại thành ứng viên FP.")
    if value.startswith("Path category '"):
        return _safe_text("Nhóm đường dẫn không đủ điều kiện trở thành ứng viên FP.")
    return _safe_text(value)


def _action_text(action: PolicyAction) -> str:
    """Trả nhãn action gồm mã ổn định và giải thích tiếng Việt."""
    return f"{action.value} — {_ACTION_LABELS[action.value]}"


def _verdict_text(decision: Any) -> str:
    """Trả nhãn verdict tiếng Việt hoặc trạng thái không có quyết định."""
    if decision is None:
        return "Không có quyết định LLM hợp lệ"
    value = decision.model_verdict.value
    return f"{value} — {_VERDICT_LABELS[value]}"


def _confidence_text(decision: Any) -> str:
    """Trả mức confidence kèm diễn giải tiếng Việt."""
    if decision is None:
        return "Không có"
    value = decision.model_confidence.value
    return f"{value} — {_CONFIDENCE_LABELS[value]}"


def _project_run_metadata(batch_result: BatchResult) -> dict[str, Any]:
    """Chiếu run metadata qua allowlist phục vụ báo cáo công khai."""
    metadata = batch_result.run_metadata
    return {
        "run_id": metadata.run_id,
        "repository_name": metadata.repository_name,
        "repository_identifier": metadata.repository_identifier,
        "commit_sha": metadata.commit_sha,
        "working_tree_state": metadata.working_tree_state,
        "artifact_repository_match": metadata.artifact_repository_match.value,
        "scanners_attempted": [scanner.value for scanner in metadata.scanners_attempted],
        "scanners_succeeded": [scanner.value for scanner in metadata.scanners_succeeded],
        "scanner_versions": metadata.scanner_versions,
        "scanner_config_ids": metadata.scanner_config_ids,
        "input_artifact_hashes": metadata.input_artifact_hashes,
        "analysis_backend": metadata.analysis_backend,
        "analysis_backend_version": metadata.analysis_backend_version,
        "analysis_config_id": metadata.analysis_config_id,
        "cpg_build_status": metadata.cpg_build_status,
        "cpg_build_seconds": metadata.cpg_build_seconds,
        "prompt_version": metadata.prompt_version,
        "model_version": metadata.model_version,
        "policy_version": metadata.policy_version,
        "triage_provider": metadata.triage_provider,
        "tool_version": metadata.tool_version,
        "cli_mode": metadata.cli_mode,
        "started_at": metadata.started_at.isoformat(),
        "completed_at": metadata.completed_at.isoformat(),
        "duration_seconds": max(
            0.0, (metadata.completed_at - metadata.started_at).total_seconds()
        ),
        "total_findings_parsed": metadata.total_findings_parsed,
        "findings_triaged_ok": metadata.findings_triaged_ok,
        "findings_with_errors": metadata.findings_with_errors,
    }


def _render_processing_error(error: Any) -> str:
    """Chỉ hiển thị các trường lỗi đã được xác định là an toàn."""
    scanner = error.scanner.value if error.scanner is not None else None
    stage = error.stage.value
    stage_label = _STAGE_LABELS.get(stage, stage)
    return (
        f"- Giai đoạn: {_safe_text(stage)} — {_safe_text(stage_label)}; "
        f"mã lỗi: {_safe_text(error.error_code)}; "
        f"scanner: {_safe_text(scanner)}; "
        f"finding: {_safe_text(error.finding_id)}; "
        f"có thể thử lại: {_safe_text(error.retryable)}; "
        f"thông báo an toàn: {_safe_text(error.safe_message)}"
    )


def _append_safe_list(lines: list[str], values: list[str], *, empty: str) -> None:
    """Thêm danh sách Markdown an toàn hoặc một thông báo rỗng rõ ràng."""
    if values:
        lines.extend(f"- {_safe_text(value)}" for value in values)
    else:
        lines.append(f"- {_safe_text(empty)}")


def _overall_status(batch_result: BatchResult, action_counts: dict[str, int]) -> str:
    """Tóm tắt trạng thái run theo nguyên tắc fail-closed."""
    if batch_result.scanner_errors or action_counts[PolicyAction.TRIAGE_ERROR.value]:
        return "Có lỗi cần xử lý; không được bỏ qua các finding liên quan."
    if action_counts[PolicyAction.MANUAL_REVIEW.value]:
        return "Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review."
    return "Pipeline hoàn tất; mọi finding vẫn được giữ lại trong báo cáo."


def _render_report(batch_result: BatchResult) -> str:
    """Tạo báo cáo Markdown tiếng Việt đầy đủ từ dữ liệu đã được allowlist."""
    metadata = _project_run_metadata(batch_result)
    action_counts = {action.value: 0 for action in PolicyAction}
    for result in batch_result.results:
        action_counts[result.policy_decision.action.value] += 1

    lines = [
        "# Báo cáo SAST Triage",
        "",
        "> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua",
        "> validation và quyết định policy của hệ thống. Đây không phải response thô hay",
        "> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.",
        "",
        "## 1. Tóm tắt điều hành",
        "",
        f"**Trạng thái:** {_safe_text(_overall_status(batch_result, action_counts))}",
        "",
        "| Chỉ số | Giá trị |",
        "|---|---:|",
        f"| Finding đã parse | {_safe_text(metadata['total_findings_parsed'])} |",
        f"| Triage thành công | {_safe_text(metadata['findings_triaged_ok'])} |",
        f"| Finding có lỗi | {_safe_text(metadata['findings_with_errors'])} |",
        f"| Lỗi scanner | {_safe_text(len(batch_result.scanner_errors))} |",
        f"| Thời gian toàn run (giây) | {_safe_text(metadata['duration_seconds'])} |",
        "",
        "### Phân bố quyết định policy",
        "",
        "| Action | Số lượng | Reviewer cần làm gì |",
        "|---|---:|---|",
    ]
    for action in (
        PolicyAction.TRIAGE_ERROR,
        PolicyAction.MANUAL_REVIEW,
        PolicyAction.LIKELY_TP,
        PolicyAction.FP_CANDIDATE,
    ):
        guidance = _REVIEW_GUIDANCE[action][0]
        lines.append(
            f"| {_safe_text(_action_text(action))} | "
            f"{_safe_text(action_counts[action.value])} | {_safe_text(guidance)} |"
        )

    lines.extend(
        [
            "",
            "## 2. Cấu hình và khả năng tái lập",
            "",
            "| Thuộc tính | Giá trị |",
            "|---|---|",
            f"| Run ID | {_safe_text(metadata['run_id'])} |",
            f"| Repository | {_safe_text(metadata['repository_name'])} |",
            f"| Repository identifier | {_safe_text(metadata['repository_identifier'])} |",
            f"| Commit | {_safe_text(metadata['commit_sha'])} |",
            f"| Trạng thái working tree | {_safe_text(metadata['working_tree_state'])} |",
            f"| Xác minh artifact–repository | {_safe_text(metadata['artifact_repository_match'])} |",
            f"| Provider | {_safe_text(metadata['triage_provider'])} |",
            f"| Model | {_safe_text(metadata['model_version'])} |",
            f"| Prompt version | {_safe_text(metadata['prompt_version'])} |",
            f"| Analysis backend | {_safe_text(metadata['analysis_backend'])} |",
            f"| Backend version | {_safe_text(metadata['analysis_backend_version'])} |",
            f"| Analysis config ID | {_safe_text(metadata['analysis_config_id'])} |",
            f"| Trạng thái CPG | {_safe_text(metadata['cpg_build_status'])} |",
            f"| Thời gian dựng CPG | {_safe_text(metadata['cpg_build_seconds'])} giây |",
            f"| Policy version | {_safe_text(metadata['policy_version'])} |",
            f"| Tool version | {_safe_text(metadata['tool_version'])} |",
            f"| Chế độ CLI | {_safe_text(metadata['cli_mode'])} |",
            f"| Bắt đầu | {_safe_text(metadata['started_at'])} |",
            f"| Kết thúc | {_safe_text(metadata['completed_at'])} |",
            "",
            "### Scanner",
            "",
            f"- Đã chạy: {_safe_values(metadata['scanners_attempted'])}",
            f"- Thành công: {_safe_values(metadata['scanners_succeeded'])}",
            f"- Phiên bản: {_safe_mapping(metadata['scanner_versions'])}",
            f"- Cấu hình: {_safe_mapping(metadata['scanner_config_ids'])}",
            f"- Hash artifact: {_safe_mapping(metadata['input_artifact_hashes'])}",
            "",
            "## 3. Cách đọc verdict và action",
            "",
            "- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.",
            "- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.",
            "- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.",
            "- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.",
            "- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.",
            "",
            "## 4. Hàng đợi review",
            "",
        ]
    )

    ordered_results = sorted(
        batch_result.results,
        key=lambda result: (
            _ACTION_PRIORITY[result.policy_decision.action],
            _SEVERITY_PRIORITY[result.finding.severity.value],
            result.finding.finding_instance_id,
        ),
    )
    if ordered_results:
        lines.extend(
            [
                "| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |",
                "|---:|---|---|---|---|---|---|",
            ]
        )
        for index, result in enumerate(ordered_results, start=1):
            finding = result.finding
            decision = result.triage_decision
            location = f"{finding.file_path}:{_line_range(finding.start_line, finding.end_line)}"
            verdict = _verdict_text(decision)
            confidence = _confidence_text(decision)
            lines.append(
                f"| {index} | {_safe_text(result.policy_decision.action.value)} | "
                f"{_safe_text(finding.severity.value)} | "
                f"{_safe_text(finding.finding_instance_id)} | {_safe_text(finding.rule_id)} | "
                f"{_safe_text(location)} | {_safe_text(verdict)} / {_safe_text(confidence)} |"
            )
    else:
        lines.append("Không có finding nào trong run này.")

    lines.extend(["", "## 5. Chi tiết từng finding"])
    for index, result in enumerate(ordered_results, start=1):
        finding = result.finding
        decision = result.triage_decision
        policy = result.policy_decision
        lines.extend(
            [
                "",
                f"### 5.{index}. {_safe_text(policy.action.value)} — {_safe_text(finding.rule_id)}",
                "",
                f"> **Ưu tiên review:** {_safe_text(_ACTION_LABELS[policy.action.value])}",
                "",
                "#### Thông tin finding",
                "",
                "| Thuộc tính | Giá trị |",
                "|---|---|",
                f"| Finding ID | {_safe_text(finding.finding_instance_id)} |",
                f"| Scanner / loại finding | {_safe_text(finding.scanner.value)} / {_safe_text(finding.finding_type.value)} |",
                f"| Rule | {_safe_text(_rule_text(finding.rule_id, finding.rule_name))} |",
                f"| File | {_safe_text(finding.file_path)} |",
                f"| Dòng | {_safe_text(_line_range(finding.start_line, finding.end_line))} |",
                f"| Severity | {_safe_text(finding.severity.value)} |",
                f"| Metadata an toàn | {_safe_mapping(finding.metadata)} |",
                f"| Thời gian xử lý | {_safe_text(result.processing_duration_ms)} ms |",
                f"| Thời gian provider | {_safe_text(result.provider_duration_ms)} ms |",
                f"| SHA-256 đầu vào triage | {_safe_text(result.triage_input_digest)} |",
                "",
                "**Thông báo của scanner**",
                "",
                f"> {_safe_text(finding.message)}",
                "",
                "**Tóm tắt ngữ cảnh an toàn**",
                "",
                f"> {_safe_text(result.context_summary or 'Không có tóm tắt ngữ cảnh.')}",
                "",
                "#### Phân tích của LLM",
                "",
                f"- **Verdict:** {_safe_text(_verdict_text(decision))}",
                f"- **Confidence:** {_safe_text(_confidence_text(decision))}",
            ]
        )
        if decision is None:
            lines.extend(
                [
                    "- **Kết luận:** Không có quyết định LLM hợp lệ. Xem mục lỗi xử lý bên dưới.",
                    "",
                    "> Ghi chú: Finding vẫn được giữ lại và policy chuyển sang trạng thái an toàn.",
                ]
            )
        else:
            lines.extend(
                [
                    f"- **Model / Prompt:** {_safe_text(decision.model_version)} / {_safe_text(decision.prompt_version)}",
                    "",
                    "**Kết luận ngắn gọn**",
                    "",
                    f"> {_safe_text(decision.summary)}",
                    "",
                    "**Bằng chứng LLM sử dụng**",
                    "",
                ]
            )
            _append_safe_list(
                lines,
                decision.evidence,
                empty="LLM không cung cấp bằng chứng cụ thể.",
            )
            lines.extend(["", "**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**", ""])
            _append_safe_list(
                lines,
                decision.missing_information,
                empty="LLM không ghi nhận thông tin quan trọng còn thiếu.",
            )
            lines.extend(["", "**Giả định LLM đã sử dụng**", ""])
            _append_safe_list(
                lines,
                decision.assumptions,
                empty="LLM không khai báo giả định.",
            )
            lines.extend(
                [
                    "",
                    "> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải",
                    "> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.",
                ]
            )

        lines.extend(
            [
                "",
                "#### Quyết định policy của hệ thống",
                "",
                f"- **Action:** {_safe_text(_action_text(policy.action))}",
                f"- **Policy version:** {_safe_text(policy.policy_version)}",
                f"- **Đã escalated:** {_safe_text(_yes_no(policy.escalated))}",
                f"- **Lý do escalation:** {_translated_policy_text(policy.escalation_reason)}",
                "- **Lý do policy:**",
            ]
        )
        lines.extend(
            f"  - {_translated_policy_text(reason)}" for reason in policy.reasons
        )
        lines.extend(["", "#### Reviewer nên làm gì tiếp theo", ""])
        lines.extend(
            f"- {_safe_text(item)}" for item in _REVIEW_GUIDANCE[policy.action]
        )
        lines.extend(["", "#### Lỗi xử lý", ""])
        if result.processing_errors:
            lines.extend(_render_processing_error(error) for error in result.processing_errors)
        else:
            lines.append("- Không có lỗi xử lý cho finding này.")

    lines.extend(["", "## 6. Lỗi scanner"])
    if batch_result.scanner_errors:
        lines.extend(_render_processing_error(error) for error in batch_result.scanner_errors)
    else:
        lines.append("- Không có lỗi scanner.")
    lines.extend(
        [
            "",
            "## 7. Ghi chú bảo mật và giới hạn",
            "",
            "- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.",
            "- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.",
            "- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.",
            "- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.",
            "",
        ]
    )
    return "\n".join(lines)


def _validate_input(
    batch_result: BatchResult,
    output_path: Path,
    forbidden_values: tuple[str, ...],
    overwrite: bool,
) -> None:
    """Kiểm tra đầu vào báo cáo trước khi chiếu dữ liệu hoặc ghi file."""
    if not isinstance(batch_result, BatchResult) or not isinstance(output_path, Path):
        raise SastTriageError(
            "Đầu vào báo cáo Markdown không hợp lệ.", error_code=_EC_INVALID_INPUT
        )
    if output_path.is_dir() or not output_path.parent.exists() or not output_path.parent.is_dir():
        raise SastTriageError(
            "Đường dẫn báo cáo Markdown không hợp lệ.", error_code=_EC_INVALID_INPUT
        )
    if not overwrite and output_path.exists():
        raise SastTriageError(
            "File báo cáo đã tồn tại và overwrite=False.", error_code=_EC_OUTPUT_EXISTS
        )
    for value in forbidden_values:
        if not isinstance(value, str) or not value.strip():
            raise SastTriageError(
                "forbidden_values chứa giá trị không hợp lệ.",
                error_code=_EC_INVALID_INPUT,
            )
        if value in _KNOWN_SAFE_PLACEHOLDERS:
            raise SastTriageError(
                "forbidden_values chứa placeholder an toàn đã biết.",
                error_code=_EC_INVALID_INPUT,
            )


def write_markdown_report(
    batch_result: BatchResult,
    output_path: Path,
    *,
    forbidden_values: tuple[str, ...] = (),
    overwrite: bool = True,
) -> Path:
    """Ghi báo cáo Markdown UTF-8 an toàn theo cơ chế atomic write."""
    _validate_input(batch_result, output_path, forbidden_values, overwrite)
    markdown = _render_report(batch_result)
    for value in set(forbidden_values):
        if value in markdown or _safe_text(value) in markdown:
            raise SastTriageError(
                "Báo cáo Markdown chứa giá trị bị cấm.",
                error_code=_EC_LEAK_CHECK_FAILED,
            )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(markdown)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    except Exception as exc:
        raise SastTriageError(
            "Không thể ghi báo cáo Markdown.", error_code=_EC_WRITE_ERROR
        ) from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
    return output_path.resolve()
