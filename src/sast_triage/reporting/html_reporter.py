"""Generate a standalone, source-free HTML report for security reviewers."""

from __future__ import annotations

import html
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError
from sast_triage.models import BatchResult, PolicyAction, TriageResult

_KNOWN_SAFE_PLACEHOLDERS = frozenset(
    {
        "<REDACTED_SECRET>",
        "<REDACTED_PRIVATE_KEY_BLOCK>",
        "<REDACTED_GITLEAKS_FINDING_LINE>",
    }
)

_ACTION_PRIORITY = {
    PolicyAction.TRIAGE_ERROR: 0,
    PolicyAction.MANUAL_REVIEW: 1,
    PolicyAction.LIKELY_TP: 2,
    PolicyAction.FP_CANDIDATE: 3,
}
_SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_ACTION_LABELS = {
    PolicyAction.TRIAGE_ERROR: "Lỗi phân loại",
    PolicyAction.MANUAL_REVIEW: "Cần đánh giá thủ công",
    PolicyAction.LIKELY_TP: "Có khả năng là lỗ hổng thật",
    PolicyAction.FP_CANDIDATE: "Ứng viên dương tính giả",
}
_SEVERITY_LABELS = {
    "CRITICAL": "NGHIÊM TRỌNG",
    "HIGH": "CAO",
    "MEDIUM": "TRUNG BÌNH",
    "LOW": "THẤP",
    "UNKNOWN": "CHƯA XÁC ĐỊNH",
}
_RISK_FACTOR_LABELS = {
    "confidence": "Độ tin cậy",
    "exploitability": "Khả năng khai thác",
    "exposure": "Mức độ phơi bày",
    "severity": "Mức độ nghiêm trọng",
}

_EC_INVALID_INPUT = "REPORT_INVALID_INPUT"
_EC_OUTPUT_EXISTS = "REPORT_OUTPUT_EXISTS"
_EC_LEAK_CHECK_FAILED = "REPORT_LEAK_CHECK_FAILED"
_EC_WRITE_ERROR = "REPORT_WRITE_ERROR"


def _escape(value: object) -> str:
    """Escape untrusted report data for an HTML text node."""
    text = "Không có dữ liệu" if value is None else str(value)
    return html.escape(text, quote=True)


def _line_range(start: int, end: int | None) -> str:
    if end is None or end == start:
        return str(start)
    return f"{start}-{end}"


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if isinstance(item, (str, int, float, bool)))


def _list(items: Iterable[object], *, empty: str) -> str:
    values = tuple(items)
    if not values:
        return f'<p class="muted">{_escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{_escape(item)}</li>" for item in values) + "</ul>"


def _row(label: str, value: object) -> str:
    return f"<tr><th>{_escape(label)}</th><td>{_escape(value)}</td></tr>"


def _risk_value(metadata: dict[str, Any]) -> str:
    score = metadata.get("risk_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return f"{score:.1f}/5.0"
    return "Chưa tính"


def _risk_factors(metadata: dict[str, Any]) -> tuple[str, ...]:
    factors = metadata.get("risk_factors")
    if not isinstance(factors, dict):
        return ()
    return tuple(
        f"{_RISK_FACTOR_LABELS.get(str(key), str(key))}: {value}"
        for key, value in sorted(factors.items())
    )


def _trace(metadata: dict[str, Any]) -> tuple[str, ...]:
    trace = _string_list(metadata.get("trace"))
    if trace:
        translated: list[str] = []
        for step in trace:
            prefix, separator, value = step.partition(":")
            label = {
                "source": "Nguồn",
                "flow": "Luồng",
                "guard": "Kiểm soát",
                "control": "Kiểm soát",
                "sink": "Điểm nguy hiểm",
            }.get(prefix.strip().lower())
            translated.append(f"{label}: {value}" if label and separator else step)
        return tuple(translated)
    source = metadata.get("source_kind")
    guards = _string_list(metadata.get("guards"))
    sink = metadata.get("sink_kind")
    steps: list[str] = []
    if source is not None:
        steps.append(f"Nguồn: {source}")
    steps.extend(f"Kiểm soát: {guard}" for guard in guards)
    if sink is not None:
        steps.append(f"Điểm nguy hiểm: {sink}")
    return tuple(steps)


def _joern_summary_trace(context_summary: str | None) -> tuple[str, ...]:
    """Project the stable, source-free Joern context summary into display steps."""
    if context_summary is None or not context_summary.startswith("Joern CPG evidence "):
        return ()
    fields: dict[str, str] = {}
    for part in context_summary.split("; "):
        for prefix, key in (
            ("source ", "source"),
            ("sink ", "sink"),
            ("đường source–sink ", "path"),
            ("control ", "control"),
        ):
            if part.startswith(prefix):
                fields[key] = part.removeprefix(prefix).rstrip(".")
                break

    steps: list[str] = []
    source = fields.get("source")
    if source and source not in {"chưa xác định", "không áp dụng"}:
        steps.append(f"Nguồn: {source}")
    path = fields.get("path")
    if path and path not in {
        "chưa có đường đi đầy đủ",
        "không yêu cầu cho cơ chế này",
    }:
        for location in (item.strip() for item in path.split("→")):
            if location and location not in {source, fields.get("sink")}:
                steps.append(f"Luồng: {location}")
    control = fields.get("control")
    if control and control != "không tìm thấy":
        steps.extend(
            f"Kiểm soát: {item.strip()}"
            for item in control.split(",")
            if item.strip()
        )
    sink = fields.get("sink")
    if sink and sink != "chưa xác định":
        steps.append(f"Điểm nguy hiểm: {sink}")
    return tuple(steps)


def _trace_html(
    metadata: dict[str, Any],
    backend: str,
    context_summary: str | None,
) -> str:
    steps = _trace(metadata)
    if not steps and backend == "joern":
        steps = _joern_summary_trace(context_summary)
    if not steps:
        note = (
            "Chưa có đường đi source-to-sink được xuất cho phát hiện này. "
            f"Backend phân tích: {backend}."
        )
        return f'<p class="muted">{_escape(note)}</p>'
    cards = []
    for index, step in enumerate(steps, start=1):
        kind = "flow-step"
        lowered = step.lower()
        if "source" in lowered or "nguồn" in lowered:
            kind += " source"
        elif "sink" in lowered or "điểm nguy hiểm" in lowered:
            kind += " sink"
        elif "guard" in lowered or "control" in lowered or "kiểm soát" in lowered:
            kind += " guard"
        cards.append(
            f'<div class="{kind}"><span>{index}</span><strong>{_escape(step)}</strong></div>'
        )
    return '<div class="flow">' + '<div class="arrow">&rarr;</div>'.join(cards) + "</div>"


def _finding_html(index: int, result: TriageResult, backend: str) -> str:
    finding = result.finding
    policy = result.policy_decision
    decision = result.triage_decision
    metadata = finding.metadata
    severity = finding.severity.value
    labels = [finding.scanner.value, finding.finding_type.value, finding.rule_id]
    logic_class = metadata.get("logic_class")
    if logic_class is not None:
        labels.append(str(logic_class))

    summary = (
        decision.summary
        if decision is not None
        else "Provider không trả về quyết định hợp lệ; phát hiện này cần được đánh giá thủ công."
    )
    evidence = () if decision is None else tuple(decision.evidence)
    missing = () if decision is None else tuple(decision.missing_information)
    remediation = metadata.get("remediation")
    if not isinstance(remediation, str) or not remediation.strip():
        remediation = (
            "Kiểm tra toàn bộ luồng dữ liệu, xác nhận ranh giới tin cậy và áp dụng biện "
            "pháp kiểm soát do rule của scanner đề xuất trước khi kiểm thử lại."
        )
    checklist = _string_list(metadata.get("validation_checklist"))
    if not checklist:
        checklist = (
            "Xác nhận nguồn, ranh giới tin cậy, điểm kiểm soát và sink với chuyên gia bảo mật.",
            "Thêm regression test cho hành vi có lỗ hổng và hành vi an toàn mong đợi.",
            "Kiểm thử lại sau khi sửa mà không sử dụng dữ liệu hoặc secret thật.",
        )

    title = finding.rule_name or finding.rule_id
    location = f"{finding.file_path}:{_line_range(finding.start_line, finding.end_line)}"
    description = (
        f"{finding.scanner.value} phát hiện dấu hiệu liên quan đến rule “{title}” tại "
        f"{location}. Cần xác minh dữ liệu đầu vào có thể đi đến thao tác nhạy cảm hay "
        "không, đồng thời kiểm tra các biện pháp kiểm soát trên toàn bộ luồng dữ liệu."
    )
    errors = tuple(
        f"{error.stage.value} / {error.error_code}: {error.safe_message}"
        for error in result.processing_errors
    )
    return f"""
    <article class="finding" id="finding-{index}">
      <div class="finding-heading">
        <div>
          <p class="eyebrow">Phát hiện {index}</p>
          <h2>{_escape(title)}</h2>
        </div>
        <span class="severity severity-{_escape(severity.lower())}">{_escape(_SEVERITY_LABELS[severity])}</span>
      </div>

      <table class="details"><tbody>
        {_row("Trạng thái", _ACTION_LABELS[policy.action])}
        {_row("Điểm rủi ro", _risk_value(metadata))}
        {_row("Mức rủi ro", metadata.get("risk_level", _SEVERITY_LABELS[severity]))}
        {_row("CWE", metadata.get("cwe", "Chưa ánh xạ"))}
        {_row("CVSS", metadata.get("cvss", "Chưa tính"))}
        {_row("Nhãn", ", ".join(labels))}
      </tbody></table>

      <section><h3>Mô tả</h3><p>{_escape(description)}</p>
        <details><summary>Thông báo gốc từ scanner</summary><p>{_escape(finding.message)}</p></details>
        <div class="callout">{_escape(result.context_summary or "Không có tóm tắt ngữ cảnh an toàn.")}</div>
      </section>
      <section><h3>Tác động</h3><p>{_escape(summary)}</p>
        {_list(_risk_factors(metadata), empty="Không có yếu tố rủi ro dạng cấu trúc.")}
      </section>
      <section><h3>Thành phần bị ảnh hưởng</h3>
        <p><code>{_escape(location)}</code></p>
        <p>Thành phần: {_escape(metadata.get("component", "Chưa xác định"))}; điểm vào: {_escape(metadata.get("entrypoint", "Chưa xác định"))}</p>
      </section>
      <section><h3>Bằng chứng Source-to-Sink</h3>
        <p class="provenance">Backend: {_escape(backend)}. Khi backend phân tích xuất được luồng, báo cáo sẽ hiển thị Nguồn &rarr; Kiểm soát &rarr; Điểm nguy hiểm.</p>
        {_trace_html(metadata, backend, result.context_summary)}
        <h4>Bằng chứng đã xác thực</h4>{_list(evidence, empty="Không có thêm bằng chứng đã được LLM xác thực.")}
      </section>
      <section><h3>Tái hiện và xác minh an toàn</h3>
        <p>Chỉ tái hiện trong môi trường kiểm thử được cho phép. Không sử dụng secret thật hoặc payload có tính phá hoại.</p>
        {_list(checklist, empty="Không có danh sách bước xác minh.")}
        <h4>Thông tin còn thiếu</h4>{_list(missing, empty="Không yêu cầu thêm thông tin.")}
      </section>
      <section><h3>Hướng khắc phục đề xuất</h3><p>{_escape(remediation)}</p></section>
      <section><h3>Quyết định chính sách</h3>
        <p><strong>{_escape(_ACTION_LABELS[policy.action])}</strong> — chính sách {_escape(policy.policy_version)}</p>
        {_list(policy.reasons, empty="Không có lý do từ chính sách.")}
      </section>
      <section><h3>Lỗi xử lý</h3>{_list(errors, empty="Phát hiện này không có lỗi xử lý.")}</section>
    </article>
    """


def _render_report(batch_result: BatchResult) -> str:
    metadata = batch_result.run_metadata
    ordered = sorted(
        batch_result.results,
        key=lambda result: (
            _ACTION_PRIORITY[result.policy_decision.action],
            _SEVERITY_PRIORITY[result.finding.severity.value],
            result.finding.finding_instance_id,
        ),
    )
    counts = {action.value: 0 for action in PolicyAction}
    for result in batch_result.results:
        counts[result.policy_decision.action.value] += 1
    findings = "".join(
        _finding_html(index, result, metadata.analysis_backend)
        for index, result in enumerate(ordered, start=1)
    )
    if not findings:
        findings = '<div class="empty">Lần chạy này không tạo ra phát hiện nào.</div>'
    scanner_errors = tuple(
        f"{error.stage.value} / {error.error_code}: {error.safe_message}"
        for error in batch_result.scanner_errors
    )
    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Báo cáo đánh giá bảo mật — {_escape(metadata.repository_name)}</title>
  <style>
    :root {{ --blue:#2474e5; --ink:#1f2937; --muted:#667085; --line:#d9e2ef; --paper:#fff; --bg:#f2f6fb; --critical:#b42318; --high:#d92d20; --medium:#dc6803; --low:#027a48; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--ink); background:var(--bg); font:14px/1.55 Inter,Segoe UI,Arial,sans-serif; }}
    main {{ max-width:1040px; margin:32px auto; padding:0 20px 48px; }}
    .cover,.summary,.finding,.footer {{ background:var(--paper); border:1px solid var(--line); border-radius:10px; box-shadow:0 5px 18px rgba(31,41,55,.06); }}
    .cover {{ padding:48px; border-top:6px solid var(--blue); }}
    .eyebrow {{ margin:0 0 5px; color:var(--blue); font-weight:700; letter-spacing:.08em; text-transform:uppercase; }}
    h1 {{ margin:0; font-size:34px; }} h2 {{ margin:0; font-size:22px; color:#175fb8; }} h3 {{ margin:30px 0 10px; color:var(--blue); font-size:19px; }} h4 {{ margin:18px 0 8px; }}
    .muted,.provenance {{ color:var(--muted); }} .provenance {{ font-size:12px; }}
    .summary {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1px; margin:18px 0; overflow:hidden; background:var(--line); }}
    .metric {{ padding:18px; background:#fff; }} .metric strong {{ display:block; font-size:25px; color:#175fb8; }}
    .finding {{ margin:26px 0; padding:32px 38px; page-break-before:always; }}
    .finding-heading {{ display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }}
    .severity {{ color:#fff; border-radius:999px; padding:5px 11px; font-weight:700; font-size:12px; }}
    .severity-critical {{ background:var(--critical); }} .severity-high {{ background:var(--high); }} .severity-medium {{ background:var(--medium); }} .severity-low {{ background:var(--low); }} .severity-unknown {{ background:#667085; }}
    table {{ width:100%; border-collapse:collapse; margin:18px 0; }} th,td {{ padding:8px 10px; border:1px solid var(--line); text-align:left; vertical-align:top; }} th {{ width:170px; color:#175fb8; background:#edf4ff; }}
    .callout {{ margin:12px 0; padding:13px 15px; border-left:4px solid var(--blue); background:#f5f9ff; }}
    code {{ padding:2px 6px; border-radius:4px; background:#eef2f6; overflow-wrap:anywhere; }}
    .flow {{ display:flex; align-items:stretch; gap:8px; overflow-x:auto; padding:10px 0; }}
    .flow-step {{ min-width:150px; padding:12px; border:1px solid #9cbce6; border-radius:7px; background:#eef6ff; }}
    .flow-step span {{ display:block; color:var(--muted); font-size:11px; }} .flow-step.source {{ border-color:#12b76a; background:#ecfdf3; }} .flow-step.guard {{ border-color:#f79009; background:#fffaeb; }} .flow-step.sink {{ border-color:#f04438; background:#fef3f2; }}
    .arrow {{ align-self:center; color:var(--blue); font-size:20px; }}
    .empty,.footer {{ padding:24px; }} .footer {{ color:var(--muted); margin-top:24px; font-size:12px; }}
    @media(max-width:720px) {{ .summary {{ grid-template-columns:1fr 1fr; }} .cover,.finding {{ padding:24px; }} .flow {{ flex-direction:column; }} .arrow {{ transform:rotate(90deg); }} }}
    @media print {{ body {{ background:#fff; }} main {{ max-width:none; margin:0; padding:0; }} .cover,.summary,.finding,.footer {{ box-shadow:none; }} .finding {{ border:none; padding:20mm 12mm; }} }}
  </style>
</head>
<body><main>
  <header class="cover">
    <p class="eyebrow">SAST Triage Platform</p>
    <h1>Báo cáo đánh giá bảo mật</h1>
    <p>Repository: <strong>{_escape(metadata.repository_name)}</strong></p>
    <p class="muted">Lần chạy {_escape(metadata.run_id)} · {_escape(metadata.completed_at.isoformat())} · Backend phân tích: {_escape(metadata.analysis_backend)}</p>
  </header>
  <section class="summary" aria-label="Tóm tắt kết quả">
    <div class="metric"><strong>{len(batch_result.results)}</strong>Tổng số phát hiện</div>
    <div class="metric"><strong>{counts[PolicyAction.LIKELY_TP.value]}</strong>Có khả năng là lỗ hổng thật</div>
    <div class="metric"><strong>{counts[PolicyAction.MANUAL_REVIEW.value]}</strong>Cần đánh giá thủ công</div>
    <div class="metric"><strong>{counts[PolicyAction.TRIAGE_ERROR.value]}</strong>Lỗi phân loại</div>
  </section>
  <section aria-labelledby="details-heading"><p class="eyebrow">Chi tiết lỗ hổng được phát hiện</p><h2 id="details-heading">Các phát hiện</h2>{findings}</section>
  <section class="footer"><strong>Lỗi scanner</strong>{_list(scanner_errors, empty="Không có lỗi scanner.")}
    <p>Báo cáo không chứa mã nguồn thô, prompt thô, phản hồi thô từ model, traceback hoặc đường dẫn tuyệt đối của repository. Không phát hiện nào bị tự động loại bỏ.</p>
  </section>
</main></body></html>
"""


def _validate_input(
    batch_result: BatchResult,
    output_path: Path,
    forbidden_values: tuple[str, ...],
    overwrite: bool,
) -> None:
    if not isinstance(batch_result, BatchResult) or not isinstance(output_path, Path):
        raise SastTriageError("Invalid HTML report input.", error_code=_EC_INVALID_INPUT)
    if output_path.is_dir() or not output_path.parent.is_dir():
        raise SastTriageError("Invalid HTML report path.", error_code=_EC_INVALID_INPUT)
    if not overwrite and output_path.exists():
        raise SastTriageError("HTML report already exists.", error_code=_EC_OUTPUT_EXISTS)
    for value in forbidden_values:
        if not isinstance(value, str) or not value.strip() or value in _KNOWN_SAFE_PLACEHOLDERS:
            raise SastTriageError("Invalid forbidden report value.", error_code=_EC_INVALID_INPUT)


def write_html_report(
    batch_result: BatchResult,
    output_path: Path,
    *,
    forbidden_values: tuple[str, ...] = (),
    overwrite: bool = True,
) -> Path:
    """Write a standalone UTF-8 HTML security report using an atomic replace."""
    _validate_input(batch_result, output_path, forbidden_values, overwrite)
    report = _render_report(batch_result)
    for value in set(forbidden_values):
        if value in report or html.escape(value, quote=True) in report:
            raise SastTriageError(
                "HTML report contains a forbidden value.",
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
            temporary_file.write(report)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    except OSError:
        raise SastTriageError(
            "Could not write the HTML report.", error_code=_EC_WRITE_ERROR
        ) from None
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
    return output_path.resolve()
