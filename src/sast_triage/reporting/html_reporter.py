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

_EC_INVALID_INPUT = "REPORT_INVALID_INPUT"
_EC_OUTPUT_EXISTS = "REPORT_OUTPUT_EXISTS"
_EC_LEAK_CHECK_FAILED = "REPORT_LEAK_CHECK_FAILED"
_EC_WRITE_ERROR = "REPORT_WRITE_ERROR"


def _escape(value: object) -> str:
    """Escape untrusted report data for an HTML text node."""
    text = "Not available" if value is None else str(value)
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
    return "Not calculated"


def _risk_factors(metadata: dict[str, Any]) -> tuple[str, ...]:
    factors = metadata.get("risk_factors")
    if not isinstance(factors, dict):
        return ()
    return tuple(f"{key}: {value}" for key, value in sorted(factors.items()))


def _trace(metadata: dict[str, Any]) -> tuple[str, ...]:
    trace = _string_list(metadata.get("trace"))
    if trace:
        return trace
    source = metadata.get("source_kind")
    guards = _string_list(metadata.get("guards"))
    sink = metadata.get("sink_kind")
    steps: list[str] = []
    if source is not None:
        steps.append(f"Source: {source}")
    steps.extend(f"Guard: {guard}" for guard in guards)
    if sink is not None:
        steps.append(f"Sink: {sink}")
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
    if source and source != "chưa xác định":
        steps.append(f"Source: {source}")
    path = fields.get("path")
    if path and path != "chưa có đường đi đầy đủ":
        for location in (item.strip() for item in path.split("→")):
            if location and location not in {source, fields.get("sink")}:
                steps.append(f"Flow: {location}")
    control = fields.get("control")
    if control and control != "không tìm thấy":
        steps.extend(f"Control: {item.strip()}" for item in control.split(",") if item.strip())
    sink = fields.get("sink")
    if sink and sink != "chưa xác định":
        steps.append(f"Sink: {sink}")
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
            "No source-to-sink path was exported for this finding. "
            f"Analysis backend: {backend}."
        )
        return f'<p class="muted">{_escape(note)}</p>'
    cards = []
    for index, step in enumerate(steps, start=1):
        kind = "flow-step"
        lowered = step.lower()
        if "source" in lowered:
            kind += " source"
        elif "sink" in lowered:
            kind += " sink"
        elif "guard" in lowered or "control" in lowered:
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
        else "The provider did not return a valid decision; this finding requires review."
    )
    evidence = () if decision is None else tuple(decision.evidence)
    missing = () if decision is None else tuple(decision.missing_information)
    remediation = metadata.get("remediation")
    if not isinstance(remediation, str) or not remediation.strip():
        remediation = (
            "Review the complete data flow, confirm the trust boundary, and apply the "
            "scanner rule's recommended control before retesting."
        )
    checklist = _string_list(metadata.get("validation_checklist"))
    if not checklist:
        checklist = (
            "Confirm the source, trust boundary, guard, and sink with a security reviewer.",
            "Add a regression test for the vulnerable and expected-safe behavior.",
            "Retest after the fix without exposing production data or secrets.",
        )

    title = finding.rule_name or finding.rule_id
    location = f"{finding.file_path}:{_line_range(finding.start_line, finding.end_line)}"
    errors = tuple(
        f"{error.stage.value} / {error.error_code}: {error.safe_message}"
        for error in result.processing_errors
    )
    return f"""
    <article class="finding" id="finding-{index}">
      <div class="finding-heading">
        <div>
          <p class="eyebrow">Finding {index}</p>
          <h2>{_escape(title)}</h2>
        </div>
        <span class="severity severity-{_escape(severity.lower())}">{_escape(severity)}</span>
      </div>

      <table class="details"><tbody>
        {_row("Status", policy.action.value)}
        {_row("Risk score", _risk_value(metadata))}
        {_row("Risk level", metadata.get("risk_level", severity))}
        {_row("CWE", metadata.get("cwe", "Not mapped"))}
        {_row("CVSS", metadata.get("cvss", "Not calculated"))}
        {_row("Labels", ", ".join(labels))}
      </tbody></table>

      <section><h3>Description</h3><p>{_escape(finding.message)}</p>
        <div class="callout">{_escape(result.context_summary or "No safe context summary is available.")}</div>
      </section>
      <section><h3>Impact</h3><p>{_escape(summary)}</p>
        {_list(_risk_factors(metadata), empty="No structured risk factors are available.")}
      </section>
      <section><h3>Affected Components</h3>
        <p><code>{_escape(location)}</code></p>
        <p>Component: {_escape(metadata.get("component", "Not identified"))}; entrypoint: {_escape(metadata.get("entrypoint", "Not identified"))}</p>
      </section>
      <section><h3>Source-to-Sink Evidence</h3>
        <p class="provenance">Backend: {_escape(backend)}. Flow is displayed Source &rarr; Guard/Control &rarr; Sink when exported by the analysis backend.</p>
        {_trace_html(metadata, backend, result.context_summary)}
        <h4>Validated evidence</h4>{_list(evidence, empty="No additional validated LLM evidence is available.")}
      </section>
      <section><h3>Safe Reproduction and Validation</h3>
        <p>Reproduce only in an authorized test environment. Do not use production secrets or destructive payloads.</p>
        {_list(checklist, empty="No validation checklist is available.")}
        <h4>Information still required</h4>{_list(missing, empty="No additional information was requested.")}
      </section>
      <section><h3>Suggested Fix</h3><p>{_escape(remediation)}</p></section>
      <section><h3>Policy Decision</h3>
        <p><strong>{_escape(policy.action.value)}</strong> — policy {_escape(policy.policy_version)}</p>
        {_list(policy.reasons, empty="No policy reason is available.")}
      </section>
      <section><h3>Processing Errors</h3>{_list(errors, empty="No processing errors for this finding.")}</section>
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
        findings = '<div class="empty">No findings were produced for this run.</div>'
    scanner_errors = tuple(
        f"{error.stage.value} / {error.error_code}: {error.safe_message}"
        for error in batch_result.scanner_errors
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Security Assessment Report — {_escape(metadata.repository_name)}</title>
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
    <h1>Security Assessment Report</h1>
    <p>Repository: <strong>{_escape(metadata.repository_name)}</strong></p>
    <p class="muted">Run {_escape(metadata.run_id)} · {_escape(metadata.completed_at.isoformat())} · Analysis backend: {_escape(metadata.analysis_backend)}</p>
  </header>
  <section class="summary" aria-label="Executive summary">
    <div class="metric"><strong>{len(batch_result.results)}</strong>Total findings</div>
    <div class="metric"><strong>{counts[PolicyAction.LIKELY_TP.value]}</strong>Likely true positives</div>
    <div class="metric"><strong>{counts[PolicyAction.MANUAL_REVIEW.value]}</strong>Manual review</div>
    <div class="metric"><strong>{counts[PolicyAction.TRIAGE_ERROR.value]}</strong>Triage errors</div>
  </section>
  <section aria-labelledby="details-heading"><p class="eyebrow">Details of Vulnerabilities Found</p><h2 id="details-heading">Findings</h2>{findings}</section>
  <section class="footer"><strong>Scanner errors</strong>{_list(scanner_errors, empty="No scanner errors.")}
    <p>This report contains no raw source, raw prompts, raw model responses, tracebacks, or absolute repository paths. Findings are never automatically discarded.</p>
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
