"""Safe Markdown report writer for SAST Triage Platform."""

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

_MARKDOWN_ESCAPABLE: frozenset[str] = frozenset(
    r"\`*_{}[]()#+-.!|>~=:/"
)

_EC_INVALID_INPUT = "REPORT_INVALID_INPUT"
_EC_OUTPUT_EXISTS = "REPORT_OUTPUT_EXISTS"
_EC_LEAK_CHECK_FAILED = "REPORT_LEAK_CHECK_FAILED"
_EC_WRITE_ERROR = "REPORT_WRITE_ERROR"


def _safe_text(value: object) -> str:
    """Render an untrusted value as one neutralized Markdown line."""
    text = "null" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return "".join(
        f"\\{character}" if character in _MARKDOWN_ESCAPABLE else character
        for character in text
    )


def _safe_values(values: list[str] | None) -> str:
    """Render a list of untrusted strings without creating Markdown structure."""
    if not values:
        return "none"
    return "; ".join(_safe_text(value) for value in values)


def _project_run_metadata(batch_result: BatchResult) -> dict[str, Any]:
    """Project run metadata using an explicit allowlist."""
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
        "prompt_version": metadata.prompt_version,
        "model_version": metadata.model_version,
        "policy_version": metadata.policy_version,
        "triage_provider": metadata.triage_provider,
        "tool_version": metadata.tool_version,
        "cli_mode": metadata.cli_mode,
        "started_at": metadata.started_at.isoformat(),
        "completed_at": metadata.completed_at.isoformat(),
        "total_findings_parsed": metadata.total_findings_parsed,
        "findings_triaged_ok": metadata.findings_triaged_ok,
        "findings_with_errors": metadata.findings_with_errors,
    }


def _render_processing_error(error: Any) -> str:
    """Render only safe, structured processing error fields."""
    scanner = error.scanner.value if error.scanner is not None else None
    return (
        f"- stage: {_safe_text(error.stage.value)}; "
        f"code: {_safe_text(error.error_code)}; "
        f"scanner: {_safe_text(scanner)}; "
        f"finding: {_safe_text(error.finding_id)}; "
        f"retryable: {_safe_text(error.retryable)}; "
        f"message: {_safe_text(error.safe_message)}"
    )


def _render_report(batch_result: BatchResult) -> str:
    """Build the complete Markdown report from safe allowlisted values."""
    metadata = _project_run_metadata(batch_result)
    action_counts = {action.value: 0 for action in PolicyAction}
    for result in batch_result.results:
        action_counts[result.policy_decision.action.value] += 1

    lines = [
        "# SAST Triage Report",
        "",
        "## Run summary",
        f"- Run ID: {_safe_text(metadata['run_id'])}",
        f"- Repository: {_safe_text(metadata['repository_name'])}",
        f"- Repository identifier: {_safe_text(metadata['repository_identifier'])}",
        f"- Artifact repository match: {_safe_text(metadata['artifact_repository_match'])}",
        f"- Started: {_safe_text(metadata['started_at'])}",
        f"- Completed: {_safe_text(metadata['completed_at'])}",
        "",
        "## Scanner status",
        f"- Attempted: {_safe_values(metadata['scanners_attempted'])}",
        f"- Succeeded: {_safe_values(metadata['scanners_succeeded'])}",
        "",
        "## Finding totals",
        f"- Parsed: {_safe_text(metadata['total_findings_parsed'])}",
        f"- Triaged successfully: {_safe_text(metadata['findings_triaged_ok'])}",
        f"- With errors: {_safe_text(metadata['findings_with_errors'])}",
        "",
        "## Policy-action counts",
        f"- LIKELY_TP: {_safe_text(action_counts['LIKELY_TP'])}",
        f"- FP_CANDIDATE: {_safe_text(action_counts['FP_CANDIDATE'])}",
        f"- MANUAL_REVIEW: {_safe_text(action_counts['MANUAL_REVIEW'])}",
        f"- TRIAGE_ERROR: {_safe_text(action_counts['TRIAGE_ERROR'])}",
        "",
        "## Findings",
    ]

    for index, result in enumerate(batch_result.results, start=1):
        finding = result.finding
        decision = result.triage_decision
        policy = result.policy_decision
        lines.extend(
            [
                "",
                f"### Finding {_safe_text(index)}",
                f"- Finding ID: {_safe_text(finding.finding_instance_id)}",
                f"- Scanner: {_safe_text(finding.scanner.value)}",
                f"- Finding type: {_safe_text(finding.finding_type.value)}",
                f"- Rule ID: {_safe_text(finding.rule_id)}",
                f"- Rule name: {_safe_text(finding.rule_name)}",
                f"- File: {_safe_text(finding.file_path)}",
                f"- Lines: {_safe_text(finding.start_line)}-{_safe_text(finding.end_line)}",
                f"- Severity: {_safe_text(finding.severity.value)}",
                f"- Scanner message: {_safe_text(finding.message)}",
                f"- Context summary: {_safe_text(result.context_summary)}",
                f"- Model verdict: {_safe_text(decision.model_verdict.value if decision else None)}",
                f"- Model confidence: {_safe_text(decision.model_confidence.value if decision else None)}",
                f"- Policy action: {_safe_text(policy.action.value)}",
                f"- Policy version: {_safe_text(policy.policy_version)}",
                f"- Escalated: {_safe_text(policy.escalated)}",
                f"- Escalation reason: {_safe_text(policy.escalation_reason)}",
                "- Policy reasons:",
            ]
        )
        lines.extend(f"  - {_safe_text(reason)}" for reason in policy.reasons)
        lines.append("- Processing errors:")
        if result.processing_errors:
            lines.extend(f"  {_render_processing_error(error)}" for error in result.processing_errors)
        else:
            lines.append("  - none")

    lines.extend(["", "## Scanner errors"])
    if batch_result.scanner_errors:
        lines.extend(_render_processing_error(error) for error in batch_result.scanner_errors)
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _validate_input(
    batch_result: BatchResult,
    output_path: Path,
    forbidden_values: tuple[str, ...],
    overwrite: bool,
) -> None:
    """Validate report inputs before projection or file I/O."""
    if not isinstance(batch_result, BatchResult) or not isinstance(output_path, Path):
        raise SastTriageError("Invalid Markdown report input.", error_code=_EC_INVALID_INPUT)
    if output_path.is_dir() or not output_path.parent.exists() or not output_path.parent.is_dir():
        raise SastTriageError("Invalid Markdown report output path.", error_code=_EC_INVALID_INPUT)
    if not overwrite and output_path.exists():
        raise SastTriageError("Output file already exists and overwrite=False.", error_code=_EC_OUTPUT_EXISTS)
    for value in forbidden_values:
        if not isinstance(value, str) or not value.strip():
            raise SastTriageError("forbidden_values contains an invalid value.", error_code=_EC_INVALID_INPUT)
        if value in _KNOWN_SAFE_PLACEHOLDERS:
            raise SastTriageError("forbidden_values contains a known-safe placeholder.", error_code=_EC_INVALID_INPUT)


def write_markdown_report(
    batch_result: BatchResult,
    output_path: Path,
    *,
    forbidden_values: tuple[str, ...] = (),
    overwrite: bool = True,
) -> Path:
    """Write a safe Markdown report atomically as UTF-8."""
    _validate_input(batch_result, output_path, forbidden_values, overwrite)
    markdown = _render_report(batch_result)
    for value in set(forbidden_values):
        if value in markdown or _safe_text(value) in markdown:
            raise SastTriageError(
                "Markdown report contains a forbidden value.",
                error_code=_EC_LEAK_CHECK_FAILED,
            )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output_path.parent, suffix=".tmp", delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(markdown)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    except Exception as exc:
        raise SastTriageError(
            "Failed to write Markdown report.", error_code=_EC_WRITE_ERROR
        ) from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
    return output_path.resolve()
