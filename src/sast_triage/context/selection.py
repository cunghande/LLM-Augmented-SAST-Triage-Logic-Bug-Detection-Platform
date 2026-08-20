"""Select a bounded line window before source is sanitized."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sast_triage.context.reader import SourceReadResult
from sast_triage.errors import SastTriageError
from sast_triage.models import ContextStrategy, NormalizedFinding, ScannerType

GITLEAKS_REDACTION_REQUIRED = "GITLEAKS_REDACTION_REQUIRED"
FINDING_EXCEEDS_CONTEXT_LIMIT = "FINDING_EXCEEDS_CONTEXT_LIMIT"
CONTEXT_TRUNCATED_TO_LIMIT = "CONTEXT_TRUNCATED_TO_LIMIT"


@dataclass(frozen=True, slots=True)
class RawContextSelection:
    """Temporary raw line window; text fields are excluded from repr output."""

    finding_id: str
    scanner: ScannerType
    strategy: ContextStrategy
    selected_text: str | None = field(default=None, repr=False)
    context_start_line: int | None = None
    context_end_line: int | None = None
    finding_start_line: int = 1
    finding_end_line: int = 1
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    limited_imports: tuple[str, ...] = field(default=(), repr=False)
    limited_decorators: tuple[str, ...] = field(default=(), repr=False)
    truncated: bool = False
    context_available: bool = True
    diagnostic_reasons: tuple[str, ...] = ()


def _validate_inputs(
    finding: NormalizedFinding,
    source: SourceReadResult,
    *,
    line_window_before: int,
    line_window_after: int,
    max_context_characters: int,
) -> tuple[list[str], int, int]:
    if Path(finding.file_path).as_posix() != Path(source.relative_path).as_posix():
        raise SastTriageError(
            safe_message="Finding path does not match the source path.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )
    if (
        not isinstance(line_window_before, int)
        or isinstance(line_window_before, bool)
        or line_window_before < 0
        or not isinstance(line_window_after, int)
        or isinstance(line_window_after, bool)
        or line_window_after < 0
        or not isinstance(max_context_characters, int)
        or isinstance(max_context_characters, bool)
        or max_context_characters <= 0
    ):
        raise SastTriageError(
            safe_message="Context window limits are invalid.",
            error_code="CONTEXT_INVALID_SELECTION_LIMIT",
            retryable=False,
        )

    lines = source.text.splitlines(keepends=True)
    finding_start = finding.start_line
    finding_end = finding.end_line or finding_start
    if (
        not lines
        or finding_start <= 0
        or finding_end < finding_start
        or finding_end > len(lines)
    ):
        raise SastTriageError(
            safe_message="Finding line range exceeds the source file.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )
    return lines, finding_start, finding_end


def _trim_window(
    lines: list[str],
    start: int,
    end: int,
    finding_start: int,
    finding_end: int,
    character_limit: int,
) -> tuple[int, int, str]:
    while start < finding_start or end > finding_end:
        text = "".join(lines[start - 1 : end])
        if len(text) <= character_limit:
            return start, end, text
        top_distance = finding_start - start
        bottom_distance = end - finding_end
        if start < finding_start and (
            end == finding_end or top_distance >= bottom_distance
        ):
            start += 1
        elif end > finding_end:
            end -= 1
    return start, end, "".join(lines[start - 1 : end])


def select_raw_context(
    finding: NormalizedFinding,
    source: SourceReadResult,
    *,
    line_window_before: int = 10,
    line_window_after: int = 10,
    max_context_characters: int = 12_000,
) -> RawContextSelection:
    """Return a bounded raw line window containing the complete finding range."""
    lines, finding_start, finding_end = _validate_inputs(
        finding,
        source,
        line_window_before=line_window_before,
        line_window_after=line_window_after,
        max_context_characters=max_context_characters,
    )
    diagnostics = (
        (GITLEAKS_REDACTION_REQUIRED,)
        if finding.scanner == ScannerType.GITLEAKS
        else ()
    )
    finding_text = "".join(lines[finding_start - 1 : finding_end])
    if len(finding_text) > max_context_characters:
        return RawContextSelection(
            finding_id=finding.finding_instance_id,
            scanner=finding.scanner,
            strategy=ContextStrategy.LINE_WINDOW,
            context_start_line=finding_start,
            context_end_line=finding_end,
            finding_start_line=finding_start,
            finding_end_line=finding_end,
            context_available=False,
            diagnostic_reasons=(*diagnostics, FINDING_EXCEEDS_CONTEXT_LIMIT),
        )

    start = max(1, finding_start - line_window_before)
    end = min(len(lines), finding_end + line_window_after)
    text = "".join(lines[start - 1 : end])
    truncated = len(text) > max_context_characters
    if truncated:
        start, end, text = _trim_window(
            lines,
            start,
            end,
            finding_start,
            finding_end,
            max_context_characters,
        )
        diagnostics = (*diagnostics, CONTEXT_TRUNCATED_TO_LIMIT)

    return RawContextSelection(
        finding_id=finding.finding_instance_id,
        scanner=finding.scanner,
        strategy=ContextStrategy.LINE_WINDOW,
        selected_text=text,
        context_start_line=start,
        context_end_line=end,
        finding_start_line=finding_start,
        finding_end_line=finding_end,
        truncated=truncated,
        diagnostic_reasons=diagnostics,
    )
