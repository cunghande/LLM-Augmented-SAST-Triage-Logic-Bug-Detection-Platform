"""Raw Context Selection for SAST Triage Platform.

Selects raw internal context (AST scope or line window) for a NormalizedFinding
from a SourceReadResult and optional PythonScopeResult.

Security guarantees:
- `RawContextSelection` is internal, immutable, and ephemeral.
- Raw text fields (`selected_text`, `limited_imports`, `limited_decorators`) use `repr=False`
  so that `repr(result)` and `str(result)` NEVER leak raw source code or secrets.
- Gitleaks findings ALWAYS use LINE_WINDOW in raw selection (with GITLEAKS_REDACTION_REQUIRED diagnostic).
  The strategy becomes REDACTED_LINE_WINDOW only after sanitization in Task 3.4.
"""

from dataclasses import dataclass, field
from pathlib import Path

from sast_triage.context.python_scope import PythonScopeResult
from sast_triage.context.reader import SourceReadResult
from sast_triage.errors import SastTriageError
from sast_triage.models import ContextStrategy, NormalizedFinding, ScannerType

# --- Diagnostic Constants ---

LINE_WINDOW_FALLBACK: str = "LINE_WINDOW_FALLBACK"
GITLEAKS_REDACTION_REQUIRED: str = "GITLEAKS_REDACTION_REQUIRED"
FINDING_EXCEEDS_CONTEXT_LIMIT: str = "FINDING_EXCEEDS_CONTEXT_LIMIT"
CONTEXT_TRUNCATED_TO_LIMIT: str = "CONTEXT_TRUNCATED_TO_LIMIT"


@dataclass(frozen=True, slots=True)
class RawContextSelection:
    """Internal ephemeral result of raw context selection.

    Attributes:
        finding_id: Unique finding instance ID.
        scanner: Scanner type of the finding (SEMGREP or GITLEAKS).
        strategy: Raw context strategy applied (PYTHON_FUNCTION, PYTHON_CLASS, or LINE_WINDOW).
        selected_text: Raw selected context text (excluded from repr).
        context_start_line: 1-based start line of selected context.
        context_end_line: 1-based end line of selected context.
        finding_start_line: 1-based start line of finding.
        finding_end_line: 1-based end line of finding.
        enclosing_function: Name of enclosing function (if available).
        enclosing_class: Name of enclosing class (if available).
        limited_imports: Module-level import lines (excluded from repr).
        limited_decorators: Decorator lines for scope (excluded from repr).
        truncated: True if context was line-truncated to fit character limits.
        context_available: True if context text is available.
        diagnostic_reasons: Tuple of diagnostic reason codes.
    """

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


def _paths_match(path1: str, path2: str) -> bool:
    """Check if two relative path strings refer to the same normalized relative file path."""
    p1 = Path(path1).as_posix()
    p2 = Path(path2).as_posix()
    return p1 == p2


def select_raw_context(
    finding: NormalizedFinding,
    source: SourceReadResult,
    scope: PythonScopeResult | None = None,
    *,
    line_window_before: int = 10,
    line_window_after: int = 10,
    max_context_characters: int = 12_000,
) -> RawContextSelection:
    """Select raw context text and metadata for a finding from source and scope.

    Args:
        finding: Normalized finding from static analyzer.
        source: Immutable ``SourceReadResult`` for target source file.
        scope: Optional ``PythonScopeResult`` from AST analysis.
        line_window_before: Lines to include before finding start line (default 10).
        line_window_after: Lines to include after finding end line (default 10).
        max_context_characters: Maximum character limit for selected context (default 12,000).

    Returns:
        An internal immutable ``RawContextSelection``.

    Raises:
        SastTriageError: On path mismatch, invalid line range, or invalid limits.
    """
    # 1. Input Validation
    if not _paths_match(finding.file_path, source.relative_path):
        raise SastTriageError(
            safe_message="Finding file_path does not match source relative_path.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    finding_start = finding.start_line
    finding_end = finding.end_line if finding.end_line is not None else finding_start

    if (
        not isinstance(finding_start, int)
        or isinstance(finding_start, bool)
        or finding_start <= 0
        or not isinstance(finding_end, int)
        or isinstance(finding_end, bool)
        or finding_end < finding_start
    ):
        raise SastTriageError(
            safe_message="Finding line range is invalid.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    source_lines = source.text.splitlines(keepends=True)
    total_source_lines = len(source_lines)

    if total_source_lines == 0 or finding_start > total_source_lines or finding_end > total_source_lines:
        raise SastTriageError(
            safe_message="Finding line range exceeds source file line count.",
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
            safe_message="Line window and character limit parameters must be valid positive integers.",
            error_code="CONTEXT_INVALID_SELECTION_LIMIT",
            retryable=False,
        )

    # 2. Decision Tree Strategy Selection
    is_semgrep = finding.scanner == ScannerType.SEMGREP

    has_valid_ast_scope = (
        is_semgrep
        and scope is not None
        and scope.strategy in (ContextStrategy.PYTHON_FUNCTION, ContextStrategy.PYTHON_CLASS)
        and scope.selected_text is not None
        and not scope.scope_exceeded_limit
    )

    diagnostics: list[str] = []
    enclosing_function = scope.enclosing_function if scope else None
    enclosing_class = scope.enclosing_class if scope else None
    limited_imports = scope.limited_imports if scope else ()
    limited_decorators = scope.limited_decorators if scope else ()

    if has_valid_ast_scope and scope is not None and scope.selected_text is not None:
        strategy = scope.strategy
        raw_text = scope.selected_text
        start_line = scope.context_start_line if scope.context_start_line is not None else finding_start
        end_line = scope.context_end_line if scope.context_end_line is not None else finding_end
        if scope.diagnostic_reasons:
            diagnostics.extend(scope.diagnostic_reasons)
    else:
        # Fallback / Default Line Window Strategy
        strategy = ContextStrategy.LINE_WINDOW

        if is_semgrep:
            diagnostics.append(LINE_WINDOW_FALLBACK)
            if scope and scope.diagnostic_reasons:
                diagnostics.extend(scope.diagnostic_reasons)
        else:
            # Gitleaks
            diagnostics.append(GITLEAKS_REDACTION_REQUIRED)
            if scope and scope.diagnostic_reasons:
                diagnostics.extend(scope.diagnostic_reasons)

        start_line = max(1, finding_start - line_window_before)
        end_line = min(total_source_lines, finding_end + line_window_after)
        raw_text = "".join(source_lines[start_line - 1 : end_line])

    # 3. Truncation and Character Limit Defense
    finding_lines_text = "".join(source_lines[finding_start - 1 : finding_end])
    finding_char_count = len(finding_lines_text)

    # Case A: Finding lines alone exceed character limit
    if finding_char_count > max_context_characters:
        diagnostics.append(FINDING_EXCEEDS_CONTEXT_LIMIT)
        return RawContextSelection(
            finding_id=finding.finding_instance_id,
            scanner=finding.scanner,
            strategy=strategy,
            selected_text=None,
            context_start_line=finding_start,
            context_end_line=finding_end,
            finding_start_line=finding_start,
            finding_end_line=finding_end,
            enclosing_function=enclosing_function,
            enclosing_class=enclosing_class,
            limited_imports=limited_imports,
            limited_decorators=limited_decorators,
            truncated=False,
            context_available=False,
            diagnostic_reasons=tuple(diagnostics),
        )

    # Case B: Context fits within character limit
    if len(raw_text) <= max_context_characters:
        return RawContextSelection(
            finding_id=finding.finding_instance_id,
            scanner=finding.scanner,
            strategy=strategy,
            selected_text=raw_text,
            context_start_line=start_line,
            context_end_line=end_line,
            finding_start_line=finding_start,
            finding_end_line=finding_end,
            enclosing_function=enclosing_function,
            enclosing_class=enclosing_class,
            limited_imports=limited_imports,
            limited_decorators=limited_decorators,
            truncated=False,
            context_available=True,
            diagnostic_reasons=tuple(diagnostics),
        )

    # Case C: Context exceeds limit -> Truncate lines surrounding finding
    diagnostics.append(CONTEXT_TRUNCATED_TO_LIMIT)
    curr_start = start_line
    curr_end = end_line

    while curr_start < finding_start or curr_end > finding_end:
        curr_len = sum(len(source_lines[i]) for i in range(curr_start - 1, curr_end))
        if curr_len <= max_context_characters:
            break

        # Trim top or bottom
        top_dist = finding_start - curr_start
        bottom_dist = curr_end - finding_end

        if curr_start < finding_start and (curr_end == finding_end or top_dist >= bottom_dist):
            curr_start += 1
        elif curr_end > finding_end:
            curr_end -= 1
        else:
            break

    truncated_text = "".join(source_lines[curr_start - 1 : curr_end])

    return RawContextSelection(
        finding_id=finding.finding_instance_id,
        scanner=finding.scanner,
        strategy=strategy,
        selected_text=truncated_text,
        context_start_line=curr_start,
        context_end_line=curr_end,
        finding_start_line=finding_start,
        finding_end_line=finding_end,
        enclosing_function=enclosing_function,
        enclosing_class=enclosing_class,
        limited_imports=limited_imports,
        limited_decorators=limited_decorators,
        truncated=True,
        context_available=True,
        diagnostic_reasons=tuple(diagnostics),
    )
