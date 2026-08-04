"""Python AST Scope Analysis for SAST Triage Platform.

Analyzes Python source code using standard library `ast` to find the smallest
enclosing function or class scope covering a static analysis finding line range.

Security guarantees:
- `PythonScopeResult` is internal, immutable, and ephemeral.
- Raw text fields (`selected_text`, `limited_imports`, `limited_decorators`) use `repr=False`
  so that `repr(result)` and `str(result)` NEVER leak raw source code or secrets.
- Does NOT execute decorators or imports, does NOT call `eval`, and does NOT use `ast.unparse()`.
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from sast_triage.context.reader import SourceReadResult
from sast_triage.errors import SastTriageError
from sast_triage.models import ContextStrategy

# --- Diagnostic Constants ---

PYTHON_AST_PARSE_FAILED: str = "PYTHON_AST_PARSE_FAILED"
NO_ENCLOSING_SCOPE: str = "NO_ENCLOSING_SCOPE"
ENCLOSING_SCOPE_EXCEEDED_LIMIT: str = "ENCLOSING_SCOPE_EXCEEDED_LIMIT"


@dataclass(frozen=True, slots=True)
class PythonScopeResult:
    """Internal ephemeral result of Python AST scope analysis.

    Attributes:
        strategy: Applied context strategy (PYTHON_FUNCTION, PYTHON_CLASS, or UNAVAILABLE).
        selected_text: Raw source code of the selected scope (excluded from repr).
        context_start_line: 1-based start line of selected scope (including decorators).
        context_end_line: 1-based end line of selected scope.
        enclosing_function: Name of the enclosing function/method (if any).
        enclosing_class: Name of the enclosing class (if any).
        limited_imports: Module-level import source statements (excluded from repr).
        limited_decorators: Decorator source text lines for selected scope (excluded from repr).
        diagnostic_reasons: Tuple of diagnostic reason strings.
        scope_exceeded_limit: True if enclosing scope exceeded size limits.
    """

    strategy: ContextStrategy
    selected_text: str | None = field(default=None, repr=False)
    context_start_line: int | None = None
    context_end_line: int | None = None
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    limited_imports: tuple[str, ...] = field(default=(), repr=False)
    limited_decorators: tuple[str, ...] = field(default=(), repr=False)
    diagnostic_reasons: tuple[str, ...] = ()
    scope_exceeded_limit: bool = False


def _get_effective_start_line(node: ast.AST) -> int:
    """Return effective start line including decorators if present."""
    decorator_list: list[ast.AST] = getattr(node, "decorator_list", [])
    if decorator_list:
        return min(dec.lineno for dec in decorator_list)
    return getattr(node, "lineno", 1)


def _collect_module_imports(
    tree: ast.AST,
    source_lines: list[str],
    max_import_lines: int,
) -> tuple[str, ...]:
    """Collect module-level import statement texts up to max_import_lines."""
    if max_import_lines <= 0:
        return ()

    collected: list[str] = []
    line_count = 0

    if not isinstance(tree, ast.Module):
        return ()

    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            start = stmt.lineno
            end = stmt.end_lineno if stmt.end_lineno is not None else start
            stmt_lines_count = end - start + 1

            if line_count + stmt_lines_count > max_import_lines:
                break

            stmt_text = "".join(source_lines[start - 1 : end]).rstrip()
            collected.append(stmt_text)
            line_count += stmt_lines_count

    return tuple(collected)


def select_python_scope(
    source: SourceReadResult,
    finding_start_line: int,
    finding_end_line: int | None = None,
    *,
    max_scope_lines: int = 120,
    max_context_characters: int = 12_000,
    max_import_lines: int = 20,
) -> PythonScopeResult:
    """Select the smallest enclosing Python function or class scope for a finding.

    Args:
        source: Immutable ``SourceReadResult`` containing raw source text.
        finding_start_line: 1-based start line of the finding.
        finding_end_line: 1-based end line of the finding (defaults to start line).
        max_scope_lines: Maximum allowed line count for selected scope (default 120).
        max_context_characters: Maximum allowed character count for selected scope (default 12,000).
        max_import_lines: Maximum module-level import lines to collect (default 20).

    Returns:
        An internal immutable ``PythonScopeResult``.

    Raises:
        SastTriageError: On invalid line range or invalid scope limits.
    """
    # 1. Input Validation
    if (
        not isinstance(finding_start_line, int)
        or isinstance(finding_start_line, bool)
        or finding_start_line <= 0
    ):
        raise SastTriageError(
            safe_message="finding_start_line must be a positive integer.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    if finding_end_line is None:
        finding_end_line = finding_start_line
    elif (
        not isinstance(finding_end_line, int)
        or isinstance(finding_end_line, bool)
        or finding_end_line < finding_start_line
    ):
        raise SastTriageError(
            safe_message="finding_end_line cannot be earlier than finding_start_line.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    source_lines = source.text.splitlines(keepends=True)
    total_source_lines = len(source_lines)

    if total_source_lines == 0 or finding_start_line > total_source_lines or finding_end_line > total_source_lines:
        raise SastTriageError(
            safe_message="finding line range exceeds source file line count.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    if (
        not isinstance(max_scope_lines, int)
        or isinstance(max_scope_lines, bool)
        or max_scope_lines <= 0
        or not isinstance(max_context_characters, int)
        or isinstance(max_context_characters, bool)
        or max_context_characters <= 0
        or not isinstance(max_import_lines, int)
        or isinstance(max_import_lines, bool)
        or max_import_lines < 0
    ):
        raise SastTriageError(
            safe_message="Scope limits must be valid positive integers.",
            error_code="CONTEXT_INVALID_SCOPE_LIMIT",
            retryable=False,
        )

    # 2. Parse AST
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return PythonScopeResult(
            strategy=ContextStrategy.UNAVAILABLE,
            selected_text=None,
            diagnostic_reasons=(PYTHON_AST_PARSE_FAILED,),
        )
    except (MemoryError, SystemError) as exc:
        raise SastTriageError(
            safe_message="AST parsing failed due to memory or system limits.",
            error_code="CONTEXT_AST_PARSE_ERROR",
            retryable=False,
        ) from exc

    # 3. Collect module-level imports
    limited_imports = _collect_module_imports(tree, source_lines, max_import_lines)

    # 4. Build Parent Map
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent

    # 5. Find Scope Candidates
    matching_func_nodes: list[tuple[ast.AST, int]] = []
    matching_class_nodes: list[tuple[ast.AST, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            eff_start = _get_effective_start_line(node)
            eff_end = node.end_lineno if node.end_lineno is not None else eff_start

            if eff_start <= finding_start_line and eff_end >= finding_end_line:
                span = eff_end - eff_start + 1
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    matching_func_nodes.append((node, span))
                else:
                    matching_class_nodes.append((node, span))

    target_node: Any = None
    strategy: ContextStrategy = ContextStrategy.UNAVAILABLE
    enclosing_function: str | None = None
    enclosing_class: str | None = None

    if matching_func_nodes:
        # Smallest span function node
        matching_func_nodes.sort(key=lambda item: item[1])
        target_node = matching_func_nodes[0][0]
        enclosing_function = target_node.name
        strategy = ContextStrategy.PYTHON_FUNCTION

        # Walk up parent_map to find nearest enclosing ClassDef
        curr: ast.AST | None = parent_map.get(target_node)
        while curr is not None:
            if isinstance(curr, ast.ClassDef):
                enclosing_class = curr.name
                break
            curr = parent_map.get(curr)

    elif matching_class_nodes:
        # Smallest span class node
        matching_class_nodes.sort(key=lambda item: item[1])
        target_node = matching_class_nodes[0][0]
        enclosing_class = target_node.name
        strategy = ContextStrategy.PYTHON_CLASS
    else:
        return PythonScopeResult(
            strategy=ContextStrategy.UNAVAILABLE,
            selected_text=None,
            limited_imports=limited_imports,
            diagnostic_reasons=(NO_ENCLOSING_SCOPE,),
        )

    # 6. Extract Decorators
    limited_decorators: list[str] = []
    decorator_list: list[ast.AST] = getattr(target_node, "decorator_list", [])
    for dec in decorator_list:
        dec_start = dec.lineno
        dec_end = dec.end_lineno if dec.end_lineno is not None else dec_start
        dec_text = "".join(source_lines[dec_start - 1 : dec_end]).strip()
        limited_decorators.append(dec_text)

    # 7. Extract Source Text & Enforce Limits
    eff_start = _get_effective_start_line(target_node)
    eff_end = target_node.end_lineno if target_node.end_lineno is not None else eff_start
    scope_line_count = eff_end - eff_start + 1

    selected_lines = source_lines[eff_start - 1 : eff_end]
    raw_selected_text = "".join(selected_lines)
    char_count = len(raw_selected_text)

    if scope_line_count > max_scope_lines or char_count > max_context_characters:
        return PythonScopeResult(
            strategy=ContextStrategy.UNAVAILABLE,
            selected_text=None,
            context_start_line=eff_start,
            context_end_line=eff_end,
            enclosing_function=enclosing_function,
            enclosing_class=enclosing_class,
            limited_imports=limited_imports,
            limited_decorators=tuple(limited_decorators),
            diagnostic_reasons=(ENCLOSING_SCOPE_EXCEEDED_LIMIT,),
            scope_exceeded_limit=True,
        )

    return PythonScopeResult(
        strategy=strategy,
        selected_text=raw_selected_text,
        context_start_line=eff_start,
        context_end_line=eff_end,
        enclosing_function=enclosing_function,
        enclosing_class=enclosing_class,
        limited_imports=limited_imports,
        limited_decorators=tuple(limited_decorators),
        diagnostic_reasons=(),
        scope_exceeded_limit=False,
    )
