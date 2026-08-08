"""Package đọc và trích xuất ngữ cảnh mã nguồn."""

from sast_triage.context.python_scope import (
    ENCLOSING_SCOPE_EXCEEDED_LIMIT,
    NO_ENCLOSING_SCOPE,
    PYTHON_AST_PARSE_FAILED,
    PythonScopeResult,
    select_python_scope,
)
from sast_triage.context.reader import SourceReadResult, read_repository_source
from sast_triage.context.sanitizer import sanitize_context
from sast_triage.context.selection import (
    CONTEXT_TRUNCATED_TO_LIMIT,
    FINDING_EXCEEDS_CONTEXT_LIMIT,
    GITLEAKS_REDACTION_REQUIRED,
    LINE_WINDOW_FALLBACK,
    RawContextSelection,
    select_raw_context,
)

__all__ = [
    "CONTEXT_TRUNCATED_TO_LIMIT",
    "ENCLOSING_SCOPE_EXCEEDED_LIMIT",
    "FINDING_EXCEEDS_CONTEXT_LIMIT",
    "GITLEAKS_REDACTION_REQUIRED",
    "LINE_WINDOW_FALLBACK",
    "NO_ENCLOSING_SCOPE",
    "PYTHON_AST_PARSE_FAILED",
    "PythonScopeResult",
    "RawContextSelection",
    "SourceReadResult",
    "read_repository_source",
    "sanitize_context",
    "select_python_scope",
    "select_raw_context",
]
