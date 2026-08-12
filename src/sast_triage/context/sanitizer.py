"""Bộ làm sạch context cho SAST Triage Platform.

Sanitizes raw context text (AST scope or line window) to ensure safety
prior to handing over to the LLM provider.

Security Guarantees:
- `SanitizedContext` is the ONLY public frozen domain model allowed to reach TriageProvider.
- For Gitleaks findings, finding lines are masked with safe markers `# <REDACTED_GITLEAKS_FINDING_LINE>`.
- Generic credential assignment, Bearer tokens, PEM private key blocks, and connection URLs
  are sanitized with `<REDACTED_SECRET>` or `<REDACTED_PRIVATE_KEY_BLOCK>`.
- Defense-in-depth leak check validates that no forbidden values remain in output.
- No raw secret values, raw finding lines, hashes, or tracebacks are serialized or logged.
"""

import re
from collections.abc import Sequence
from pathlib import Path

from sast_triage.analysis.base import AnalysisBackend
from sast_triage.context.evidence_service import build_evidence_context
from sast_triage.context.repository_index import RepositoryEvidenceIndex
from sast_triage.context.selection import RawContextSelection
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    MissingContextReason,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    ScannerType,
    SourceKind,
)

# --- Placeholder an toàn và hằng số ---

REDACTED_GITLEAKS_FINDING_LINE: str = "<REDACTED_GITLEAKS_FINDING_LINE>"
REDACTED_SECRET: str = "<REDACTED_SECRET>"
REDACTED_PRIVATE_KEY_BLOCK: str = "<REDACTED_PRIVATE_KEY_BLOCK>"

KNOWN_PLACEHOLDERS: set[str] = {
    REDACTED_GITLEAKS_FINDING_LINE,
    REDACTED_SECRET,
    REDACTED_PRIVATE_KEY_BLOCK,
    f"# {REDACTED_GITLEAKS_FINDING_LINE}",
}

# --- Định danh loại redact ---

GITLEAKS_FINDING_LINE: str = "GITLEAKS_FINDING_LINE"
CREDENTIAL_ASSIGNMENT: str = "CREDENTIAL_ASSIGNMENT"
AUTHORIZATION_BEARER: str = "AUTHORIZATION_BEARER"
PRIVATE_KEY_BLOCK: str = "PRIVATE_KEY_BLOCK"
CONNECTION_URL: str = "CONNECTION_URL"

# --- Mẫu redact tổng quát ---

# PEM Private Key Block
_PEM_REGEX = re.compile(
    r"-----BEGIN [A-Z0-9_\- ]*KEY[A-Z0-9_\- ]*-----[\s\S]*?-----END [A-Z0-9_\- ]*KEY[A-Z0-9_\- ]*-----"
)

# Authorization Bearer Header (handles HTTP headers and dictionary keys e.g. 'Authorization': 'Bearer ...')
_BEARER_REGEX = re.compile(
    r"(?i)(\bAuthorization\b[\s\'\"]*:?[\s\'\"]*Bearer\s+)([^\s\"\'\`\\]+)"
)

# Connection URL Credentials
_URL_CRED_REGEX = re.compile(r"(?i)([a-z0-9\+\-\.]+://[^:\s\/]+:)([^@\s\/]+)(@)")

# Literal Credential Assignment (Quoted: e.g. password = "value", "api_key": 'value')
_CRED_QUOTED_REGEX = re.compile(
    r"(?i)(\b(?:password|passwd|secret|api_key|access_token|token)\b[\s\'\"]*[:=]\s*)([\"'])(.*?)\2"
)

# Literal Credential Assignment (Unquoted standalone token ending statement, excludes expressions like load_token() or req.form['x'])
_CRED_UNQUOTED_REGEX = re.compile(
    r"(?i)(\b(?:password|passwd|secret|api_key|access_token|token)\b\s*[:=]\s*)([a-zA-Z0-9_\-]+)(?=\s*(?:[;,\n]|$))"
)


def _classify_path_category(relative_path: str) -> PathCategory:
    """Phân loại file path thành PathCategory theo các segment đã normalize."""
    path_obj = Path(relative_path)
    parts = [p.lower() for p in path_obj.parts]
    filename = path_obj.name.lower()

    if any(p in ("fixtures", "fixture") for p in parts):
        return PathCategory.FIXTURE

    if (
        any(p in ("tests", "test") for p in parts)
        or filename.startswith("test_")
        or filename.endswith(("_test.py", ".test.js", "_test.go"))
    ):
        return PathCategory.TEST

    if any(p in ("examples", "example") for p in parts):
        return PathCategory.EXAMPLE

    if any(p in ("docs", "documentation") for p in parts):
        return PathCategory.DOCUMENTATION

    return PathCategory.UNKNOWN


def _map_missing_context_reasons(
    raw_context: RawContextSelection,
) -> list[MissingContextReason]:
    """Ánh xạ lý do chẩn đoán thô sang enum MissingContextReason của domain."""
    reasons: list[MissingContextReason] = []
    for diag in raw_context.diagnostic_reasons:
        if diag in ("PYTHON_AST_PARSE_FAILED", MissingContextReason.PYTHON_AST_PARSE_FAILED.value):
            reasons.append(MissingContextReason.PYTHON_AST_PARSE_FAILED)
        elif diag in ("ENCLOSING_SCOPE_EXCEEDED_LIMIT", MissingContextReason.ENCLOSING_SCOPE_EXCEEDED_LIMIT.value):
            reasons.append(MissingContextReason.ENCLOSING_SCOPE_EXCEEDED_LIMIT)
        elif diag in ("CONTEXT_SOURCE_FILE_NOT_FOUND", MissingContextReason.SOURCE_FILE_NOT_FOUND.value):
            reasons.append(MissingContextReason.SOURCE_FILE_NOT_FOUND)
        elif diag in ("CONTEXT_PATH_OUTSIDE_REPOSITORY", MissingContextReason.SOURCE_PATH_OUTSIDE_REPOSITORY.value):
            reasons.append(MissingContextReason.SOURCE_PATH_OUTSIDE_REPOSITORY)
        elif diag in ("CONTEXT_SOURCE_FILE_TOO_LARGE", "FINDING_EXCEEDS_CONTEXT_LIMIT", MissingContextReason.SOURCE_FILE_TOO_LARGE.value):
            reasons.append(MissingContextReason.SOURCE_FILE_TOO_LARGE)
        elif diag in ("CONTEXT_SOURCE_UNSUPPORTED_ENCODING", MissingContextReason.SOURCE_FILE_UNSUPPORTED_ENCODING.value):
            reasons.append(MissingContextReason.SOURCE_FILE_UNSUPPORTED_ENCODING)
        elif diag in ("CONTEXT_INVALID_FINDING_LINE_RANGE", MissingContextReason.INVALID_FINDING_LINE_RANGE.value):
            reasons.append(MissingContextReason.INVALID_FINDING_LINE_RANGE)

    if not reasons:
        reasons.append(MissingContextReason.INVALID_FINDING_LINE_RANGE)

    # Deduplicate while keeping order
    seen: set[MissingContextReason] = set()
    dedup: list[MissingContextReason] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            dedup.append(r)

    return dedup


def _sanitize_text_content(
    text: str,
) -> tuple[str, int, set[str]]:
    """Áp dụng redact credential tổng quát lên nội dung văn bản.

    Returns:
        (sanitized_text, redactions_count, set_of_redaction_types_applied)
    """
    if not text:
        return text, 0, set()

    total_redactions = 0
    applied_types: set[str] = set()

    # 1. Private Key Block
    def pem_replacer(match: re.Match[str]) -> str:
        nonlocal total_redactions
        total_redactions += 1
        applied_types.add(PRIVATE_KEY_BLOCK)
        return REDACTED_PRIVATE_KEY_BLOCK

    text = _PEM_REGEX.sub(pem_replacer, text)

    # 2. Authorization Bearer Header
    def bearer_replacer(match: re.Match[str]) -> str:
        nonlocal total_redactions
        token_val = match.group(2)
        if token_val == REDACTED_SECRET or token_val in KNOWN_PLACEHOLDERS:
            return match.group(0)
        total_redactions += 1
        applied_types.add(AUTHORIZATION_BEARER)
        return f"{match.group(1)}{REDACTED_SECRET}"

    text = _BEARER_REGEX.sub(bearer_replacer, text)

    # 3. Connection URL Credentials
    def url_cred_replacer(match: re.Match[str]) -> str:
        nonlocal total_redactions
        pass_val = match.group(2)
        if pass_val == REDACTED_SECRET or pass_val in KNOWN_PLACEHOLDERS:
            return match.group(0)
        total_redactions += 1
        applied_types.add(CONNECTION_URL)
        return f"{match.group(1)}{REDACTED_SECRET}{match.group(3)}"

    text = _URL_CRED_REGEX.sub(url_cred_replacer, text)

    # 4. Credential Assignment (Quoted)
    def cred_quoted_replacer(match: re.Match[str]) -> str:
        nonlocal total_redactions
        prefix = match.group(1)
        quote = match.group(2)
        val = match.group(3)
        if val in KNOWN_PLACEHOLDERS or val.startswith("<REDACTED_"):
            return match.group(0)
        total_redactions += 1
        applied_types.add(CREDENTIAL_ASSIGNMENT)
        return f"{prefix}{quote}{REDACTED_SECRET}{quote}"

    text = _CRED_QUOTED_REGEX.sub(cred_quoted_replacer, text)

    # 5. Credential Assignment (Unquoted)
    def cred_unquoted_replacer(match: re.Match[str]) -> str:
        nonlocal total_redactions
        prefix = match.group(1)
        val = match.group(2)
        if val in KNOWN_PLACEHOLDERS or val.startswith("<REDACTED_"):
            return match.group(0)
        total_redactions += 1
        applied_types.add(CREDENTIAL_ASSIGNMENT)
        return f"{prefix}{REDACTED_SECRET}"

    text = _CRED_UNQUOTED_REGEX.sub(cred_unquoted_replacer, text)

    return text, total_redactions, applied_types


def _sanitize_string_sequence(
    items: Sequence[str],
) -> tuple[list[str], int, set[str]]:
    """Áp dụng redact credential tổng quát lên dãy chuỗi (ví dụ import/decorator)."""
    sanitized_list: list[str] = []
    total_redactions = 0
    applied_types: set[str] = set()

    for item in items:
        s_item, count, types = _sanitize_text_content(item)
        sanitized_list.append(s_item)
        total_redactions += count
        applied_types.update(types)

    return sanitized_list, total_redactions, applied_types


def sanitize_context(
    finding: NormalizedFinding,
    raw_context: RawContextSelection,
    *,
    forbidden_values: tuple[str, ...] = (),
    repository_index: RepositoryEvidenceIndex | None = None,
    analysis_backend: AnalysisBackend | None = None,
) -> SanitizedContext:
    """Sanitize raw context đã chọn để tạo ``SanitizedContext`` an toàn cho LLM sử dụng.

    Args:
        finding: Target NormalizedFinding.
        raw_context: Ephemeral RawContextSelection from context layer.
        forbidden_values: Optional tuple of secret strings that MUST NOT remain in sanitized output.

    Returns:
        A frozen, validated ``SanitizedContext`` Pydantic model.

    Raises:
        SastTriageError: On input mismatch or invalid forbidden_values parameter.
    """
    # 1. Input Consistency Validation
    if raw_context.finding_id != finding.finding_instance_id:
        raise SastTriageError(
            safe_message="raw_context.finding_id does not match finding.finding_instance_id.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    if raw_context.scanner != finding.scanner:
        raise SastTriageError(
            safe_message="raw_context.scanner does not match finding.scanner.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    finding_end = finding.end_line if finding.end_line is not None else finding.start_line
    if raw_context.finding_start_line != finding.start_line or raw_context.finding_end_line != finding_end:
        raise SastTriageError(
            safe_message="raw_context finding line range does not match finding line range.",
            error_code="CONTEXT_INVALID_FINDING_LINE_RANGE",
            retryable=False,
        )

    # 2. Validate forbidden_values parameter
    cleaned_forbidden: list[str] = []
    for fv in forbidden_values:
        if not fv or not fv.strip():
            raise SastTriageError(
                safe_message="forbidden_values elements must be non-empty strings.",
                error_code="CONTEXT_INVALID_FORBIDDEN_VALUE",
                retryable=False,
            )
        stripped = fv.strip()
        if stripped in KNOWN_PLACEHOLDERS or stripped.startswith("<REDACTED_"):
            raise SastTriageError(
                safe_message="forbidden_values elements cannot be safe placeholder strings.",
                error_code="CONTEXT_INVALID_FORBIDDEN_VALUE",
                retryable=False,
            )
        cleaned_forbidden.append(stripped)

    # Deduplicate forbidden values
    unique_forbidden = list(dict.fromkeys(cleaned_forbidden))

    path_cat = _classify_path_category(finding.file_path)

    # 3. Handle Unavailable Raw Context
    if not raw_context.context_available or raw_context.selected_text is None:
        missing_reasons = _map_missing_context_reasons(raw_context)
        return SanitizedContext(
            finding_id=finding.finding_instance_id,
            sanitized_snippet=None,
            context_strategy=ContextStrategy.UNAVAILABLE,
            context_start_line=None,
            context_end_line=None,
            finding_start_line=finding.start_line,
            finding_end_line=finding.end_line,
            enclosing_function=raw_context.enclosing_function,
            enclosing_class=raw_context.enclosing_class,
            limited_imports=list(raw_context.limited_imports) if raw_context.limited_imports else None,
            limited_decorators=list(raw_context.limited_decorators) if raw_context.limited_decorators else None,
            path_category=path_cat,
            source_kind=SourceKind.WORKTREE,
            context_available=False,
            missing_context_reasons=missing_reasons,
            redactions_applied=0,
            redaction_types=[],
            truncated=raw_context.truncated,
        )

    # 4. Perform Scanner-Specific Pre-Processing
    total_redactions = 0
    applied_types: set[str] = set()
    current_text = raw_context.selected_text
    strategy = raw_context.strategy

    if finding.scanner == ScannerType.GITLEAKS:
        strategy = ContextStrategy.REDACTED_LINE_WINDOW
        c_start = raw_context.context_start_line
        c_end = raw_context.context_end_line

        if c_start is None or c_end is None or finding.start_line < c_start or finding_end > c_end:
            # Line mapping failure
            return SanitizedContext(
                finding_id=finding.finding_instance_id,
                sanitized_snippet=None,
                context_strategy=ContextStrategy.UNAVAILABLE,
                context_start_line=None,
                context_end_line=None,
                finding_start_line=finding.start_line,
                finding_end_line=finding.end_line,
                enclosing_function=raw_context.enclosing_function,
                enclosing_class=raw_context.enclosing_class,
                limited_imports=None,
                limited_decorators=None,
                path_category=path_cat,
                source_kind=SourceKind.WORKTREE,
                context_available=False,
                missing_context_reasons=[MissingContextReason.CONTEXT_SANITIZATION_FAILED],
                redactions_applied=0,
                redaction_types=[],
                truncated=raw_context.truncated,
            )

        lines = current_text.splitlines(keepends=True)
        idx_start = finding.start_line - c_start
        idx_end = finding_end - c_start

        if idx_start < 0 or idx_end >= len(lines):
            # Line mapping failure out of bounds
            return SanitizedContext(
                finding_id=finding.finding_instance_id,
                sanitized_snippet=None,
                context_strategy=ContextStrategy.UNAVAILABLE,
                context_start_line=None,
                context_end_line=None,
                finding_start_line=finding.start_line,
                finding_end_line=finding.end_line,
                enclosing_function=raw_context.enclosing_function,
                enclosing_class=raw_context.enclosing_class,
                limited_imports=None,
                limited_decorators=None,
                path_category=path_cat,
                source_kind=SourceKind.WORKTREE,
                context_available=False,
                missing_context_reasons=[MissingContextReason.CONTEXT_SANITIZATION_FAILED],
                redactions_applied=0,
                redaction_types=[],
                truncated=raw_context.truncated,
            )

        # Mask finding lines with `# <REDACTED_GITLEAKS_FINDING_LINE>` preserving line count & indentation
        for i in range(idx_start, idx_end + 1):
            original_line = lines[i]
            indent_len = len(original_line) - len(original_line.lstrip())
            indent = original_line[:indent_len]
            has_newline = original_line.endswith("\n")
            lines[i] = f"{indent}# {REDACTED_GITLEAKS_FINDING_LINE}\n" if has_newline else f"{indent}# {REDACTED_GITLEAKS_FINDING_LINE}"
            total_redactions += 1

        applied_types.add(GITLEAKS_FINDING_LINE)
        current_text = "".join(lines)

    # 5. Generic Credential Sanitization on Selected Text
    current_text, text_redactions, text_types = _sanitize_text_content(current_text)
    total_redactions += text_redactions
    applied_types.update(text_types)

    # 6. Generic Credential Sanitization on Imports & Decorators
    sanitized_imports, imp_redactions, imp_types = _sanitize_string_sequence(raw_context.limited_imports)
    total_redactions += imp_redactions
    applied_types.update(imp_types)

    sanitized_decorators, dec_redactions, dec_types = _sanitize_string_sequence(raw_context.limited_decorators)
    total_redactions += dec_redactions
    applied_types.update(dec_types)

    # 7. Defense-in-Depth Forbidden-Value Leak Check
    for fv in unique_forbidden:
        leak_found = (
            fv in current_text
            or any(fv in imp for imp in sanitized_imports)
            or any(fv in dec for dec in sanitized_decorators)
        )
        if leak_found:
            # Forbidden value leaked -> abort context
            return SanitizedContext(
                finding_id=finding.finding_instance_id,
                sanitized_snippet=None,
                context_strategy=ContextStrategy.UNAVAILABLE,
                context_start_line=None,
                context_end_line=None,
                finding_start_line=finding.start_line,
                finding_end_line=finding.end_line,
                enclosing_function=raw_context.enclosing_function,
                enclosing_class=raw_context.enclosing_class,
                limited_imports=None,
                limited_decorators=None,
                path_category=path_cat,
                source_kind=SourceKind.WORKTREE,
                context_available=False,
                missing_context_reasons=[MissingContextReason.CONTEXT_SANITIZATION_FAILED],
                redactions_applied=0,
                redaction_types=[],
                truncated=raw_context.truncated,
            )

    sorted_redaction_types = sorted(applied_types)

    sanitized_context = SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet=current_text,
        context_strategy=strategy,
        context_start_line=raw_context.context_start_line,
        context_end_line=raw_context.context_end_line,
        finding_start_line=finding.start_line,
        finding_end_line=finding.end_line,
        enclosing_function=raw_context.enclosing_function,
        enclosing_class=raw_context.enclosing_class,
        limited_imports=sanitized_imports if sanitized_imports else None,
        limited_decorators=sanitized_decorators if sanitized_decorators else None,
        path_category=path_cat,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
        missing_context_reasons=[],
        redactions_applied=total_redactions,
        redaction_types=sorted_redaction_types,
        truncated=raw_context.truncated,
    )

    if finding.finding_type != FindingType.SAST or raw_context.analysis_source is None:
        return sanitized_context

    try:
        return build_evidence_context(
            finding,
            raw_context.analysis_source,
            sanitized_context,
            repository_index=repository_index,
            analysis_backend=analysis_backend,
        ).context
    except SyntaxError:
        # Syntax details can include raw source; expose only a typed, safe reason.
        return sanitized_context.model_copy(
            update={
                "missing_context_reasons": [MissingContextReason.PYTHON_AST_PARSE_FAILED],
                "truncated": True,
            }
        )
