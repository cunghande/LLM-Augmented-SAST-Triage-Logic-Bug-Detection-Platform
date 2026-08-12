"""Chọn raw context cho SAST Triage Platform.

Chọn raw context nội bộ (AST scope hoặc line window) cho một NormalizedFinding
từ SourceReadResult và PythonScopeResult tùy chọn.

Cam kết bảo mật:
- `RawContextSelection` là nội bộ, bất biến và tạm thời.
- Các trường văn bản thô (`selected_text`, `limited_imports`, `limited_decorators`) dùng `repr=False`
  để `repr(result)` và `str(result)` KHÔNG BAO GIỜ làm lộ mã nguồn thô hoặc secret.
- Finding Gitleaks LUÔN dùng LINE_WINDOW khi chọn raw context (có chẩn đoán GITLEAKS_REDACTION_REQUIRED).
  Chiến lược chỉ thành REDACTED_LINE_WINDOW sau bước sanitize ở Task 3.4.
"""

from dataclasses import dataclass, field
from pathlib import Path

from sast_triage.context.python_scope import PythonScopeResult
from sast_triage.context.reader import SourceReadResult
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    ScannerType,
)

# --- Hằng số chẩn đoán ---

LINE_WINDOW_FALLBACK: str = "LINE_WINDOW_FALLBACK"
GITLEAKS_REDACTION_REQUIRED: str = "GITLEAKS_REDACTION_REQUIRED"
FINDING_EXCEEDS_CONTEXT_LIMIT: str = "FINDING_EXCEEDS_CONTEXT_LIMIT"
CONTEXT_TRUNCATED_TO_LIMIT: str = "CONTEXT_TRUNCATED_TO_LIMIT"


@dataclass(frozen=True, slots=True)
class RawContextSelection:
    """Kết quả tạm thời, nội bộ của việc chọn raw context.

    Thuộc tính:
        finding_id: ID instance finding duy nhất.
        scanner: Loại scanner của finding (SEMGREP hoặc GITLEAKS).
        strategy: Chiến lược raw context đã áp dụng (PYTHON_FUNCTION, PYTHON_CLASS hoặc LINE_WINDOW).
        selected_text: Văn bản raw context đã chọn (loại khỏi repr).
        context_start_line: Dòng bắt đầu 1-based của context đã chọn.
        context_end_line: Dòng kết thúc 1-based của context đã chọn.
        finding_start_line: Dòng bắt đầu 1-based của finding.
        finding_end_line: Dòng kết thúc 1-based của finding.
        enclosing_function: Tên hàm bao quanh (nếu có).
        enclosing_class: Tên lớp bao quanh (nếu có).
        limited_imports: Các dòng import cấp module (loại khỏi repr).
        limited_decorators: Các dòng decorator của scope (loại khỏi repr).
        truncated: True nếu context bị cắt dòng để khớp giới hạn ký tự.
        context_available: True nếu văn bản context khả dụng.
        diagnostic_reasons: Tuple mã lý do chẩn đoán.
        analysis_source: Full source chỉ giữ cho phân tích bằng chứng nội bộ.
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
    analysis_source: SourceReadResult | None = field(default=None, repr=False)


def _paths_match(path1: str, path2: str) -> bool:
    """Kiểm tra hai đường dẫn tương đối có cùng chỉ đến một file đã normalize hay không."""
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
    """Chọn văn bản raw context và metadata cho finding từ source và scope.

    Tham số:
        finding: Finding đã normalize từ static analyzer.
        source: ``SourceReadResult`` bất biến của file mã nguồn đích.
        scope: ``PythonScopeResult`` tùy chọn từ phân tích AST.
        line_window_before: Số dòng trước dòng bắt đầu finding cần lấy (mặc định 10).
        line_window_after: Số dòng sau dòng kết thúc finding cần lấy (mặc định 10).
        max_context_characters: Giới hạn ký tự của context được chọn (mặc định 12.000).

    Trả về:
        ``RawContextSelection`` nội bộ, bất biến.

    Ném lỗi:
        SastTriageError: Khi path không khớp, khoảng dòng hoặc giới hạn không hợp lệ.
    """
    # 1. Validate đầu vào
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

    # 2. Chọn chiến lược theo cây quyết định
    is_sast = finding.finding_type == FindingType.SAST

    has_valid_ast_scope = (
        is_sast
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
        # Chiến lược Line Window dự phòng / mặc định
        strategy = ContextStrategy.LINE_WINDOW

        if is_sast:
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

    # 3. Phòng vệ cắt ngắn và giới hạn ký tự
    finding_lines_text = "".join(source_lines[finding_start - 1 : finding_end])
    finding_char_count = len(finding_lines_text)

    # Trường hợp A: Riêng các dòng finding đã vượt giới hạn ký tự
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
            analysis_source=source,
        )

    # Trường hợp B: Context nằm trong giới hạn ký tự
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
            analysis_source=source,
        )

    # Trường hợp C: Context vượt giới hạn -> Cắt các dòng quanh finding
    diagnostics.append(CONTEXT_TRUNCATED_TO_LIMIT)
    curr_start = start_line
    curr_end = end_line

    while curr_start < finding_start or curr_end > finding_end:
        curr_len = sum(len(source_lines[i]) for i in range(curr_start - 1, curr_end))
        if curr_len <= max_context_characters:
            break

        # Cắt phần trên hoặc dưới
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
        analysis_source=source,
    )
