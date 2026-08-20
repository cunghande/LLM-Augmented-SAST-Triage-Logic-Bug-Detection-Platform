"""Các model bằng chứng có kiểu, nội bộ, cho phân tích ngữ cảnh có giới hạn.

Các model này không phải model domain/báo cáo công khai. Mọi văn bản mã nguồn
lưu tại đây phải được làm sạch trước khi package được dựng cho provider.
"""

from dataclasses import dataclass, field
from enum import Enum


class EvidenceStatus(str, Enum):
    """Trạng thái đầy đủ của bằng chứng ngữ cảnh."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """Các dữ kiện finding đã allowlist trong bằng chứng gửi provider."""

    rule_id: str
    category: str | None
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int | None


@dataclass(frozen=True, slots=True)
class RelevantCodeEvidence:
    """Mã đã làm sạch được chọn quanh finding."""

    scope_type: str
    function_name: str | None
    class_name: str | None
    start_line: int | None
    end_line: int | None
    code: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    """Mô tả cấu trúc an toàn của một nguồn dữ liệu tiềm năng."""

    expression: str
    source_type: str
    user_controlled: bool
    file_path: str
    line: int | None
    confidence: str


@dataclass(frozen=True, slots=True)
class SinkEvidence:
    """Mô tả cấu trúc an toàn của một sink nhạy cảm bảo mật."""

    expression: str
    sink_type: str
    dangerous_argument: str | None
    dangerous_conditions: tuple[str, ...]
    file_path: str
    line: int | None


@dataclass(frozen=True, slots=True)
class TaintStep:
    """Một bước an toàn từ source đến sink."""

    order: int
    kind: str
    expression: str
    function_id: str | None
    file_path: str
    line: int | None


@dataclass(frozen=True, slots=True)
class TaintPathEvidence:
    """Kết quả taint nội bộ hoặc liên hàm có giới hạn."""

    path_type: str
    steps: tuple[TaintStep, ...]
    source_reaches_sink: bool | None
    complete: bool


@dataclass(frozen=True, slots=True)
class SecurityControlEvidence:
    """Guard, validation, sanitizer hoặc API an toàn liên quan đến đường taint."""

    symbol: str
    control_type: str
    on_taint_path: bool
    protects_target: bool | None
    effective: bool | None
    confidence: str


@dataclass(frozen=True, slots=True)
class ContextCompleteness:
    """Các dữ kiện tường minh về đủ ngữ cảnh mà cổng kiểm tra sử dụng."""

    status: EvidenceStatus
    source_resolved: bool
    sink_resolved: bool
    taint_path_complete: bool
    call_chain_complete: bool
    reachability_resolved: bool
    unresolved_symbols: tuple[str, ...] = ()
    missing_information: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    """Bằng chứng nội bộ tổng hợp từ AST và phân tích dataflow có giới hạn."""

    finding_id: str
    finding: FindingEvidence
    relevant_code: RelevantCodeEvidence
    source: SourceEvidence | None
    sink: SinkEvidence | None
    taint_path: TaintPathEvidence
    security_controls: tuple[SecurityControlEvidence, ...]
    context_completeness: ContextCompleteness
    provenance: tuple[str, ...] = ()
