"""Các wrapper tool có giới hạn trên core evidence engine dùng chung."""

from __future__ import annotations

from sast_triage.context.evidence_engine import CoreAnalysisEngine
from sast_triage.context.evidence_models import ToolResult, ToolStatus


class EvidenceToolbox:
    """Cung cấp các tool phân tích cấu trúc an toàn với ngân sách theo finding."""

    def __init__(
        self,
        engine: CoreAnalysisEngine,
        *,
        max_tool_calls: int = 5,
        max_depth: int = 5,
    ) -> None:
        """Tạo toolbox với giới hạn cứng số lần gọi và độ sâu duyệt."""
        if max_tool_calls < 1 or max_tool_calls > 5:
            raise ValueError("max_tool_calls must be between 1 and 5")
        if max_depth < 1 or max_depth > 5:
            raise ValueError("max_depth must be between 1 and 5")
        self._engine = engine
        self._max_tool_calls = max_tool_calls
        self._max_depth = max_depth
        self._calls = 0

    @property
    def calls_used(self) -> int:
        """Trả về số lần gọi tool được chấp nhận."""
        return self._calls

    def _begin(self, requested_depth: int | None = None) -> ToolResult | None:
        if self._calls >= self._max_tool_calls:
            return ToolResult(
                status=ToolStatus.ERROR,
                complete=False,
                evidence={},
                limitations=("MAX_TOOL_CALLS_REACHED",),
            )
        if requested_depth is not None and (
            requested_depth < 1
            or requested_depth > self._max_depth
            or requested_depth > 5
        ):
            return ToolResult(
                status=ToolStatus.ERROR,
                complete=False,
                evidence={},
                limitations=("INVALID_OR_EXCESSIVE_MAX_DEPTH",),
            )
        self._calls += 1
        return None

    def trace_taint_path(self, finding_id: str, max_depth: int) -> ToolResult:
        """Mở rộng đường taint đích qua các caller có giới hạn."""
        rejected = self._begin(max_depth)
        if rejected:
            return rejected
        if finding_id != self._engine.finding.finding_instance_id:
            return ToolResult(
                status=ToolStatus.ERROR,
                complete=False,
                evidence={},
                limitations=("FINDING_ID_MISMATCH",),
            )
        evidence = self._engine.build_evidence(expand_callers=max_depth > 0)
        path = evidence.taint_path
        return ToolResult(
            status=ToolStatus.SUCCESS if path.complete else ToolStatus.PARTIAL,
            complete=path.complete,
            evidence={
                "path_type": path.path_type,
                "source_reaches_sink": path.source_reaches_sink,
                "steps": [
                    {
                        "order": step.order,
                        "kind": step.kind,
                        "expression": step.expression,
                        "function_id": step.function_id,
                        "file_path": step.file_path,
                        "line": step.line,
                    }
                    for step in path.steps
                ],
            },
            limitations=evidence.context_completeness.limitations,
            provenance=evidence.provenance,
        )

    def find_callers(self, function_id: str, max_depth: int) -> ToolResult:
        """Tìm caller cùng đơn vị phân tích của một hàm, trong giới hạn."""
        rejected = self._begin(max_depth)
        if rejected:
            return rejected
        callers, complete = self._engine.caller_evidence(function_id)
        return ToolResult(
            status=ToolStatus.SUCCESS if complete else ToolStatus.PARTIAL,
            complete=complete,
            evidence={"function_id": function_id, "callers": callers},
            limitations=() if complete else ("NO_RESOLVABLE_CALLER",),
            provenance=(f"python_ast:{self._engine.finding.file_path}",),
        )

    def find_entrypoint_path(self, function_id: str, max_depth: int) -> ToolResult:
        """Trả về đường caller có giới hạn, dùng được làm bằng chứng entrypoint."""
        rejected = self._begin(max_depth)
        if rejected:
            return rejected
        callers, complete = self._engine.caller_evidence(function_id)
        path = [caller["function_id"] for caller in callers[:max_depth]]
        if complete:
            path.append(function_id)
        return ToolResult(
            status=ToolStatus.SUCCESS if complete else ToolStatus.PARTIAL,
            complete=complete,
            evidence={"function_id": function_id, "entrypoint_path": path},
            limitations=() if complete else ("ENTRYPOINT_NOT_RESOLVED",),
            provenance=(f"python_ast:{self._engine.finding.file_path}",),
        )

    def inspect_symbol(self, qualified_name: str) -> ToolResult:
        """Kiểm tra signature và tên lời gọi của symbol mà không trả về mã nguồn."""
        rejected = self._begin()
        if rejected:
            return rejected
        evidence, complete = self._engine.symbol_evidence(qualified_name)
        return ToolResult(
            status=ToolStatus.SUCCESS if complete else ToolStatus.PARTIAL,
            complete=complete,
            evidence=evidence,
            limitations=() if complete else ("SYMBOL_NOT_RESOLVED",),
            provenance=(f"python_ast:{self._engine.finding.file_path}",),
        )

    def resolve_symbol_value(self, symbol: str, file_path: str) -> ToolResult:
        """Resolve một symbol theo cấu trúc mà không làm lộ literal value."""
        rejected = self._begin()
        if rejected:
            return rejected
        if file_path != self._engine.finding.file_path:
            return ToolResult(
                status=ToolStatus.ERROR,
                complete=False,
                evidence={},
                limitations=("FILE_OUTSIDE_ANALYSIS_UNIT",),
            )
        evidence, complete = self._engine.symbol_value_evidence(symbol)
        return ToolResult(
            status=ToolStatus.SUCCESS if complete else ToolStatus.PARTIAL,
            complete=complete,
            evidence=evidence,
            limitations=() if complete else ("SYMBOL_VALUE_NOT_RESOLVED",),
            provenance=(f"python_ast:{file_path}",),
        )

    def analyze_security_control(
        self,
        symbol: str,
        vulnerability_type: str,
    ) -> ToolResult:
        """Phân loại control tự tạo bằng AST engine dùng chung."""
        rejected = self._begin()
        if rejected:
            return rejected
        effective = self._engine.analyze_security_control(symbol)
        complete = effective is not None
        return ToolResult(
            status=ToolStatus.SUCCESS if complete else ToolStatus.PARTIAL,
            complete=complete,
            evidence={
                "symbol": symbol,
                "vulnerability_type": vulnerability_type,
                "effective": effective,
            },
            limitations=() if complete else ("CUSTOM_CONTROL_NOT_RESOLVED",),
            provenance=(f"python_ast:{self._engine.finding.file_path}",),
        )
