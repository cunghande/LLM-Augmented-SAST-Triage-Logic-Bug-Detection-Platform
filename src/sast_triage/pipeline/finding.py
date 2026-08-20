"""Pipeline triage theo từng finding cho SAST Triage Platform.

Điều phối trích xuất context, sanitize, đóng gói triage input, chạy provider,
đánh giá policy và tổng hợp TriageResult cho một finding.

Cam kết bảo mật và cô lập:
- SanitizedContext tạm thời được dùng cho LLM triage nhưng KHÔNG BAO GIỜ lưu trong TriageResult.
- Chỉ chuỗi context_summary cấp cao, an toàn được lưu trong TriageResult.
- Lỗi vận hành được bắt và đổi thành ProcessingError an toàn.
- Lỗi lập trình hoặc cấu hình bất ngờ được lan truyền ngay.
"""

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from sast_triage.analysis.base import AnalysisBackend
from sast_triage.context.evidence_service import build_evidence_context
from sast_triage.context.reader import read_repository_source
from sast_triage.context.sanitizer import (
    KNOWN_PLACEHOLDERS,
    sanitize_context,
)
from sast_triage.context.selection import select_raw_context
from sast_triage.errors import SastTriageError
from sast_triage.logic.index import LogicFindingIndex
from sast_triage.models import (
    ArtifactRepositoryMatch,
    ContextStrategy,
    FindingType,
    MissingContextReason,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    PolicyDecision,
    ProcessingError,
    ProcessingStage,
    SanitizedContext,
    SourceKind,
    TriageDecision,
    TriageInput,
    TriageResult,
)
from sast_triage.policy.engine import POLICY_VERSION, apply_policy

# --- Allowlist tường minh cho các lỗi context layer có thể phục hồi ---

RECOVERABLE_CONTEXT_ERROR_MAP: dict[str, MissingContextReason] = {
    "CONTEXT_REPOSITORY_NOT_FOUND": MissingContextReason.SOURCE_FILE_NOT_FOUND,
    "CONTEXT_REPOSITORY_NOT_DIRECTORY": MissingContextReason.SOURCE_FILE_NOT_FOUND,
    "CONTEXT_INVALID_SOURCE_PATH": MissingContextReason.SOURCE_PATH_OUTSIDE_REPOSITORY,
    "CONTEXT_PATH_OUTSIDE_REPOSITORY": MissingContextReason.SOURCE_PATH_OUTSIDE_REPOSITORY,
    "CONTEXT_SOURCE_FILE_NOT_FOUND": MissingContextReason.SOURCE_FILE_NOT_FOUND,
    "CONTEXT_SOURCE_NOT_REGULAR_FILE": MissingContextReason.SOURCE_FILE_NOT_FOUND,
    "CONTEXT_SOURCE_FILE_TOO_LARGE": MissingContextReason.SOURCE_FILE_TOO_LARGE,
    "CONTEXT_SOURCE_UNSUPPORTED_ENCODING": MissingContextReason.SOURCE_FILE_UNSUPPORTED_ENCODING,
    "CONTEXT_SOURCE_READ_ERROR": MissingContextReason.SOURCE_FILE_READ_ERROR,
    "CONTEXT_INVALID_FINDING_LINE_RANGE": MissingContextReason.INVALID_FINDING_LINE_RANGE,
}


def _make_unavailable_context(
    finding: NormalizedFinding,
    missing_reason: MissingContextReason,
) -> SanitizedContext:
    """Helper nội bộ tạo SanitizedContext rỗng, an toàn khi trích xuất thất bại."""
    return SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet=None,
        context_strategy=ContextStrategy.UNAVAILABLE,
        context_start_line=None,
        context_end_line=None,
        finding_start_line=finding.start_line,
        finding_end_line=finding.end_line,
        enclosing_function=None,
        enclosing_class=None,
        limited_imports=(),
        limited_decorators=(),
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=False,
        missing_context_reasons=[missing_reason],
        redactions_applied=0,
        redaction_types=(),
        truncated=False,
    )


def _build_context_summary(context: SanitizedContext) -> str:
    """Tạo tóm tắt ngữ cảnh tiếng Việt, an toàn và ổn định."""
    if not context.context_available:
        return "Không có ngữ cảnh khả dụng."

    try:
        projected = json.loads(context.sanitized_snippet or "{}")
    except json.JSONDecodeError:
        projected = {}
    if isinstance(projected, dict) and "JOERN_CPG" in projected.get("provenance", []):
        source = projected.get("source")
        sink = projected.get("sink")
        taint_path = projected.get("taint_path")
        controls = projected.get("security_controls")
        completeness = projected.get("context_completeness")
        source_location = "chưa xác định"
        sink_location = "chưa xác định"
        path_text = "chưa có đường đi đầy đủ"
        control_names: list[str] = []
        if isinstance(source, dict):
            source_location = f"{source.get('file_path')}:{source.get('line')}"
        if isinstance(sink, dict):
            sink_location = f"{sink.get('file_path')}:{sink.get('line')}"
        if isinstance(taint_path, dict) and isinstance(taint_path.get("steps"), list):
            safe_steps = []
            for step in taint_path["steps"][:10]:
                if isinstance(step, dict):
                    safe_steps.append(f"{step.get('file_path')}:{step.get('line')}")
            if safe_steps:
                path_text = " → ".join(safe_steps)
        if isinstance(controls, dict):
            for group in controls.values():
                if isinstance(group, list):
                    control_names.extend(
                        str(item.get("symbol"))
                        for item in group
                        if isinstance(item, dict) and item.get("symbol")
                    )
        status = "partial"
        stop_reason = "INSUFFICIENT_EVIDENCE"
        if isinstance(completeness, dict):
            status = str(completeness.get("status", status))
            limitations = completeness.get("limitations", [])
            if isinstance(limitations, list):
                reasons = [
                    str(item)
                    for item in limitations
                    if str(item).startswith(("AGENT_", "MAX_TOOL_CALLS"))
                ]
                if reasons:
                    stop_reason = reasons[-1]
            if status == "complete" and stop_reason == "INSUFFICIENT_EVIDENCE":
                stop_reason = "EVIDENCE_SUFFICIENT"
        return (
            f"Joern CPG evidence {status}; source {source_location}; sink {sink_location}; "
            f"đường source–sink {path_text}; control "
            f"{', '.join(dict.fromkeys(control_names)) if control_names else 'không tìm thấy'}; "
            f"Agent dừng vì {stop_reason}."
        )

    parts: list[str] = [f"Ngữ cảnh {context.context_strategy.value}"]

    if context.context_start_line is not None and context.context_end_line is not None:
        parts.append(f"dòng {context.context_start_line}-{context.context_end_line}")

    if context.enclosing_class:
        parts.append(f"lớp {context.enclosing_class}")

    if context.enclosing_function:
        parts.append(f"hàm {context.enclosing_function}")

    if context.truncated:
        parts.append("đã bị cắt bớt")

    return ", ".join(parts) + "."


def triage_finding(
    finding: NormalizedFinding,
    repository_root: Path,
    provider: object,
    *,
    prompt_version: str = "triage-prompt-v13",
    output_schema_version: str = "triage-decision-v1",
    prompt_type: str = "fake.default",
    line_window_before: int = 60,
    line_window_after: int = 60,
    max_file_size_bytes: int = 1_048_576,
    max_context_characters: int = 12_000,
    forbidden_values: tuple[str, ...] = (),
    initial_processing_errors: tuple[ProcessingError, ...] = (),
    artifact_repository_match: ArtifactRepositoryMatch = ArtifactRepositoryMatch.VERIFIED,
    logic_index: LogicFindingIndex | None = None,
    analysis_backend: AnalysisBackend | None = None,
) -> TriageResult:
    """Triage một NormalizedFinding qua trích xuất context, LLM triage và policy.

    Tham số:
        finding: Target NormalizedFinding.
        repository_root: Absolute Path to the repository root directory.
        provider: FakeTriageProvider instance for LLM simulation.
        prompt_version: Prompt version string.
        output_schema_version: Output schema version string.
        prompt_type: Prompt type test control signal.
        line_window_before: Lines to include before finding line.
        line_window_after: Lines to include after finding line.
        max_file_size_bytes: Maximum allowed source file size in bytes.
        max_context_characters: Maximum context snippet characters.
        forbidden_values: Optional secret strings that must be redacted.
        initial_processing_errors: Optional tuple of parser diagnostics linked to this finding.

    Trả về:
        Model Pydantic TriageResult bất biến, đã validate.

    Ném lỗi:
        SastTriageError: Khi tham số cấu hình không hợp lệ hoặc lỗi xử lý ban đầu không khớp.
    """
    start_perf = time.perf_counter()
    processed_at = datetime.now(UTC)

    # 1. Validate tham số cấu hình
    if not prompt_version or not prompt_version.strip():
        raise SastTriageError(
            safe_message="prompt_version must be a non-empty string.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if not output_schema_version or not output_schema_version.strip():
        raise SastTriageError(
            safe_message="output_schema_version must be a non-empty string.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if not prompt_type or not prompt_type.strip():
        raise SastTriageError(
            safe_message="prompt_type must be a non-empty string.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if max_file_size_bytes <= 0:
        raise SastTriageError(
            safe_message="max_file_size_bytes must be greater than 0.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if max_context_characters <= 0:
        raise SastTriageError(
            safe_message="max_context_characters must be greater than 0.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if line_window_before < 0 or line_window_after < 0:
        raise SastTriageError(
            safe_message="line_window_before and line_window_after must be non-negative.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )

    for fv in forbidden_values:
        if not fv or not fv.strip() or fv in KNOWN_PLACEHOLDERS or fv.startswith("<REDACTED_"):
            raise SastTriageError(
                safe_message="forbidden_values elements must be valid non-placeholder strings.",
                error_code="PIPELINE_INVALID_CONFIGURATION",
                retryable=False,
            )

    for err in initial_processing_errors:
        if err.finding_id is None or err.finding_id != finding.finding_instance_id:
            raise SastTriageError(
                safe_message="Initial processing error finding_id mismatch.",
                error_code="PIPELINE_PROCESSING_ERROR_MISMATCH",
                retryable=False,
            )
        if err.scanner is not None and err.scanner != finding.scanner:
            raise SastTriageError(
                safe_message="Initial processing error scanner mismatch.",
                error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                retryable=False,
            )

    processing_errors: list[ProcessingError] = list(initial_processing_errors)
    sanitized: SanitizedContext | None = None

    # 2. Các bước trích xuất context
    try:
        # Bước 2a: Đọc file mã nguồn
        src_res = read_repository_source(
            repository_root,
            finding.file_path,
            max_file_size_bytes=max_file_size_bytes,
        )

        # Bước 2b: Chọn bounded raw context; Joern owns structural analysis.
        raw_ctx = select_raw_context(
            finding,
            src_res,
            line_window_before=line_window_before,
            line_window_after=line_window_after,
            max_context_characters=max_context_characters,
        )

        # Bước 2c: Sanitize Context
        sanitized = sanitize_context(
            finding,
            raw_ctx,
            forbidden_values=forbidden_values,
        )
        if finding.finding_type == FindingType.SAST and sanitized.context_available:
            sanitized = build_evidence_context(
                finding,
                sanitized,
                logic_index=logic_index,
                analysis_backend=analysis_backend,
            ).context

        # Kiểm tra sanitizer có tạo context không khả dụng với CONTEXT_SANITIZATION_FAILED không
        if (
            not sanitized.context_available
            and MissingContextReason.CONTEXT_SANITIZATION_FAILED in sanitized.missing_context_reasons
        ):
            processing_errors.append(
                ProcessingError(
                    finding_id=finding.finding_instance_id,
                    scanner=finding.scanner,
                    stage=ProcessingStage.SANITIZE,
                    error_code="CONTEXT_SANITIZATION_FAILED",
                    safe_message="Context sanitization could not produce a usable context.",
                    retryable=False,
                )
            )

    except SastTriageError as exc:
        if exc.error_code in RECOVERABLE_CONTEXT_ERROR_MAP:
            mapped_reason = RECOVERABLE_CONTEXT_ERROR_MAP[exc.error_code]
            processing_errors.append(
                ProcessingError(
                    finding_id=finding.finding_instance_id,
                    scanner=finding.scanner,
                    stage=ProcessingStage.CONTEXT,
                    error_code=exc.error_code,
                    safe_message=exc.safe_message,
                    retryable=exc.retryable,
                )
            )
            sanitized = _make_unavailable_context(finding, mapped_reason)
        else:
            # Lỗi contract/cấu hình không thể phục hồi -> lan truyền
            raise

    # Bảo đảm sanitized luôn tồn tại
    if sanitized is None:
        sanitized = _make_unavailable_context(finding, MissingContextReason.SOURCE_FILE_NOT_FOUND)

    # 3. Đóng gói Triage Input và chạy Provider
    triage_dec: TriageDecision | None = None
    triage_input = TriageInput(
        finding=finding,
        context=sanitized,
        prompt_version=prompt_version,
        output_schema_version=output_schema_version,
        prompt_type=prompt_type,
    )
    triage_input_digest = hashlib.sha256(
        triage_input.model_dump_json().encode("utf-8")
    ).hexdigest()

    provider_start_perf = time.perf_counter()
    try:
        triage_dec = provider.triage(triage_input)
    except SastTriageError as exc:
        if exc.error_code in {
            "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED",
            "TRIAGE_PROVIDER_MODAL_AUTH_ERROR",
        }:
            raise
        processing_errors.append(
            ProcessingError(
                finding_id=finding.finding_instance_id,
                scanner=finding.scanner,
                stage=ProcessingStage.TRIAGE,
                error_code=exc.error_code,
                safe_message=exc.safe_message,
                retryable=exc.retryable,
            )
        )
        triage_dec = None
    provider_duration_ms = max(
        0,
        int((time.perf_counter() - provider_start_perf) * 1000),
    )

    # 4. Đánh giá Policy
    policy_dec: PolicyDecision | None = None
    try:
        policy_dec = apply_policy(
            finding,
            sanitized,
            triage_dec,
            processing_errors=tuple(processing_errors),
            artifact_repository_match=artifact_repository_match,
        )
    except SastTriageError as exc:
        processing_errors.append(
            ProcessingError(
                finding_id=finding.finding_instance_id,
                scanner=finding.scanner,
                stage=ProcessingStage.POLICY,
                error_code=exc.error_code,
                safe_message=exc.safe_message,
                retryable=exc.retryable,
            )
        )
        policy_dec = PolicyDecision(
            action=PolicyAction.TRIAGE_ERROR,
            reasons=["Policy evaluation failed."],
            policy_version=POLICY_VERSION,
            escalated=False,
            escalation_reason=None,
        )

    # 5. Tạo Context Summary và tổng hợp TriageResult
    summary_str = _build_context_summary(sanitized)
    end_perf = time.perf_counter()
    duration_ms = max(0, int((end_perf - start_perf) * 1000))

    return TriageResult(
        finding=finding,
        context_summary=summary_str,
        triage_decision=triage_dec,
        policy_decision=policy_dec,
        processing_errors=processing_errors,
        processed_at=processed_at,
        processing_duration_ms=duration_ms,
        provider_duration_ms=provider_duration_ms,
        triage_input_digest=triage_input_digest,
    )
