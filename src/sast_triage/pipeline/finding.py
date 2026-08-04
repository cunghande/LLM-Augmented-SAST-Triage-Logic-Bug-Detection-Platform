"""Per-finding triage pipeline for SAST Triage Platform.

Orchestrates context extraction, sanitization, triage input packaging,
provider execution, policy evaluation, and TriageResult assembly for a single finding.

Security & Isolation Guarantees:
- Transient SanitizedContext is used for LLM triage but NEVER stored in TriageResult.
- Only a safe, high-level context_summary string is saved in TriageResult.
- Operational errors are caught and converted to safe ProcessingError instances.
- Unexpected programming or configuration errors are propagated immediately.
"""

import time
from datetime import UTC, datetime
from pathlib import Path

from sast_triage.context.python_scope import select_python_scope
from sast_triage.context.reader import read_repository_source
from sast_triage.context.sanitizer import (
    KNOWN_PLACEHOLDERS,
    sanitize_context,
)
from sast_triage.context.selection import select_raw_context
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
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
from sast_triage.triage.fake_provider import FakeTriageProvider

# --- Explicit Allowlist for Recoverable Context Layer Errors ---

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
    """Internal helper to build a safe, empty SanitizedContext when extraction fails."""
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
    """Internal helper to construct a safe, deterministic context summary string."""
    if not context.context_available:
        return "Context unavailable."

    parts: list[str] = [f"{context.context_strategy.value} context"]

    if context.context_start_line is not None and context.context_end_line is not None:
        parts.append(f"lines {context.context_start_line}-{context.context_end_line}")

    if context.enclosing_class:
        parts.append(f"class {context.enclosing_class}")

    if context.enclosing_function:
        parts.append(f"function {context.enclosing_function}")

    if context.truncated:
        parts.append("truncated")

    return ", ".join(parts) + "."


def triage_finding(
    finding: NormalizedFinding,
    repository_root: Path,
    provider: FakeTriageProvider,
    *,
    prompt_version: str = "triage-prompt-v1",
    output_schema_version: str = "triage-decision-v1",
    prompt_type: str = "fake.default",
    line_window_before: int = 10,
    line_window_after: int = 10,
    max_file_size_bytes: int = 1_048_576,
    max_scope_lines: int = 120,
    max_context_characters: int = 12_000,
    max_import_lines: int = 20,
    forbidden_values: tuple[str, ...] = (),
) -> TriageResult:
    """Triage a single NormalizedFinding through context extraction, LLM triage, and policy.

    Args:
        finding: Target NormalizedFinding.
        repository_root: Absolute Path to the repository root directory.
        provider: FakeTriageProvider instance for LLM simulation.
        prompt_version: Prompt version string.
        output_schema_version: Output schema version string.
        prompt_type: Prompt type test control signal.
        line_window_before: Lines to include before finding line.
        line_window_after: Lines to include after finding line.
        max_file_size_bytes: Maximum allowed source file size in bytes.
        max_scope_lines: Maximum scope lines for AST analysis.
        max_context_characters: Maximum context snippet characters.
        max_import_lines: Maximum import lines.
        forbidden_values: Optional secret strings that must be redacted.

    Returns:
        A frozen, validated TriageResult Pydantic model.

    Raises:
        SastTriageError: On invalid configuration parameters or unrecoverable contract errors.
    """
    start_perf = time.perf_counter()
    processed_at = datetime.now(UTC)

    # 1. Configuration Parameter Validation
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
    if max_scope_lines <= 0:
        raise SastTriageError(
            safe_message="max_scope_lines must be greater than 0.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if max_context_characters <= 0:
        raise SastTriageError(
            safe_message="max_context_characters must be greater than 0.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )
    if max_import_lines < 0:
        raise SastTriageError(
            safe_message="max_import_lines must be non-negative.",
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

    processing_errors: list[ProcessingError] = []
    sanitized: SanitizedContext | None = None

    # 2. Context Extraction Steps
    try:
        # Step 2a: Read source file
        src_res = read_repository_source(
            repository_root,
            finding.file_path,
            max_file_size_bytes=max_file_size_bytes,
        )

        # Step 2b: AST Scope Analysis
        scope_res = select_python_scope(
            src_res,
            finding.start_line,
            finding.end_line,
            max_scope_lines=max_scope_lines,
            max_import_lines=max_import_lines,
        )

        # Step 2c: Raw Context Selection
        raw_ctx = select_raw_context(
            finding,
            src_res,
            scope=scope_res,
            line_window_before=line_window_before,
            line_window_after=line_window_after,
            max_context_characters=max_context_characters,
        )

        # Step 2d: Context Sanitization
        sanitized = sanitize_context(finding, raw_ctx, forbidden_values=forbidden_values)

        # Check if sanitizer produced an unavailable context with CONTEXT_SANITIZATION_FAILED
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
            # Unrecoverable contract/configuration error -> propagate
            raise

    # Guarantee sanitized is present
    if sanitized is None:
        sanitized = _make_unavailable_context(finding, MissingContextReason.SOURCE_FILE_NOT_FOUND)

    # 3. Triage Input Packaging & Provider Execution
    triage_dec: TriageDecision | None = None
    triage_input = TriageInput(
        finding=finding,
        context=sanitized,
        prompt_version=prompt_version,
        output_schema_version=output_schema_version,
        prompt_type=prompt_type,
    )

    try:
        triage_dec = provider.triage(triage_input)
    except SastTriageError as exc:
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

    # 4. Policy Evaluation
    policy_dec: PolicyDecision | None = None
    try:
        policy_dec = apply_policy(
            finding,
            sanitized,
            triage_dec,
            processing_errors=tuple(processing_errors),
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

    # 5. Build Context Summary & Assemble TriageResult
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
    )
