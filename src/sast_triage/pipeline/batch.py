"""Pipeline batch triage nhiều finding cho SAST Triage Platform.

Orchestrates sequential per-finding triage over Semgrep and Gitleaks parser results,
manages scanner attempted/succeeded state, isolates operational errors, and assembles
RunMetadata and BatchResult models.

Security & Invariant Guarantees:
- Validates scanner result identity before processing findings.
- Enforces fail-closed scanner succeeded semantics (only known record-level parse errors allow succeeded status).
- Never serializes absolute repository paths, raw source text, or secret canaries.
- Purely functional metadata assembly without mutating input collections.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sast_triage import __version__ as TOOL_VERSION
from sast_triage.analysis.base import AnalysisBackend, AnalysisIdentity
from sast_triage.context.repository_index import RepositoryEvidenceIndex
from sast_triage.context.sanitizer import KNOWN_PLACEHOLDERS
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    BatchResult,
    FindingType,
    NormalizedFinding,
    PolicyAction,
    ProcessingError,
    ProcessingStage,
    RunMetadata,
    ScannerParseResult,
    ScannerType,
    TriageResult,
    _is_absolute_path,
)
from sast_triage.pipeline.finding import triage_finding
from sast_triage.policy.engine import POLICY_VERSION

# Mã lỗi parse cấp record KHÔNG làm scanner parse thất bại
RECORD_LEVEL_PARSE_ERROR_CODES: set[str] = {
    "PARSE_RECORD_MISSING_FIELD",
    "PARSE_RECORD_INVALID_FIELD",
}


def _validate_scanner_result_identity(
    semgrep_result: ScannerParseResult | None,
    gitleaks_result: ScannerParseResult | None,
    module2_result: ScannerParseResult | None,
) -> None:
    """Validate nội dung ScannerParseResult khớp scanner identity đã gán."""
    if semgrep_result is not None:
        for finding in semgrep_result.findings:
            if finding.scanner != ScannerType.SEMGREP or finding.finding_type != FindingType.SAST:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )
        for err in semgrep_result.errors:
            if err.scanner is not None and err.scanner != ScannerType.SEMGREP:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )

    if gitleaks_result is not None:
        for finding in gitleaks_result.findings:
            if finding.scanner != ScannerType.GITLEAKS or finding.finding_type != FindingType.SECRET:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )
        for err in gitleaks_result.errors:
            if err.scanner is not None and err.scanner != ScannerType.GITLEAKS:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )

    if module2_result is not None:
        for finding in module2_result.findings:
            if finding.scanner != ScannerType.MODULE2 or finding.finding_type != FindingType.SAST:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )
        for err in module2_result.errors:
            if err.scanner is not None and err.scanner != ScannerType.MODULE2:
                raise SastTriageError(
                    safe_message="ScannerParseResult contents do not match expected scanner slot identity.",
                    error_code="PIPELINE_SCANNER_RESULT_MISMATCH",
                    retryable=False,
                )


def _has_artifact_level_parse_error(errors: tuple[ProcessingError, ...]) -> bool:
    """Trả về True nếu errors có lỗi PARSE cấp artifact."""
    for err in errors:
        if err.stage == ProcessingStage.PARSE and err.error_code not in RECORD_LEVEL_PARSE_ERROR_CODES:
            return True
    return False


def triage_batch(
    repository_root: Path,
    provider: object,
    *,
    semgrep_result: ScannerParseResult | None = None,
    gitleaks_result: ScannerParseResult | None = None,
    module2_result: ScannerParseResult | None = None,
    repository_index: RepositoryEvidenceIndex | None = None,
    analysis_backend: AnalysisBackend | None = None,
    analysis_identity: AnalysisIdentity | None = None,
    repository_identifier: str,
    commit_sha: str | None = None,
    working_tree_state: str | None = None,
    artifact_repository_match: ArtifactRepositoryMatch = ArtifactRepositoryMatch.VERIFIED,
    prompt_version: str = "triage-prompt-v11",
    output_schema_version: str = "triage-decision-v1",
    prompt_type: str = "fake.default",
    line_window_before: int = 10,
    line_window_after: int = 10,
    max_file_size_bytes: int = 1_048_576,
    max_scope_lines: int = 120,
    max_context_characters: int = 12_000,
    max_import_lines: int = 20,
    forbidden_values: tuple[str, ...] = (),
    scanner_versions: dict[str, str | None] | None = None,
    scanner_config_ids: dict[str, str | None] | None = None,
    input_artifact_hashes: dict[str, str | None] | None = None,
    cli_mode: str = "triage",
    existing_results: tuple[TriageResult, ...] = (),
    progress_callback: Callable[[tuple[TriageResult, ...]], None] | None = None,
    triage_provider_name: str | None = None,
    model_version: str | None = None,
) -> BatchResult:
    """Triage một batch finding tĩnh từ kết quả scanner Semgrep và Gitleaks.

    Tham số:
        repository_root: Absolute Path to the repository root directory.
        provider: FakeTriageProvider instance for LLM simulation.
        semgrep_result: Optional ScannerParseResult for Semgrep SAST findings.
        gitleaks_result: Optional ScannerParseResult for Gitleaks secret findings.
        repository_identifier: Logical repository identifier string.
        commit_sha: Optional commit SHA string.
        working_tree_state: Optional working tree state ("clean", "dirty", "unknown").
        artifact_repository_match: Result of repository constraint verification.
        prompt_version: Prompt version string.
        output_schema_version: Output schema version string.
        prompt_type: Test control signal for FakeTriageProvider.
        line_window_before: Lines to include before finding line.
        line_window_after: Lines to include after finding line.
        max_file_size_bytes: Maximum allowed source file size in bytes.
        max_scope_lines: Maximum scope lines for AST analysis.
        max_context_characters: Maximum context snippet characters.
        max_import_lines: Maximum import lines.
        forbidden_values: Optional secret strings that must be redacted.
        scanner_versions: Optional mapping of scanner name to version.
        scanner_config_ids: Optional mapping of scanner name to config ID.
        input_artifact_hashes: Optional mapping of scanner name to artifact SHA256 hash.
        cli_mode: CLI execution mode recorded in run metadata.

    Trả về:
        BatchResult bất biến chứa RunMetadata, TriageResults và ProcessingErrors.

    Ném lỗi:
        SastTriageError: Khi tham số cấu hình không hợp lệ hoặc scanner identity không khớp.
    """
    # 1. Validate trước cấu hình và identity
    if (
        not repository_identifier
        or not repository_identifier.strip()
        or _is_absolute_path(repository_identifier)
        or Path(repository_identifier).is_absolute()
    ):
        raise SastTriageError(
            safe_message="repository_identifier must be a non-empty relative identifier string.",
            error_code="PIPELINE_INVALID_CONFIGURATION",
            retryable=False,
        )

    for ctrl_char in ("\n", "\r", "\t", "\0"):
        if ctrl_char in repository_identifier:
            raise SastTriageError(
                safe_message="repository_identifier must not contain control characters.",
                error_code="PIPELINE_INVALID_CONFIGURATION",
                retryable=False,
            )

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

    # Validate identity của scanner slot
    _validate_scanner_result_identity(semgrep_result, gitleaks_result, module2_result)

    # Ghi timestamp started_at sau khi validate trước thành công
    started_at = datetime.now(UTC)

    # 2. Xác định scanner đã thử / thành công và thu thập lỗi parser
    scanners_attempted: list[ScannerType] = []
    scanners_succeeded: list[ScannerType] = []
    scanner_errors: list[ProcessingError] = []

    findings_to_process: list[NormalizedFinding] = []

    if semgrep_result is not None:
        scanners_attempted.append(ScannerType.SEMGREP)
        scanner_errors.extend(list(semgrep_result.errors))
        if not _has_artifact_level_parse_error(semgrep_result.errors):
            scanners_succeeded.append(ScannerType.SEMGREP)
        findings_to_process.extend(semgrep_result.findings)

    if gitleaks_result is not None:
        scanners_attempted.append(ScannerType.GITLEAKS)
        scanner_errors.extend(list(gitleaks_result.errors))
        if not _has_artifact_level_parse_error(gitleaks_result.errors):
            scanners_succeeded.append(ScannerType.GITLEAKS)
        findings_to_process.extend(gitleaks_result.findings)

    if module2_result is not None:
        scanners_attempted.append(ScannerType.MODULE2)
        scanner_errors.extend(list(module2_result.errors))
        if not _has_artifact_level_parse_error(module2_result.errors):
            scanners_succeeded.append(ScannerType.MODULE2)
        findings_to_process.extend(module2_result.findings)

    # 3. Tạo Error Index theo finding_id và vòng triage tuần tự từng finding
    errors_by_finding_id: dict[str, list[ProcessingError]] = {}
    for err in scanner_errors:
        if err.finding_id is not None:
            errors_by_finding_id.setdefault(err.finding_id, []).append(err)

    finding_by_id = {
        finding.finding_instance_id: finding for finding in findings_to_process
    }
    result_by_id: dict[str, TriageResult] = {}
    for existing in existing_results:
        finding_id = existing.finding.finding_instance_id
        current_finding = finding_by_id.get(finding_id)
        if current_finding is None or current_finding != existing.finding or finding_id in result_by_id:
            raise SastTriageError(
                safe_message="Existing triage result does not match the current finding batch.",
                error_code="PIPELINE_RESUME_RESULT_MISMATCH",
                retryable=False,
            )
        result_by_id[finding_id] = existing

    for finding in findings_to_process:
        if finding.finding_instance_id in result_by_id:
            continue
        initial_errors = tuple(errors_by_finding_id.get(finding.finding_instance_id, ()))
        # Gọi pipeline từng finding; không bắt exception (lan truyền lỗi cấu hình/contract)
        result = triage_finding(
            finding,
            repository_root,
            provider,
            prompt_version=prompt_version,
            output_schema_version=output_schema_version,
            prompt_type=prompt_type,
            line_window_before=line_window_before,
            line_window_after=line_window_after,
            max_file_size_bytes=max_file_size_bytes,
            max_scope_lines=max_scope_lines,
            max_context_characters=max_context_characters,
            max_import_lines=max_import_lines,
            forbidden_values=forbidden_values,
            initial_processing_errors=initial_errors,
            artifact_repository_match=artifact_repository_match,
            repository_index=repository_index,
            analysis_backend=analysis_backend,
        )
        result_by_id[finding.finding_instance_id] = result
        if progress_callback is not None:
            progress_callback(
                tuple(
                    result_by_id[item.finding_instance_id]
                    for item in findings_to_process
                    if item.finding_instance_id in result_by_id
                )
            )

    triage_results = [
        result_by_id[finding.finding_instance_id] for finding in findings_to_process
    ]

    completed_at = datetime.now(UTC)

    # 4. Tính ngữ nghĩa các bộ đếm
    total_findings_parsed = len(findings_to_process)
    findings_triaged_ok = len(
        [
            r
            for r in triage_results
            if not r.processing_errors and r.policy_decision.action != PolicyAction.TRIAGE_ERROR
        ]
    )
    findings_with_errors = len(
        [
            r
            for r in triage_results
            if r.processing_errors or r.policy_decision.action == PolicyAction.TRIAGE_ERROR
        ]
    )

    # 5. Tổng hợp RunMetadata và BatchResult
    run_id = str(uuid.uuid4())
    repository_name = repository_root.name

    sc_versions = dict(scanner_versions) if scanner_versions is not None else {}
    sc_config_ids = dict(scanner_config_ids) if scanner_config_ids is not None else {}
    artifact_hashes = dict(input_artifact_hashes) if input_artifact_hashes is not None else {}

    run_metadata = RunMetadata(
        run_id=run_id,
        repository_name=repository_name,
        repository_identifier=repository_identifier,
        commit_sha=commit_sha,
        working_tree_state=working_tree_state,
        artifact_repository_match=artifact_repository_match,
        scanners_attempted=scanners_attempted,
        scanners_succeeded=scanners_succeeded,
        scanner_versions=sc_versions,
        scanner_config_ids=sc_config_ids,
        input_artifact_hashes=artifact_hashes,
        analysis_backend=(analysis_identity.backend if analysis_identity else "native"),
        analysis_backend_version=(analysis_identity.version if analysis_identity else TOOL_VERSION),
        analysis_config_id=(analysis_identity.config_id if analysis_identity else "native-evidence-v1"),
        cpg_build_status=(analysis_identity.build_status if analysis_identity else "not_applicable"),
        cpg_build_seconds=(analysis_identity.build_seconds if analysis_identity else 0.0),
        prompt_version=prompt_version,
        model_version=(
            model_version
            if model_version is not None
            else getattr(provider, "model_version", None)
        ),
        policy_version=POLICY_VERSION,
        triage_provider=(
            triage_provider_name
            if triage_provider_name is not None
            else getattr(provider, "provider_name", provider.__class__.__name__)
        ),
        tool_version=TOOL_VERSION,
        cli_mode=cli_mode,
        started_at=started_at,
        completed_at=completed_at,
        total_findings_parsed=total_findings_parsed,
        findings_triaged_ok=findings_triaged_ok,
        findings_with_errors=findings_with_errors,
    )

    return BatchResult(
        run_metadata=run_metadata,
        results=list(triage_results),
        scanner_errors=list(scanner_errors),
    )
