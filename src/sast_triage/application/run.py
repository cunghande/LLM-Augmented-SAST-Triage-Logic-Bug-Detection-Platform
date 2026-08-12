"""Điều phối một lần chạy end-to-end của CLI."""

import argparse
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from sast_triage import __version__ as TOOL_VERSION
from sast_triage.analysis.base import AnalysisBackend
from sast_triage.analysis.factory import analysis_backend_session
from sast_triage.application.artifacts import (
    collect_artifacts,
    validate_repository,
)
from sast_triage.application.console import show_progress
from sast_triage.application.providers import provider_identity, provider_session
from sast_triage.application.repository_state import read_repository_state
from sast_triage.checkpoint import CHECKPOINT_FILENAME, TriageCheckpointStore
from sast_triage.context.repository_index import MODULE2_CONFIG_ID
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    BatchResult,
    NormalizedFinding,
    ScannerParseResult,
    TriageResult,
)
from sast_triage.pipeline.batch import triage_batch
from sast_triage.reporting.json_reporter import write_json_report
from sast_triage.reporting.markdown_reporter import write_markdown_report

EXIT_SUCCESS = 0
EXIT_CONFIGURATION_ERROR = 2
EXIT_SCANNER_ERROR = 3
EXIT_REPORT_ERROR = 4
EXIT_PROVIDER_RESOURCE_EXHAUSTED = 5


def execute_run(args: argparse.Namespace) -> int:
    """Run the pipeline with exactly one analysis backend session."""
    repository = validate_repository(args.repository)
    repository_id = args.repository_identifier or repository.name
    backend_name = getattr(args, "analysis_backend", "native")
    show_progress(
        "PREFLIGHT",
        f"Đang khởi tạo analysis backend={backend_name}.",
    )
    with analysis_backend_session(
        backend_name,
        repository,
        repository_id,
        module2_enabled=args.module2,
    ) as backend:
        args._analysis_backend = backend
        return _execute_run(args)


def _execute_run(args: argparse.Namespace) -> int:
    """Chạy scanner/artifact, triage, checkpoint rồi ghi báo cáo."""
    show_progress("1/7", "Đang kiểm tra repository và cấu hình output.")
    repository = validate_repository(args.repository)
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    artifacts = collect_artifacts(
        command=args.command,
        repository=repository,
        output_dir=output_dir,
        resume=args.resume,
        semgrep_json=getattr(args, "semgrep_json", None),
        gitleaks_json=getattr(args, "gitleaks_json", None),
        semgrep_config=tuple(args.semgrep_config or ("p/python",)),
        gitleaks_config=args.gitleaks_config,
        progress=show_progress,
    )
    analysis_backend: AnalysisBackend = args._analysis_backend
    repository_index = analysis_backend.repository_index
    module2_result = None
    if args.module2:
        show_progress("3/7", "Đang lập chỉ mục Python theo component cho Module 2.")
        module2_findings = analysis_backend.discover_findings(
            artifacts.semgrep.findings,
        )
        module2_result = ScannerParseResult(findings=module2_findings)
    scanner_versions = dict(artifacts.scanner_versions)
    scanner_config_ids = dict(artifacts.scanner_config_ids)
    if module2_result is not None:
        scanner_versions["MODULE2"] = TOOL_VERSION
        scanner_config_ids["MODULE2"] = MODULE2_CONFIG_ID
    findings = (
        artifacts.semgrep.findings
        + artifacts.gitleaks.findings
        + (() if module2_result is None else module2_result.findings)
    )
    show_progress(
        "3/7",
        f"Đã parse {len(findings)} finding: "
        f"Semgrep={len(artifacts.semgrep.findings)}, "
        f"Gitleaks={len(artifacts.gitleaks.findings)}.",
    )

    repository_id = args.repository_identifier or repository.name
    commit_sha, working_tree_state = read_repository_state(repository)
    checkpoint = TriageCheckpointStore(
        output_dir / CHECKPOINT_FILENAME,
        repository_identifier=repository_id,
        artifact_hashes=artifacts.hashes,
        finding_ids=tuple(item.finding_instance_id for item in findings),
        prompt_version=args.prompt_version,
        output_schema_version=args.output_schema_version,
        analysis_backend=analysis_backend.identity.backend,
        analysis_backend_version=analysis_backend.identity.version,
        analysis_config_id=analysis_backend.identity.config_id,
    )
    previous_results, provider_history = _restore_checkpoint(
        checkpoint, findings, args.resume
    )
    current_provider = provider_identity(args.provider)
    if not provider_history or provider_history[-1] != current_provider:
        provider_history = (*provider_history, current_provider)

    completed_results = previous_results

    def save_progress(results: tuple[TriageResult, ...]) -> None:
        nonlocal completed_results
        completed_results = results
        checkpoint.save(results, provider_history=provider_history)
        latest_action = results[-1].policy_decision.action.value
        show_progress(
            "5/7",
            f"Tiến độ triage {len(results)}/{len(findings)}; "
            f"policy action gần nhất={latest_action}.",
        )

    checkpoint.save(previous_results, provider_history=provider_history)
    try:
        provider_label, model_label = current_provider
        show_progress(
            "4/7",
            f"Đang khởi động provider={provider_label}, "
            f"model={model_label or 'không áp dụng'}.",
        )
        with provider_session(args.provider) as provider:
            batch = triage_batch(
                repository,
                provider,
                semgrep_result=artifacts.semgrep,
                gitleaks_result=artifacts.gitleaks,
                module2_result=module2_result,
                repository_index=repository_index,
                analysis_backend=analysis_backend,
                analysis_identity=analysis_backend.identity,
                repository_identifier=repository_id,
                commit_sha=commit_sha,
                working_tree_state=working_tree_state,
                artifact_repository_match=(
                    ArtifactRepositoryMatch.VERIFIED
                    if args.command == "scan-and-triage"
                    else ArtifactRepositoryMatch.UNVERIFIED
                ),
                prompt_version=args.prompt_version,
                output_schema_version=args.output_schema_version,
                prompt_type=args.prompt_type,
                input_artifact_hashes=artifacts.hashes,
                scanner_versions=scanner_versions,
                scanner_config_ids=scanner_config_ids,
                cli_mode=f"{args.command}-resume" if args.resume else args.command,
                existing_results=previous_results,
                progress_callback=save_progress,
                triage_provider_name=" -> ".join(name for name, _ in provider_history),
                model_version=(
                    " -> ".join(model for _, model in provider_history if model) or None
                ),
            )
    except SastTriageError as exc:
        if exc.error_code == "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED":
            checkpoint.save(
                completed_results,
                provider_history=provider_history,
                status="resource_exhausted",
                failure_code=exc.error_code,
            )
            show_progress(
                "INTERRUPTED",
                f"Modal dừng sau {len(completed_results)}/{len(findings)} finding; "
                "checkpoint đã được lưu.",
            )
        raise

    _write_outputs(batch, output_dir, args.overwrite)
    checkpoint.save(tuple(batch.results), provider_history=provider_history, status="complete")
    checkpoint.clear()
    show_progress(
        "7/7",
        "Đã ghi báo cáo và metadata thành công; checkpoint đã được xóa.",
    )
    return (
        EXIT_SCANNER_ERROR
        if artifacts.scanner_failed or bool(batch.scanner_errors)
        else EXIT_SUCCESS
    )


def _restore_checkpoint(
    checkpoint: TriageCheckpointStore,
    findings: tuple[NormalizedFinding, ...],
    resume: bool,
) -> tuple[tuple[TriageResult, ...], tuple[tuple[str, str | None], ...]]:
    if not resume:
        return (), ()
    loaded = checkpoint.load(findings)
    show_progress(
        "4/7",
        f"Đã khôi phục {len(loaded.results)}/{len(findings)} finding từ checkpoint.",
    )
    return loaded.results, loaded.provider_history


def _write_outputs(batch: BatchResult, output_dir: Path, overwrite: bool) -> None:
    show_progress("6/7", "Triage hoàn tất; đang kiểm tra và ghi báo cáo.")
    write_json_report(batch, output_dir / "report.json", overwrite=overwrite)
    write_markdown_report(batch, output_dir / "report.md", overwrite=overwrite)
    _atomic_write_metadata(
        output_dir / "run-metadata.json",
        batch.run_metadata.model_dump(mode="json"),
        overwrite,
    )


def _atomic_write_metadata(output_path: Path, metadata: object, overwrite: bool) -> None:
    """Ghi metadata qua file tạm để tránh file dở dang."""
    if output_path.exists() and not overwrite:
        raise SastTriageError(
            "Output file already exists and overwrite=False.",
            "REPORT_OUTPUT_EXISTS",
        )
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output_path)
        temporary = None
    except OSError:
        raise SastTriageError(
            "Run metadata could not be written.", "REPORT_WRITE_ERROR"
        ) from None
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
