"""Điều phối một lần chạy end-to-end của CLI."""

import argparse
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from sast_triage.application.artifacts import collect_artifacts, validate_repository
from sast_triage.application.console import show_progress
from sast_triage.application.providers import provider_identity, provider_session
from sast_triage.checkpoint import CHECKPOINT_FILENAME, TriageCheckpointStore
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    BatchResult,
    NormalizedFinding,
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
        progress=show_progress,
    )
    findings = artifacts.semgrep.findings + artifacts.gitleaks.findings
    show_progress(
        "3/7",
        f"Đã parse {len(findings)} finding: "
        f"Semgrep={len(artifacts.semgrep.findings)}, "
        f"Gitleaks={len(artifacts.gitleaks.findings)}.",
    )

    repository_id = args.repository_identifier or repository.name
    checkpoint = TriageCheckpointStore(
        output_dir / CHECKPOINT_FILENAME,
        repository_identifier=repository_id,
        artifact_hashes=artifacts.hashes,
        finding_ids=tuple(item.finding_instance_id for item in findings),
        prompt_version=args.prompt_version,
        output_schema_version=args.output_schema_version,
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
                repository_identifier=repository_id,
                artifact_repository_match=(
                    ArtifactRepositoryMatch.VERIFIED
                    if args.command == "scan-and-triage"
                    else ArtifactRepositoryMatch.UNVERIFIED
                ),
                prompt_version=args.prompt_version,
                output_schema_version=args.output_schema_version,
                prompt_type=args.prompt_type,
                input_artifact_hashes=artifacts.hashes,
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
