"""Argparse CLI for artifact triage and scan-and-triage modes."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ArtifactRepositoryMatch,
    ScannerParseResult,
    ScannerType,
)
from sast_triage.parsers.gitleaks import parse_gitleaks_json
from sast_triage.parsers.semgrep import parse_semgrep_json
from sast_triage.pipeline.batch import triage_batch
from sast_triage.reporting.json_reporter import write_json_report
from sast_triage.reporting.markdown_reporter import write_markdown_report
from sast_triage.runners.scanners import GitleaksRunner, ScannerRunResult, SemgrepRunner
from sast_triage.triage.fake_provider import FakeTriageProvider
from sast_triage.triage.real_provider import RealTriageProvider

EXIT_SUCCESS = 0
EXIT_CONFIGURATION_ERROR = 2
EXIT_SCANNER_ERROR = 3
EXIT_REPORT_ERROR = 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-Augmented SAST finding triage")
    subparsers = parser.add_subparsers(dest="command", required=True)
    triage = subparsers.add_parser("triage", help="Triage existing Semgrep/Gitleaks artifacts")
    _add_common_arguments(triage, artifacts=True)
    scan = subparsers.add_parser("scan-and-triage", help="Run scanners, then triage their artifacts")
    _add_common_arguments(scan, artifacts=False)
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser, *, artifacts: bool) -> None:
    parser.add_argument("--repository", "--repo-path", dest="repository", required=True, help="Python repository path")
    parser.add_argument("--output-dir", required=True, help="Run output directory")
    parser.add_argument("--provider", choices=("fake", "real"), default="fake")
    parser.add_argument("--prompt-version", default="triage-prompt-v1")
    parser.add_argument("--output-schema-version", default="triage-decision-v1")
    parser.add_argument("--prompt-type", default="fake.default")
    parser.add_argument("--repository-identifier", default=None)
    parser.add_argument("--overwrite", action=argparse.BooleanOptionalAction, default=True)
    if artifacts:
        parser.add_argument("--semgrep-json", "--semgrep-report", dest="semgrep_json", required=True)
        parser.add_argument("--gitleaks-json", "--gitleaks-report", dest="gitleaks_json", required=True)


def _validate_repository(path_text: str) -> Path:
    """Resolve and validate a target repository path."""
    path = Path(path_text).resolve()
    if not path.is_dir():
        raise SastTriageError("Repository path must be an existing directory.", "CLI_INVALID_REPOSITORY")
    return path


def _artifact_path(path_text: str, repository: Path) -> Path:
    """Resolve an artifact path and reject repository-directory confusion."""
    path = Path(path_text).resolve()
    if path == repository or path.is_dir():
        raise SastTriageError("Scanner artifact path must be a file.", "CLI_INVALID_ARTIFACT")
    return path


def _hash_file(path: Path) -> str | None:
    """Hash an existing artifact without storing its contents."""
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_artifact(scanner: ScannerType, path: Path) -> ScannerParseResult:
    """Dispatch artifact parsing to the existing scanner parser."""
    if scanner == ScannerType.SEMGREP:
        return parse_semgrep_json(path)
    return parse_gitleaks_json(path)


def _combine_parse_and_runner(parsed: ScannerParseResult, run: ScannerRunResult) -> ScannerParseResult:
    """Preserve runner diagnostics alongside parser diagnostics."""
    return ScannerParseResult(findings=parsed.findings, errors=parsed.errors + run.errors)


def _provider(args: argparse.Namespace) -> object:
    """Construct the selected provider; missing real config propagates safely."""
    if args.provider == "fake":
        return FakeTriageProvider()
    return RealTriageProvider.from_environment()


def _atomic_write_metadata(output_path: Path, metadata: object, overwrite: bool) -> None:
    """Write safe run metadata atomically."""
    from tempfile import NamedTemporaryFile

    if output_path.exists() and not overwrite:
        raise SastTriageError("Output file already exists and overwrite=False.", "REPORT_OUTPUT_EXISTS")
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_path.parent, suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output_path)
        temporary = None
    except OSError:
        raise SastTriageError("Run metadata could not be written.", "REPORT_WRITE_ERROR") from None
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def _execute(args: argparse.Namespace) -> int:
    """Execute one CLI mode with shared triage orchestration."""
    repository = _validate_repository(args.repository)
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    provider = _provider(args)
    scanner_errors = False
    hashes: dict[str, str | None] = {}
    if args.command == "triage":
        semgrep_path = _artifact_path(args.semgrep_json, repository)
        gitleaks_path = _artifact_path(args.gitleaks_json, repository)
        semgrep_result = _parse_artifact(ScannerType.SEMGREP, semgrep_path)
        gitleaks_result = _parse_artifact(ScannerType.GITLEAKS, gitleaks_path)
        hashes = {"semgrep": _hash_file(semgrep_path), "gitleaks": _hash_file(gitleaks_path)}
    else:
        artifacts_dir = output_dir / "scanner-artifacts"
        semgrep_run = SemgrepRunner().run(repository, artifacts_dir)
        gitleaks_run = GitleaksRunner().run(repository, artifacts_dir)
        scanner_errors = bool(semgrep_run.errors or gitleaks_run.errors)
        semgrep_result = _combine_parse_and_runner(
            _parse_artifact(ScannerType.SEMGREP, semgrep_run.artifact_path) if semgrep_run.artifact_path else ScannerParseResult(),
            semgrep_run,
        )
        gitleaks_result = _combine_parse_and_runner(
            _parse_artifact(ScannerType.GITLEAKS, gitleaks_run.artifact_path) if gitleaks_run.artifact_path else ScannerParseResult(),
            gitleaks_run,
        )
        hashes = {
            "semgrep": _hash_file(semgrep_run.artifact_path) if semgrep_run.artifact_path else None,
            "gitleaks": _hash_file(gitleaks_run.artifact_path) if gitleaks_run.artifact_path else None,
        }
    repository_identifier = args.repository_identifier or repository.name
    batch = triage_batch(
        repository,
        provider,
        semgrep_result=semgrep_result,
        gitleaks_result=gitleaks_result,
        repository_identifier=repository_identifier,
        artifact_repository_match=(
            ArtifactRepositoryMatch.VERIFIED
            if args.command == "scan-and-triage"
            else ArtifactRepositoryMatch.UNVERIFIED
        ),
        prompt_version=args.prompt_version,
        output_schema_version=args.output_schema_version,
        prompt_type=args.prompt_type,
        input_artifact_hashes=hashes,
        cli_mode=args.command,
    )
    write_json_report(batch, output_dir / "report.json", overwrite=args.overwrite)
    write_markdown_report(batch, output_dir / "report.md", overwrite=args.overwrite)
    _atomic_write_metadata(output_dir / "run-metadata.json", batch.run_metadata.model_dump(mode="json"), args.overwrite)
    return EXIT_SCANNER_ERROR if scanner_errors or bool(batch.scanner_errors) else EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    """CLI entry point with safe user-facing exit semantics."""
    args = _parser().parse_args(argv)
    try:
        return _execute(args)
    except SastTriageError as exc:
        if exc.error_code.startswith("SCANNER") or exc.error_code.startswith("PARSE"):
            return EXIT_SCANNER_ERROR
        if exc.error_code.startswith("REPORT"):
            return EXIT_REPORT_ERROR
        return EXIT_CONFIGURATION_ERROR
    except OSError:
        return EXIT_REPORT_ERROR
