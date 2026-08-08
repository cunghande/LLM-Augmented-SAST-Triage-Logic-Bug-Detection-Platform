"""Thu thập và parse artifact của scanner."""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sast_triage.errors import SastTriageError
from sast_triage.models import ScannerParseResult, ScannerType
from sast_triage.parsers.gitleaks import parse_gitleaks_json
from sast_triage.parsers.semgrep import parse_semgrep_json
from sast_triage.runners.scanners import GitleaksRunner, ScannerRunResult, SemgrepRunner

ProgressCallback = Callable[[str, str], None]


@dataclass(frozen=True, slots=True)
class ArtifactBundle:
    """Kết quả scanner cần cho pipeline và checkpoint."""

    semgrep: ScannerParseResult
    gitleaks: ScannerParseResult
    hashes: dict[str, str | None]
    scanner_failed: bool = False


def validate_repository(path_text: str) -> Path:
    """Resolve và kiểm tra repository đầu vào."""
    path = Path(path_text).resolve()
    if not path.is_dir():
        raise SastTriageError(
            "Repository path must be an existing directory.",
            "CLI_INVALID_REPOSITORY",
        )
    return path


def collect_artifacts(
    *,
    command: str,
    repository: Path,
    output_dir: Path,
    resume: bool,
    semgrep_json: str | None,
    gitleaks_json: str | None,
    progress: ProgressCallback,
) -> ArtifactBundle:
    """Đọc artifact có sẵn hoặc chạy hai scanner tuần tự."""
    if command == "triage":
        progress("2/7", "Đang đọc artifact Semgrep và Gitleaks có sẵn.")
        semgrep_path = _artifact_path(semgrep_json, repository)
        gitleaks_path = _artifact_path(gitleaks_json, repository)
        return ArtifactBundle(
            semgrep=_parse_artifact(ScannerType.SEMGREP, semgrep_path),
            gitleaks=_parse_artifact(ScannerType.GITLEAKS, gitleaks_path),
            hashes={
                "semgrep": _hash_file(semgrep_path),
                "gitleaks": _hash_file(gitleaks_path),
            },
        )

    artifacts_dir = output_dir / "scanner-artifacts"
    if resume:
        progress("2/7", "Đang dùng lại artifact của lần chạy bị gián đoạn.")
        semgrep_path = artifacts_dir / "semgrep.json"
        gitleaks_path = artifacts_dir / "gitleaks.json"
        return ArtifactBundle(
            semgrep=_parse_artifact(ScannerType.SEMGREP, semgrep_path),
            gitleaks=_parse_artifact(ScannerType.GITLEAKS, gitleaks_path),
            hashes={
                "semgrep": _hash_file(semgrep_path),
                "gitleaks": _hash_file(gitleaks_path),
            },
        )

    semgrep_run = _run_scanner(
        "Semgrep", SemgrepRunner(), repository, artifacts_dir, progress
    )
    gitleaks_run = _run_scanner(
        "Gitleaks", GitleaksRunner(), repository, artifacts_dir, progress
    )
    return ArtifactBundle(
        semgrep=_result_from_run(ScannerType.SEMGREP, semgrep_run),
        gitleaks=_result_from_run(ScannerType.GITLEAKS, gitleaks_run),
        hashes={
            "semgrep": _hash_file(semgrep_run.artifact_path),
            "gitleaks": _hash_file(gitleaks_run.artifact_path),
        },
        scanner_failed=bool(semgrep_run.errors or gitleaks_run.errors),
    )


def _artifact_path(path_text: str | None, repository: Path) -> Path:
    if not path_text:
        raise SastTriageError("Scanner artifact path is required.", "CLI_INVALID_ARTIFACT")
    path = Path(path_text).resolve()
    if path == repository or path.is_dir():
        raise SastTriageError("Scanner artifact path must be a file.", "CLI_INVALID_ARTIFACT")
    return path


def _hash_file(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_artifact(scanner: ScannerType, path: Path) -> ScannerParseResult:
    if scanner == ScannerType.SEMGREP:
        return parse_semgrep_json(path)
    return parse_gitleaks_json(path)


def _run_scanner(
    label: str,
    runner: SemgrepRunner | GitleaksRunner,
    repository: Path,
    artifacts_dir: Path,
    progress: ProgressCallback,
) -> ScannerRunResult:
    progress("2/7", f"Đang chạy scanner {label}.")
    result = runner.run(repository, artifacts_dir)
    status = "thành công" if result.succeeded else "có lỗi an toàn"
    progress("2/7", f"{label} đã kết thúc: {status}.")
    return result


def _result_from_run(scanner: ScannerType, run: ScannerRunResult) -> ScannerParseResult:
    parsed = (
        _parse_artifact(scanner, run.artifact_path)
        if run.artifact_path
        else ScannerParseResult()
    )
    return ScannerParseResult(findings=parsed.findings, errors=parsed.errors + run.errors)
