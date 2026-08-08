"""Các subprocess runner Semgrep và Gitleaks chạy tuần tự."""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from sast_triage.errors import SastTriageError
from sast_triage.models import ProcessingError, ProcessingStage, ScannerType


@dataclass(frozen=True)
class ScannerRunResult:
    """Kết quả runner an toàn; stdout thô chỉ được lưu trong file artifact."""

    scanner: ScannerType
    artifact_path: Path | None
    errors: tuple[ProcessingError, ...]
    succeeded: bool
    exit_code: int | None


class _ScannerRunner:
    """Implementation dùng chung cho một scanner executable."""

    scanner: ScannerType
    executable: str
    output_filename: str
    finding_exit_codes: frozenset[int]

    def __init__(self, executable: str | None = None, timeout_seconds: float = 300.0) -> None:
        if timeout_seconds <= 0:
            raise SastTriageError("Scanner timeout must be positive.", "SCANNER_INVALID_CONFIGURATION")
        if executable is not None and not executable.strip():
            raise SastTriageError("Scanner executable must not be empty.", "SCANNER_INVALID_CONFIGURATION")
        self._executable = executable or self.executable
        self._timeout_seconds = timeout_seconds

    def run(self, repository_root: Path, output_dir: Path) -> ScannerRunResult:
        """Chạy scanner an toàn và ghi stdout vào artifact cùng lần chạy."""
        root = repository_root.resolve()
        if not root.is_dir():
            return self._failure("SCANNER_REPOSITORY_INVALID", "Scanner repository path is invalid.")
        destination = output_dir.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        artifact_path = destination / self.output_filename
        command = self._command(root, artifact_path)
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                check=False,
                shell=False,
                timeout=self._timeout_seconds,
            )
        except FileNotFoundError:
            return self._failure("SCANNER_EXECUTABLE_NOT_FOUND", "Scanner executable was not found.")
        except subprocess.TimeoutExpired:
            return self._failure("SCANNER_TIMEOUT", "Scanner process timed out.", retryable=True)
        except OSError:
            return self._failure("SCANNER_PROCESS_ERROR", "Scanner process could not be started.")

        if not artifact_path.exists():
            try:
                artifact_path.write_bytes(completed.stdout)
            except OSError:
                return self._failure("SCANNER_ARTIFACT_WRITE_ERROR", "Scanner artifact could not be written.")
        if completed.returncode not in self.finding_exit_codes:
            return ScannerRunResult(
                scanner=self.scanner,
                artifact_path=artifact_path,
                errors=(
                    ProcessingError(
                        scanner=self.scanner,
                        stage=ProcessingStage.PARSE,
                        error_code="SCANNER_PROCESS_FAILED",
                        safe_message="Scanner process returned a failure status.",
                        retryable=False,
                    ),
                ),
                succeeded=False,
                exit_code=completed.returncode,
            )
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=artifact_path,
            errors=(),
            succeeded=True,
            exit_code=completed.returncode,
        )

    def _failure(self, code: str, message: str, retryable: bool = False) -> ScannerRunResult:
        """Tạo lỗi vận hành mà không có chi tiết subprocess thô."""
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=None,
            errors=(ProcessingError(scanner=self.scanner, stage=ProcessingStage.PARSE, error_code=code, safe_message=message, retryable=retryable),),
            succeeded=False,
            exit_code=None,
        )

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        """Tạo tham số lệnh scanner mà không nội suy shell."""
        raise SastTriageError(
            safe_message="Scanner command is not configured.",
            error_code="SCANNER_INVALID_CONFIGURATION",
            retryable=False,
        )


class SemgrepRunner(_ScannerRunner):
    """Chạy sinh output JSON Semgrep."""

    scanner = ScannerType.SEMGREP
    executable = "semgrep"
    output_filename = "semgrep.json"
    finding_exit_codes = frozenset({0})

    def run(self, repository_root: Path, output_dir: Path) -> ScannerRunResult:
        """Chạy Semgrep và normalize result path đã bind trước khi parse."""
        result = super().run(repository_root, output_dir)
        if not result.succeeded or result.artifact_path is None:
            return result
        normalization_error = self._normalize_artifact_paths(
            repository_root.resolve(),
            result.artifact_path,
        )
        if normalization_error is None:
            return result
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=result.artifact_path,
            errors=(normalization_error,),
            succeeded=False,
            exit_code=result.exit_code,
        )

    def _normalize_artifact_paths(
        self,
        repository_root: Path,
        artifact_path: Path,
    ) -> ProcessingError | None:
        """Chuyển atomic Semgrep path thành path tương đối repository đã containment."""
        try:
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            return None

        changed = False
        for record in payload["results"]:
            if not isinstance(record, dict):
                continue
            raw_path = record.get("path")
            if not isinstance(raw_path, str) or not raw_path.strip():
                continue
            candidate = Path(raw_path)
            try:
                resolved = (
                    candidate.resolve(strict=False)
                    if candidate.is_absolute()
                    else (repository_root / candidate).resolve(strict=False)
                )
            except OSError:
                return self._path_error("Semgrep result path could not be resolved safely.")
            if not resolved.is_relative_to(repository_root):
                return self._path_error("Semgrep result path is outside the target repository.")
            normalized = resolved.relative_to(repository_root).as_posix()
            if normalized != raw_path:
                record["path"] = normalized
                changed = True

        if not changed:
            return None

        temporary: Path | None = None
        try:
            with NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=artifact_path.parent,
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, artifact_path)
            temporary = None
        except OSError:
            return self._path_error("Normalized Semgrep artifact could not be written.")
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass
        return None

    def _path_error(self, message: str) -> ProcessingError:
        return ProcessingError(
            scanner=self.scanner,
            stage=ProcessingStage.PARSE,
            error_code="SCANNER_ARTIFACT_PATH_INVALID",
            safe_message=message,
            retryable=False,
        )

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        return [self._executable, "--json", "--output", str(artifact_path), str(repository_root)]


class GitleaksRunner(_ScannerRunner):
    """Chạy sinh output JSON trạng thái hiện tại của Gitleaks."""

    scanner = ScannerType.GITLEAKS
    executable = "gitleaks"
    output_filename = "gitleaks.json"
    finding_exit_codes = frozenset({0, 1})

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        return [self._executable, "detect", "--no-git", "--report-format", "json", "--report-path", str(artifact_path), "--source", str(repository_root)]
