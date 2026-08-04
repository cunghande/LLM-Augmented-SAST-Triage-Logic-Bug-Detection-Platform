"""Sequential Semgrep and Gitleaks subprocess runners."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

from sast_triage.errors import SastTriageError
from sast_triage.models import ProcessingError, ProcessingStage, ScannerType


@dataclass(frozen=True)
class ScannerRunResult:
    """Safe runner result; raw stdout is stored only in the artifact file."""

    scanner: ScannerType
    artifact_path: Path | None
    errors: tuple[ProcessingError, ...]
    succeeded: bool
    exit_code: int | None


class _ScannerRunner:
    """Common implementation for one scanner executable."""

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
        """Run scanner safely and write stdout to a same-run artifact."""
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
        """Create an operational failure without raw subprocess details."""
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=None,
            errors=(ProcessingError(scanner=self.scanner, stage=ProcessingStage.PARSE, error_code=code, safe_message=message, retryable=retryable),),
            succeeded=False,
            exit_code=None,
        )

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        """Build scanner command arguments without shell interpolation."""
        raise SastTriageError(
            safe_message="Scanner command is not configured.",
            error_code="SCANNER_INVALID_CONFIGURATION",
            retryable=False,
        )


class SemgrepRunner(_ScannerRunner):
    """Run Semgrep JSON output generation."""

    scanner = ScannerType.SEMGREP
    executable = "semgrep"
    output_filename = "semgrep.json"
    finding_exit_codes = frozenset({0})

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        return [self._executable, "--json", "--output", str(artifact_path), str(repository_root)]


class GitleaksRunner(_ScannerRunner):
    """Run Gitleaks current-state JSON output generation."""

    scanner = ScannerType.GITLEAKS
    executable = "gitleaks"
    output_filename = "gitleaks.json"
    finding_exit_codes = frozenset({0, 1})

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        return [self._executable, "detect", "--no-git", "--report-format", "json", "--report-path", str(artifact_path), "--source", str(repository_root)]
