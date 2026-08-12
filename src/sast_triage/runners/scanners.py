"""Các subprocess runner Semgrep và Gitleaks chạy tuần tự."""

import hashlib
import json
import os
import re
import shutil
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
    version: str | None = None
    config_id: str | None = None


def _normalize_artifact_paths(
    artifact_path: Path,
    repository_root: Path,
    scanner: ScannerType,
    *,
    collection_key: str | None,
    path_key: str,
) -> ProcessingError | None:
    """Normalize scanner paths while enforcing repository containment."""
    try:
        raw_bytes = artifact_path.read_bytes()
    except OSError:
        return None
    try:
        artifact_text = raw_bytes.decode("utf-8")
        changed = False
    except UnicodeDecodeError:
        # Scanner-generated JSON can contain legacy source bytes in snippets.
        # Replace only invalid code units at this local artifact boundary so the
        # public parser can retain its strict UTF-8 contract.
        artifact_text = raw_bytes.decode("utf-8", errors="replace")
        changed = True
    try:
        payload = json.loads(artifact_text)
    except json.JSONDecodeError:
        return None

    if collection_key is None:
        records = payload if isinstance(payload, list) else None
    else:
        records = payload.get(collection_key) if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return None

    for record in records:
        if not isinstance(record, dict):
            continue
        raw_path = record.get(path_key)
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
            return _artifact_path_error(scanner, "Scanner result path could not be resolved safely.")
        if not resolved.is_relative_to(repository_root):
            return _artifact_path_error(scanner, "Scanner result path is outside the target repository.")
        normalized = resolved.relative_to(repository_root).as_posix()
        if normalized != raw_path:
            record[path_key] = normalized
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
        return _artifact_path_error(scanner, "Normalized scanner artifact could not be written.")
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
    return None


def _artifact_path_error(scanner: ScannerType, message: str) -> ProcessingError:
    """Create a scanner-safe artifact path error."""
    return ProcessingError(
        scanner=scanner,
        stage=ProcessingStage.PARSE,
        error_code="SCANNER_ARTIFACT_PATH_INVALID",
        safe_message=message,
        retryable=False,
    )


class _ScannerRunner:
    """Implementation dùng chung cho một scanner executable."""

    scanner: ScannerType
    executable: str
    output_filename: str
    finding_exit_codes: frozenset[int]

    def __init__(
        self,
        executable: str | None = None,
        timeout_seconds: float = 300.0,
        config: str | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise SastTriageError("Scanner timeout must be positive.", "SCANNER_INVALID_CONFIGURATION")
        if executable is not None and not executable.strip():
            raise SastTriageError("Scanner executable must not be empty.", "SCANNER_INVALID_CONFIGURATION")
        self._executable = executable or self.executable
        self._timeout_seconds = timeout_seconds
        self._config = config
        self._config_identifier = self._safe_config_identifier(config)

    def run(self, repository_root: Path, output_dir: Path) -> ScannerRunResult:
        """Chạy scanner an toàn và ghi stdout vào artifact cùng lần chạy."""
        root = repository_root.resolve()
        if not root.is_dir():
            return self._failure("SCANNER_REPOSITORY_INVALID", "Scanner repository path is invalid.")
        destination = output_dir.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        artifact_path = destination / self.output_filename
        if shutil.which(self._executable) is None and not Path(self._executable).is_file():
            return self._failure("SCANNER_EXECUTABLE_NOT_FOUND", "Scanner executable was not found.")
        version = self._version()
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
                version=version,
                config_id=self.config_id,
            )
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=artifact_path,
            errors=(),
            succeeded=True,
            exit_code=completed.returncode,
            version=version,
            config_id=self.config_id,
        )

    @property
    def config_id(self) -> str | None:
        """Return a safe, stable scanner configuration identifier."""
        return self._config_identifier

    @staticmethod
    def _safe_config_identifier(config: str | None, root: Path | None = None) -> str | None:
        """Return a report-safe registry ID or local config content hash."""
        if config is None:
            return None
        if config.startswith(("http://", "https://")):
            return "remote-config"
        raw_candidate = Path(config)
        candidate = raw_candidate
        if root is not None and not raw_candidate.is_absolute():
            candidate = root / raw_candidate
        if candidate.is_file():
            try:
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            except OSError:
                return "local-config-unreadable"
            return f"local-sha256:{digest}"
        if raw_candidate.is_absolute() or raw_candidate.suffix.lower() in {".yml", ".yaml", ".json"}:
            return "local-config-unresolved"
        return config

    def _version(self) -> str | None:
        """Read a scanner version without exposing subprocess diagnostics."""
        try:
            completed = subprocess.run(
                [self._executable, *self._version_arguments()],
                capture_output=True,
                check=False,
                shell=False,
                timeout=min(self._timeout_seconds, 15.0),
                text=True,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None
        raw_stdout = getattr(completed, "stdout", "")
        raw_stderr = getattr(completed, "stderr", "")
        stdout = raw_stdout.decode("utf-8", errors="ignore") if isinstance(raw_stdout, bytes) else raw_stdout
        stderr = raw_stderr.decode("utf-8", errors="ignore") if isinstance(raw_stderr, bytes) else raw_stderr
        combined = f"{stdout or ''}\n{stderr or ''}"
        match = re.search(r"\b\d+\.\d+(?:\.\d+)?\b", combined)
        return match.group(0) if match else None

    def _version_arguments(self) -> list[str]:
        """Return scanner-specific version command arguments."""
        return ["--version"]

    def _failure(self, code: str, message: str, retryable: bool = False) -> ScannerRunResult:
        """Tạo lỗi vận hành mà không có chi tiết subprocess thô."""
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=None,
            errors=(ProcessingError(scanner=self.scanner, stage=ProcessingStage.PARSE, error_code=code, safe_message=message, retryable=retryable),),
            succeeded=False,
            exit_code=None,
            version=None,
            config_id=self.config_id,
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

    def __init__(
        self,
        executable: str | None = None,
        timeout_seconds: float = 300.0,
        config: str | tuple[str, ...] = "p/python",
    ) -> None:
        """Create a Semgrep runner with an explicit ruleset."""
        configs = (config,) if isinstance(config, str) else config
        if not configs or any(not item.strip() for item in configs):
            raise SastTriageError("Semgrep config must not be empty.", "SCANNER_INVALID_CONFIGURATION")
        self._configs = configs
        super().__init__(executable, timeout_seconds, "+".join(configs))

    def run(self, repository_root: Path, output_dir: Path) -> ScannerRunResult:
        """Chạy Semgrep và normalize result path đã bind trước khi parse."""
        result = super().run(repository_root, output_dir)
        if not result.succeeded or result.artifact_path is None:
            return result
        normalization_error = _normalize_artifact_paths(
            result.artifact_path,
            repository_root.resolve(),
            self.scanner,
            collection_key="results",
            path_key="path",
        )
        if normalization_error is None:
            return result
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=result.artifact_path,
            errors=(normalization_error,),
            succeeded=False,
            exit_code=result.exit_code,
            version=result.version,
            config_id=result.config_id,
        )

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        safe_ids = [self._safe_config_identifier(item, repository_root) or "unknown" for item in self._configs]
        self._config_identifier = "+".join(safe_ids)
        command = [
            self._executable,
            "scan",
        ]
        for config in self._configs:
            command.extend(["--config", config])
        command.extend(["--json", "--output", str(artifact_path), str(repository_root)])
        return command


class GitleaksRunner(_ScannerRunner):
    """Chạy sinh output JSON trạng thái hiện tại của Gitleaks."""

    scanner = ScannerType.GITLEAKS
    executable = "gitleaks"
    output_filename = "gitleaks.json"
    finding_exit_codes = frozenset({0, 1})

    def __init__(
        self,
        executable: str | None = None,
        timeout_seconds: float = 300.0,
        config: str | None = None,
    ) -> None:
        """Create a Gitleaks runner with an optional explicit config file."""
        super().__init__(executable, timeout_seconds, config or "gitleaks-built-in")

    def run(self, repository_root: Path, output_dir: Path) -> ScannerRunResult:
        """Run Gitleaks and normalize absolute result paths before parsing."""
        result = super().run(repository_root, output_dir)
        if not result.succeeded or result.artifact_path is None:
            return result
        normalization_error = _normalize_artifact_paths(
            result.artifact_path,
            repository_root.resolve(),
            self.scanner,
            collection_key=None,
            path_key="File",
        )
        if normalization_error is None:
            return result
        return ScannerRunResult(
            scanner=self.scanner,
            artifact_path=result.artifact_path,
            errors=(normalization_error,),
            succeeded=False,
            exit_code=result.exit_code,
            version=result.version,
            config_id=result.config_id,
        )

    def _version_arguments(self) -> list[str]:
        return ["version"]

    def _command(self, repository_root: Path, artifact_path: Path) -> list[str]:
        command = [
            self._executable,
            "detect",
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            str(artifact_path),
            "--source",
            str(repository_root),
        ]
        if self._config and self._config != "gitleaks-built-in":
            self._config_identifier = self._safe_config_identifier(self._config, repository_root)
            command.extend(["--config", self._config])
        return command
