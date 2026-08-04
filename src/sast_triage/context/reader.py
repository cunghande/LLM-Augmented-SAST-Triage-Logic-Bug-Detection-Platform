"""Safe Repository Reader for SAST Triage Platform.

Reads source files from a target Python repository while strictly enforcing
path containment, symlink escape protection, file size limits, and UTF-8
encoding validation.

Security guarantees:
- Resolved repository root is used for containment checks via Path.is_relative_to().
- Traversal attacks (../, absolute paths, drive letters, UNC, symlink escapes) are blocked.
- Two-layer file size defense prevents reading oversized files into RAM.
- Safe messages and repr representations NEVER leak absolute paths or raw source text.
"""

from dataclasses import dataclass, field
from pathlib import Path

from sast_triage.errors import SastTriageError


@dataclass(frozen=True, slots=True)
class SourceReadResult:
    """Internal ephemeral result of reading a repository source file.

    Attributes:
        relative_path: Repository-relative source path.
        text: Raw source code text (excluded from repr for security).
        size_bytes: Size of the source file in bytes.
        encoding: File encoding (always 'utf-8').
    """

    relative_path: str
    text: str = field(repr=False)
    size_bytes: int
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if not isinstance(self.relative_path, str) or not self.relative_path.strip():
            raise ValueError("relative_path must be a non-empty string")
        if self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        if self.encoding != "utf-8":
            raise ValueError("encoding must be utf-8")


def _is_invalid_relative_path_string(path_str: str) -> bool:
    """Early string validation to reject non-relative or malformed path strings."""
    if not isinstance(path_str, str) or not path_str.strip():
        return True
    if "\0" in path_str:
        return True

    p = path_str.strip()
    # Reject POSIX absolute, Windows rooted (\path), UNC (\\server or //server)
    if p.startswith(("/", "\\")):
        return True

    # Reject Windows drive paths (C:\file, C:/file, C:relative)
    return len(p) >= 2 and p[1] == ":"


def read_repository_source(
    repository_root: Path,
    relative_source_path: str,
    *,
    max_file_size_bytes: int = 1_048_576,
) -> SourceReadResult:
    """Safely read a repository-relative source file with containment and size checks.

    Args:
        repository_root: Path to the target repository directory.
        relative_source_path: Repository-relative file path string.
        max_file_size_bytes: Maximum allowed file size in bytes (default 1MB).

    Returns:
        An internal immutable ``SourceReadResult``.

    Raises:
        SastTriageError: On path containment failure, missing file, non-regular file,
            size limit breach, unsupported encoding, or I/O failure. Safe message
            never contains absolute paths or source code.
    """
    # 1. Validate max_file_size_bytes
    if (
        not isinstance(max_file_size_bytes, int)
        or isinstance(max_file_size_bytes, bool)
        or max_file_size_bytes <= 0
    ):
        raise SastTriageError(
            safe_message="max_file_size_bytes must be a positive integer.",
            error_code="CONTEXT_INVALID_SIZE_LIMIT",
            retryable=False,
        )

    # 2. Validate repository_root existence and directory status
    if not isinstance(repository_root, Path):
        raise SastTriageError(
            safe_message="Repository root path is invalid.",
            error_code="CONTEXT_REPOSITORY_NOT_FOUND",
            retryable=False,
        )

    try:
        if not repository_root.exists():
            raise SastTriageError(
                safe_message="Repository root directory does not exist.",
                error_code="CONTEXT_REPOSITORY_NOT_FOUND",
                retryable=False,
            )
        resolved_root = repository_root.resolve(strict=True)
    except (PermissionError, OSError) as exc:
        if isinstance(exc, SastTriageError):
            raise
        raise SastTriageError(
            safe_message="Repository root directory does not exist.",
            error_code="CONTEXT_REPOSITORY_NOT_FOUND",
            retryable=False,
        ) from exc

    if not resolved_root.is_dir():
        raise SastTriageError(
            safe_message="Repository root path is not a directory.",
            error_code="CONTEXT_REPOSITORY_NOT_DIRECTORY",
            retryable=False,
        )

    # 3. Validate relative_source_path format
    if _is_invalid_relative_path_string(relative_source_path):
        if not isinstance(relative_source_path, str) or not relative_source_path.strip():
            raise SastTriageError(
                safe_message="Source path must be a non-empty string.",
                error_code="CONTEXT_INVALID_SOURCE_PATH",
                retryable=False,
            )
        if "\0" in relative_source_path:
            raise SastTriageError(
                safe_message="Source path contains invalid null bytes.",
                error_code="CONTEXT_INVALID_SOURCE_PATH",
                retryable=False,
            )
        raise SastTriageError(
            safe_message="Source path must be repository-relative.",
            error_code="CONTEXT_PATH_OUTSIDE_REPOSITORY",
            retryable=False,
        )

    # 4. Resolve candidate path and enforce Path Containment
    candidate = resolved_root / relative_source_path
    try:
        resolved_candidate = candidate.resolve(strict=False)
    except (PermissionError, OSError):
        raise SastTriageError(
            safe_message="Failed to resolve candidate source path.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )

    if not resolved_candidate.is_relative_to(resolved_root):
        raise SastTriageError(
            safe_message="Source path escapes repository root.",
            error_code="CONTEXT_PATH_OUTSIDE_REPOSITORY",
            retryable=False,
        )

    # 5. Validate file existence and regular file status after containment pass
    try:
        exists = resolved_candidate.exists()
    except (PermissionError, OSError):
        raise SastTriageError(
            safe_message="Failed to check source file existence.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )

    if not exists:
        raise SastTriageError(
            safe_message="Source file does not exist in repository.",
            error_code="CONTEXT_SOURCE_FILE_NOT_FOUND",
            retryable=False,
        )

    try:
        is_regular = resolved_candidate.is_file()
    except (PermissionError, OSError):
        raise SastTriageError(
            safe_message="Failed to check source file type.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )

    if not is_regular:
        raise SastTriageError(
            safe_message="Source path is not a regular file.",
            error_code="CONTEXT_SOURCE_NOT_REGULAR_FILE",
            retryable=False,
        )

    # 6. Two-layer File Size Defense
    # Layer 1: Check stat().st_size before opening
    try:
        file_size = resolved_candidate.stat().st_size
    except PermissionError:
        raise SastTriageError(
            safe_message="Permission denied accessing source file.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )
    except OSError:
        raise SastTriageError(
            safe_message="Failed to stat source file.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )

    if file_size > max_file_size_bytes:
        raise SastTriageError(
            safe_message="Source file size exceeds maximum allowed limit.",
            error_code="CONTEXT_SOURCE_FILE_TOO_LARGE",
            retryable=False,
        )

    # Layer 2: Bounded read (open binary and read up to max_file_size_bytes + 1)
    try:
        with resolved_candidate.open("rb") as f:
            raw_bytes = f.read(max_file_size_bytes + 1)
    except PermissionError:
        raise SastTriageError(
            safe_message="Permission denied reading source file.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )
    except OSError:
        raise SastTriageError(
            safe_message="I/O error reading source file.",
            error_code="CONTEXT_SOURCE_READ_ERROR",
            retryable=False,
        )

    if len(raw_bytes) > max_file_size_bytes:
        raise SastTriageError(
            safe_message="Source file size exceeds maximum allowed limit.",
            error_code="CONTEXT_SOURCE_FILE_TOO_LARGE",
            retryable=False,
        )

    # 7. Decode UTF-8
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise SastTriageError(
            safe_message="Source file is not valid UTF-8 text.",
            error_code="CONTEXT_SOURCE_UNSUPPORTED_ENCODING",
            retryable=False,
        )

    return SourceReadResult(
        relative_path=relative_source_path,
        text=text,
        size_bytes=len(raw_bytes),
        encoding="utf-8",
    )
