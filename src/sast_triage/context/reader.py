"""Trình đọc repository an toàn cho SAST Triage Platform.

Đọc file mã nguồn từ Python repository đích, đồng thời thực thi nghiêm ngặt
kiểm tra path containment, chống symlink escape, giới hạn kích thước file và
validate encoding UTF-8.

Cam kết bảo mật:
- Repository root đã resolve được dùng để kiểm tra containment qua Path.is_relative_to().
- Chặn tấn công traversal (../, đường dẫn tuyệt đối, drive letter, UNC, symlink escape).
- Phòng vệ kích thước file hai lớp tránh đọc file quá lớn vào RAM.
- Thông báo an toàn và biểu diễn repr KHÔNG BAO GIỜ làm lộ đường dẫn tuyệt đối hoặc mã nguồn thô.
"""

from dataclasses import dataclass, field
from pathlib import Path

from sast_triage.errors import SastTriageError


@dataclass(frozen=True, slots=True)
class SourceReadResult:
    """Kết quả tạm thời, nội bộ khi đọc file mã nguồn repository.

    Thuộc tính:
        relative_path: Đường dẫn mã nguồn tương đối với repository.
        text: Văn bản mã nguồn thô (loại khỏi repr để bảo mật).
        size_bytes: Kích thước file mã nguồn tính bằng byte.
        encoding: Encoding file (luôn là 'utf-8').
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
    """Validate chuỗi sớm để chặn đường dẫn không tương đối hoặc sai định dạng."""
    if not isinstance(path_str, str) or not path_str.strip():
        return True
    if "\0" in path_str:
        return True

    p = path_str.strip()
    # Chặn đường dẫn tuyệt đối POSIX, rooted Windows (\path), UNC (\\server hoặc //server)
    if p.startswith(("/", "\\")):
        return True

    # Chặn đường dẫn có drive Windows (C:\file, C:/file, C:relative)
    return len(p) >= 2 and p[1] == ":"


def read_repository_source(
    repository_root: Path,
    relative_source_path: str,
    *,
    max_file_size_bytes: int = 1_048_576,
) -> SourceReadResult:
    """Đọc an toàn file mã nguồn tương đối với repository, có kiểm tra containment và kích thước.

    Tham số:
        repository_root: Path đến thư mục repository đích.
        relative_source_path: Chuỗi đường dẫn file tương đối với repository.
        max_file_size_bytes: Kích thước file tối đa tính bằng byte (mặc định 1MB).

    Trả về:
        ``SourceReadResult`` nội bộ, bất biến.

    Ném lỗi:
        SastTriageError: Khi containment thất bại, file thiếu, không phải file thường,
            vượt giới hạn kích thước, encoding không hỗ trợ hoặc I/O lỗi. Thông báo an toàn
            không bao giờ chứa đường dẫn tuyệt đối hoặc mã nguồn.
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

    # 2. Validate repository_root tồn tại và là thư mục
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

    # 3. Validate định dạng relative_source_path
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

    # 4. Resolve đường dẫn ứng viên và thực thi Path Containment
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

    # 5. Validate file tồn tại và là file thường sau khi qua containment
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

    # 6. Phòng vệ kích thước file hai lớp
    # Lớp 1: Kiểm tra stat().st_size trước khi mở
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

    # Lớp 2: Đọc có giới hạn (mở nhị phân, đọc tối đa max_file_size_bytes + 1)
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
