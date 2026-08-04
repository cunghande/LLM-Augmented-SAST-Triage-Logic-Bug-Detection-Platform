"""Unit tests for Safe Repository Reader."""

import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from sast_triage.context.reader import SourceReadResult, read_repository_source
from sast_triage.errors import SastTriageError

SOURCE_CANARY = "SOURCE_CANARY_DO_NOT_LEAK"


# --- Happy Path Tests ---


def test_read_valid_python_source(tmp_path: Path) -> None:
    repo_root = tmp_path / "my_repo"
    repo_root.mkdir()
    src_file = repo_root / "app" / "main.py"
    src_file.parent.mkdir()
    content = f"# Python file\nSOURCE_KEY = '{SOURCE_CANARY}'\n"
    src_file.write_bytes(content.encode("utf-8"))

    res = read_repository_source(repo_root, "app/main.py")

    assert isinstance(res, SourceReadResult)
    assert res.relative_path == "app/main.py"
    assert res.text == content
    assert res.size_bytes == len(content.encode("utf-8"))
    assert res.encoding == "utf-8"


def test_source_read_result_security_repr(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "test.py"
    f.write_text(f"CANARY = '{SOURCE_CANARY}'", encoding="utf-8")

    res = read_repository_source(repo_root, "test.py")

    # repr must NOT contain source text or absolute path
    res_repr = repr(res)
    assert SOURCE_CANARY not in res_repr
    assert str(repo_root.resolve()) not in res_repr
    assert "relative_path='test.py'" in res_repr
    assert "size_bytes=" in res_repr


def test_source_read_result_is_frozen(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "test.py"
    f.write_text("x = 1", encoding="utf-8")

    res = read_repository_source(repo_root, "test.py")
    with pytest.raises(AttributeError):
        res.text = "mutated"  # type: ignore[misc]


# --- Repository Root Validation ---


def test_repository_root_not_found(tmp_path: Path) -> None:
    non_existent = tmp_path / "does_not_exist"
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(non_existent, "app.py")

    err = exc_info.value
    assert err.error_code == "CONTEXT_REPOSITORY_NOT_FOUND"
    assert err.retryable is False
    assert str(non_existent) not in err.safe_message


def test_repository_root_is_not_directory(tmp_path: Path) -> None:
    file_as_root = tmp_path / "root_file.txt"
    file_as_root.write_text("not a dir", encoding="utf-8")

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(file_as_root, "app.py")

    err = exc_info.value
    assert err.error_code == "CONTEXT_REPOSITORY_NOT_DIRECTORY"
    assert err.retryable is False


# --- Path Safety & Traversal Rejection ---


def test_reject_empty_source_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "")
    assert exc_info.value.error_code == "CONTEXT_INVALID_SOURCE_PATH"


def test_reject_whitespace_source_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "   \t\n ")
    assert exc_info.value.error_code == "CONTEXT_INVALID_SOURCE_PATH"


def test_reject_null_byte_in_source_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "app\0/main.py")
    assert exc_info.value.error_code == "CONTEXT_INVALID_SOURCE_PATH"


def test_reject_posix_absolute_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "/etc/passwd")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_windows_drive_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "C:\\Windows\\system32\\config")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_windows_drive_relative_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "C:relative_file.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_unc_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "\\\\server\\share\\file.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_rooted_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "\\Windows\\file.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_parent_traversal(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("secret", encoding="utf-8")

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "../outside.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_nested_parent_traversal(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "src").mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "src/../../outside.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


def test_reject_nonexistent_traversal(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "nonexistent/../../outside_nonexistent.py")

    err = exc_info.value
    assert err.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


# --- Symlink Tests ---


def test_symlink_inside_repo_allowed(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    target_file = repo_root / "real_file.py"
    target_file.write_text(f"content={SOURCE_CANARY}", encoding="utf-8")
    link_file = repo_root / "link_file.py"

    try:
        link_file.symlink_to(target_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation not supported on Windows without admin privileges: {exc}")

    res = read_repository_source(repo_root, "link_file.py")
    assert res.text == f"content={SOURCE_CANARY}"


def test_symlink_escaping_repo_blocked(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    secret_file = tmp_path / "secret_outside.py"
    secret_file.write_text(SOURCE_CANARY, encoding="utf-8")

    link_file = repo_root / "escaped_link.py"
    try:
        link_file.symlink_to(secret_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation not supported on Windows without admin privileges: {exc}")

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "escaped_link.py")
    assert exc_info.value.error_code == "CONTEXT_PATH_OUTSIDE_REPOSITORY"


# --- Source File Behavior & Edge Cases ---


def test_source_file_not_found_inside_repo(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "missing.py")
    assert exc_info.value.error_code == "CONTEXT_SOURCE_FILE_NOT_FOUND"


def test_source_path_is_directory(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    sub_dir = repo_root / "sub_dir"
    sub_dir.mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "sub_dir")
    assert exc_info.value.error_code == "CONTEXT_SOURCE_NOT_REGULAR_FILE"


def test_invalid_max_file_size_limit(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "app.py", max_file_size_bytes=0)
    assert exc_info.value.error_code == "CONTEXT_INVALID_SIZE_LIMIT"

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "app.py", max_file_size_bytes=-10)
    assert exc_info.value.error_code == "CONTEXT_INVALID_SIZE_LIMIT"


def test_file_exceeds_size_limit_via_stat(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    large_file = repo_root / "large.py"
    large_file.write_bytes(b"x" * 200)

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "large.py", max_file_size_bytes=100)
    assert exc_info.value.error_code == "CONTEXT_SOURCE_FILE_TOO_LARGE"


def test_file_grows_after_stat_bounded_read_defense(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "growing.py"
    f.write_bytes(b"x" * 50)

    # Mock stat().st_size to return small size (e.g. 50), but open().read() returns 200 bytes
    mock_st = MagicMock()
    mock_st.st_size = 50
    mock_st.st_mode = 33188  # regular file mode

    orig_os_stat = os.stat

    def selective_os_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if isinstance(path, (str, Path)) and "growing.py" in str(path):
            return mock_st
        return orig_os_stat(path, *args, **kwargs)

    with patch("os.stat", side_effect=selective_os_stat), patch.object(
        Path, "open", mock_open(read_data=b"y" * 200)
    ), pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "growing.py", max_file_size_bytes=100)

    assert exc_info.value.error_code == "CONTEXT_SOURCE_FILE_TOO_LARGE"


def test_unsupported_encoding(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    binary_file = repo_root / "invalid.py"
    # Invalid UTF-8 bytes
    binary_file.write_bytes(b"\x80\x81\xfe\xff")

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "invalid.py")
    assert exc_info.value.error_code == "CONTEXT_SOURCE_UNSUPPORTED_ENCODING"


def test_permission_error_during_read(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "locked.py"
    f.write_text("code", encoding="utf-8")

    with (
        patch.object(Path, "open", side_effect=PermissionError("Permission denied")),
        pytest.raises(SastTriageError) as exc_info,
    ):
        read_repository_source(repo_root, "locked.py")

    assert exc_info.value.error_code == "CONTEXT_SOURCE_READ_ERROR"


def test_generic_os_error_during_stat(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "error.py"
    f.write_text("code", encoding="utf-8")

    orig_os_stat = os.stat

    def failing_os_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if isinstance(path, (str, Path)) and "error.py" in str(path):
            raise OSError("Drive I/O failure")
        return orig_os_stat(path, *args, **kwargs)

    with patch("os.stat", side_effect=failing_os_stat), pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "error.py")

    assert exc_info.value.error_code == "CONTEXT_SOURCE_READ_ERROR"


# --- Security Invariants & Canary Protection ---


def test_source_canary_not_in_exception_safe_message(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "bad_encoding.py"
    f.write_bytes(b"CANARY=" + SOURCE_CANARY.encode() + b"\x80\x81")

    with pytest.raises(SastTriageError) as exc_info:
        read_repository_source(repo_root, "bad_encoding.py")

    err = exc_info.value
    assert SOURCE_CANARY not in err.safe_message
    assert SOURCE_CANARY not in repr(err)
    assert str(repo_root.resolve()) not in err.safe_message


def test_reader_no_side_effects_on_file(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    f = repo_root / "unmodified.py"
    original_content = "def test():\n    pass\n"
    f.write_text(original_content, encoding="utf-8")

    read_repository_source(repo_root, "unmodified.py")

    assert f.read_text(encoding="utf-8") == original_content
