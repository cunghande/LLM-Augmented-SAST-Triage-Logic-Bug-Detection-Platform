from pathlib import Path
from unittest.mock import patch

from sast_triage.application.repository_state import read_repository_state


def test_repository_state_reads_only_safe_head_and_clean_state(tmp_path: Path) -> None:
    completed = [
        type("Completed", (), {"returncode": 0, "stdout": b"a" * 40 + b"\n"})(),
        type("Completed", (), {"returncode": 0, "stdout": b""})(),
    ]
    with (
        patch("sast_triage.application.repository_state.shutil.which", return_value="git"),
        patch("sast_triage.application.repository_state.subprocess.run", side_effect=completed) as run,
    ):
        commit, state = read_repository_state(tmp_path)

    assert commit == "a" * 40
    assert state == "clean"
    assert run.call_args_list[0].args[0][-3:] == ["rev-parse", "--verify", "HEAD"]
    assert run.call_args_list[1].args[0][-3:] == ["status", "--porcelain", "--untracked-files=no"]
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)


def test_repository_state_does_not_expose_invalid_git_output(tmp_path: Path) -> None:
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": b"not-a-commit-or-safe-value\n"},
    )()
    with (
        patch("sast_triage.application.repository_state.shutil.which", return_value="git"),
        patch("sast_triage.application.repository_state.subprocess.run", return_value=completed),
    ):
        assert read_repository_state(tmp_path) == (None, None)


def test_repository_state_marks_nonempty_porcelain_as_dirty(tmp_path: Path) -> None:
    completed = [
        type("Completed", (), {"returncode": 0, "stdout": b"b" * 40 + b"\n"})(),
        type("Completed", (), {"returncode": 0, "stdout": b" M private-name.py\n"})(),
    ]
    with (
        patch("sast_triage.application.repository_state.shutil.which", return_value="git"),
        patch("sast_triage.application.repository_state.subprocess.run", side_effect=completed),
    ):
        commit, state = read_repository_state(tmp_path)

    assert commit == "b" * 40
    assert state == "dirty"
