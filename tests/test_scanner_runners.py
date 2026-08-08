"""Offline tests for scanner subprocess safety."""

import json
from pathlib import Path
from unittest.mock import patch

from sast_triage.runners.scanners import GitleaksRunner, SemgrepRunner


def test_semgrep_runner_uses_safe_arguments_and_writes_artifact(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "run"
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = b'{"results": []}'
        result = SemgrepRunner(timeout_seconds=5).run(repo, output)
    assert result.succeeded is True
    assert result.artifact_path is not None and result.artifact_path.read_bytes() == b'{"results": []}'
    args = run.call_args.args[0]
    assert isinstance(args, list)
    assert args[-1] == str(repo.resolve())
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["cwd"] == repo.resolve()


def test_gitleaks_findings_exit_code_is_success(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 1
        run.return_value.stdout = b"[]"
        result = GitleaksRunner().run(repo, tmp_path / "run")
    assert result.succeeded is True


def test_runner_preserves_scanner_written_artifact(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "run"
    artifact = output / "semgrep.json"

    def run_scanner(*args: object, **kwargs: object) -> object:
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b'{"results": [{"scanner": "artifact"}]}')
        return type("Completed", (), {"returncode": 0, "stdout": b'{"results": []}'})()

    with patch("sast_triage.runners.scanners.subprocess.run", side_effect=run_scanner):
        result = SemgrepRunner().run(repo, output)
    assert result.succeeded is True
    assert artifact.read_bytes() == b'{"results": [{"scanner": "artifact"}]}'


def test_runner_failure_does_not_leak_stderr_or_canary(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("sast_triage.runners.scanners.subprocess.run", side_effect=FileNotFoundError("SCANNER_RUNNER_CANARY_DO_NOT_LEAK")):
        result = SemgrepRunner().run(repo, tmp_path / "run")
    assert result.succeeded is False
    assert "SCANNER_RUNNER_CANARY_DO_NOT_LEAK" not in result.errors[0].safe_message


def test_semgrep_runner_normalizes_absolute_result_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")
    artifact_payload = {
        "results": [
            {
                "check_id": "rule",
                "path": str(source.resolve()),
                "start": {"line": 1},
                "extra": {"message": "message"},
            }
        ]
    }
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(artifact_payload).encode("utf-8")
        result = SemgrepRunner().run(repo, tmp_path / "run")

    assert result.succeeded is True
    assert result.artifact_path is not None
    artifact = json.loads(result.artifact_path.read_text(encoding="utf-8"))
    assert artifact["results"][0]["path"] == "app.py"


def test_semgrep_runner_rejects_result_path_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    artifact_payload = {
        "results": [
            {
                "check_id": "rule",
                "path": str(outside.resolve()),
                "start": {"line": 1},
                "extra": {"message": "message"},
            }
        ]
    }
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(artifact_payload).encode("utf-8")
        result = SemgrepRunner().run(repo, tmp_path / "run")

    assert result.succeeded is False
    assert result.errors[0].error_code == "SCANNER_ARTIFACT_PATH_INVALID"
    assert str(outside.resolve()) not in result.errors[0].safe_message
