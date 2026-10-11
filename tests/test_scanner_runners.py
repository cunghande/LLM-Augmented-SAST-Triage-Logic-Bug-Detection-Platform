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
    assert args[:6] == [
        "semgrep",
        "scan",
        "--no-rewrite-rule-ids",
        "--config",
        "p/python",
        "--json",
    ]
    assert args[-1] == "."
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["cwd"] == repo.resolve()


def test_semgrep_runner_accepts_multiple_explicit_configs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = b'{"results": []}'
        result = SemgrepRunner(config=("p/python", "p/security-audit")).run(
            repo,
            tmp_path / "run",
        )
    command = run.call_args.args[0]
    assert command.count("--config") == 2
    assert "p/python" in command
    assert "p/security-audit" in command
    assert result.config_id == "p/python+p/security-audit"


def test_gitleaks_findings_exit_code_is_success(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with (
        patch("sast_triage.runners.scanners.shutil.which", return_value="/usr/bin/gitleaks"),
        patch("sast_triage.runners.scanners.subprocess.run") as run,
    ):
        run.return_value.returncode = 1
        run.return_value.stdout = b"[]"
        result = GitleaksRunner().run(repo, tmp_path / "run")
    assert result.succeeded is True


def test_gitleaks_runner_normalizes_absolute_result_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "settings.py"
    source.write_text("TOKEN = 'example'\n", encoding="utf-8")
    artifact_payload = [
        {
            "RuleID": "generic-api-key",
            "File": str(source.resolve()),
            "StartLine": 1,
            "EndLine": 1,
        }
    ]
    with (
        patch("sast_triage.runners.scanners.shutil.which", return_value="/usr/bin/gitleaks"),
        patch("sast_triage.runners.scanners.subprocess.run") as run,
    ):
        run.return_value.returncode = 1
        run.return_value.stdout = json.dumps(artifact_payload).encode("utf-8")
        result = GitleaksRunner().run(repo, tmp_path / "run")

    assert result.succeeded is True
    assert result.artifact_path is not None
    artifact = json.loads(result.artifact_path.read_text(encoding="utf-8"))
    assert artifact[0]["File"] == "settings.py"


def test_gitleaks_runner_rejects_result_path_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("TOKEN = 'example'\n", encoding="utf-8")
    artifact_payload = [
        {
            "RuleID": "generic-api-key",
            "File": str(outside.resolve()),
            "StartLine": 1,
            "EndLine": 1,
        }
    ]
    with (
        patch("sast_triage.runners.scanners.shutil.which", return_value="/usr/bin/gitleaks"),
        patch("sast_triage.runners.scanners.subprocess.run") as run,
    ):
        run.return_value.returncode = 1
        run.return_value.stdout = json.dumps(artifact_payload).encode("utf-8")
        result = GitleaksRunner().run(repo, tmp_path / "run")

    assert result.succeeded is False
    assert result.errors[0].error_code == "SCANNER_ARTIFACT_PATH_INVALID"
    assert str(outside.resolve()) not in result.errors[0].safe_message


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


def test_semgrep_runner_transcodes_invalid_source_bytes_in_generated_json(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "legacy.py"
    source.write_text("x = 1\n", encoding="utf-8")
    raw_path = json.dumps(str(source.resolve())).encode("utf-8")
    artifact_payload = (
        b'{"results":[{"check_id":"rule","path":'
        + raw_path
        + b',"start":{"line":1},"extra":{"message":"caf\xe9"}}]}'
    )
    with patch("sast_triage.runners.scanners.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = artifact_payload
        result = SemgrepRunner().run(repo, tmp_path / "run")

    assert result.succeeded is True
    assert result.artifact_path is not None
    artifact_text = result.artifact_path.read_text(encoding="utf-8")
    assert "caf�" in artifact_text
    assert json.loads(artifact_text)["results"][0]["path"] == "legacy.py"


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
