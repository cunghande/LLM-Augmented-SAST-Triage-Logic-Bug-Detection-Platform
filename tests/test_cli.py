"""Offline CLI integration tests using existing scanner artifacts and Fake provider."""

import json
from contextlib import contextmanager
from pathlib import Path

import pytest

from sast_triage.cli import (
    EXIT_PROVIDER_RESOURCE_EXHAUSTED,
    EXIT_SUCCESS,
    build_parser,
    main,
)
from sast_triage.errors import SastTriageError
from sast_triage.models import ScannerType, TriageInput
from sast_triage.runners.scanners import ScannerRunResult
from sast_triage.triage.fake_provider import FakeTriageProvider


def test_triage_cli_writes_both_reports_and_metadata(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps({"results": [{"check_id": "r", "path": "app.py", "start": {"line": 1}, "extra": {"message": "msg", "lines": "x = 1"}}]}),
        encoding="utf-8",
    )
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")
    output = tmp_path / "output"
    exit_code = main(["triage", "--repository", str(repo), "--semgrep-json", str(semgrep), "--gitleaks-json", str(gitleaks), "--output-dir", str(output), "--provider", "fake"])
    assert exit_code == EXIT_SUCCESS
    assert (output / "report.json").is_file()
    assert (output / "report.md").is_file()
    assert (output / "run-metadata.json").is_file()
    assert "x = 1" not in (output / "report.json").read_text(encoding="utf-8")
    progress = capsys.readouterr().out
    assert "[1/7] Đang kiểm tra repository" in progress
    assert "[3/7] Đã parse 1 finding" in progress
    assert "[5/7] Tiến độ triage 1/1" in progress
    assert "[7/7] Đã ghi báo cáo và metadata thành công" in progress


def test_cli_prints_safe_operational_error(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "scan-and-triage",
            "--repository",
            str(tmp_path / "missing-repository"),
            "--output-dir",
            str(tmp_path / "output"),
            "--provider",
            "fake",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code != EXIT_SUCCESS
    assert "LỖI [CLI_INVALID_REPOSITORY]" in captured.err
    assert "Traceback" not in captured.err


def test_cli_help_is_available() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["triage", "--help"])
    assert exc_info.value.code == 0


def test_module2_discovery_is_explicitly_opt_in() -> None:
    parser = build_parser()
    common = [
        "triage",
        "--repository",
        "repo",
        "--semgrep-json",
        "semgrep.json",
        "--gitleaks-json",
        "gitleaks.json",
        "--output-dir",
        "output",
    ]

    default_args = parser.parse_args(common)
    enabled_args = parser.parse_args([*common, "--module2-discovery"])

    assert default_args.module2 is True
    assert default_args.module2_discovery is False
    assert enabled_args.module2_discovery is True
    logic_args = parser.parse_args([*common, "--logic-detector", "fastapi-missing-authz"])
    assert logic_args.logic_detector == "fastapi-missing-authz"


def test_cli_fastapi_logic_detector_uses_shared_pipeline(tmp_path: Path, capsys) -> None:
    output = tmp_path / "logic-output"
    assert main(
        [
            "triage",
            "--repository",
            "tests/fixtures/fastapi_authz",
            "--semgrep-json",
            "tests/fixtures/semgrep/empty.json",
            "--gitleaks-json",
            "tests/fixtures/gitleaks/empty.json",
            "--output-dir",
            str(output),
            "--provider",
            "fake",
            "--logic-detector",
            "fastapi-missing-authz",
        ]
    ) == EXIT_SUCCESS
    metadata = json.loads((output / "run-metadata.json").read_text(encoding="utf-8"))
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert metadata["logic_detector"] == "fastapi-missing-authz"
    assert metadata["logic_detector_version"] == "sprint2-v2"
    assert len(report["results"]) == 1
    assert report["results"][0]["finding"]["rule_id"] == "module2.fastapi.missing-function-authz"
    assert "Traceback" not in capsys.readouterr().out


def test_scan_and_triage_cli_reuses_shared_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(json.dumps({"results": []}), encoding="utf-8")
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        "sast_triage.application.artifacts.SemgrepRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.SEMGREP, semgrep, (), True, 0),
    )
    monkeypatch.setattr(
        "sast_triage.application.artifacts.GitleaksRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.GITLEAKS, gitleaks, (), True, 0),
    )

    assert main(["scan-and-triage", "--repository", str(repo), "--output-dir", str(output), "--provider", "fake"]) == EXIT_SUCCESS
    metadata = json.loads((output / "run-metadata.json").read_text(encoding="utf-8"))
    assert metadata["cli_mode"] == "scan-and-triage"
    assert json.loads((output / "report.json").read_text(encoding="utf-8"))["results"] == []


def test_cli_checkpoints_modal_exhaustion_and_resumes_with_ollama(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "r1",
                        "path": "app.py",
                        "start": {"line": 1},
                        "extra": {"message": "one", "lines": "x = 1"},
                    },
                    {
                        "check_id": "r2",
                        "path": "app.py",
                        "start": {"line": 2},
                        "extra": {"message": "two", "lines": "y = 2"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")
    output = tmp_path / "output"
    calls = {"modal": 0, "ollama": 0}

    class ExhaustingProvider:
        provider_name = "real-modal-qwen"
        model_version = "Qwen/Qwen3-14B-AWQ"

        def __init__(self) -> None:
            self._fake = FakeTriageProvider()

        def triage(self, triage_input: TriageInput):
            calls["modal"] += 1
            if calls["modal"] == 2:
                raise SastTriageError(
                    "Modal quota exhausted.",
                    "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED",
                    retryable=True,
                )
            return self._fake.triage(triage_input)

    class CountingOllamaProvider:
        provider_name = "ollama"
        model_version = "qwen3:8b"

        def __init__(self) -> None:
            self._fake = FakeTriageProvider()

        def triage(self, triage_input: TriageInput):
            calls["ollama"] += 1
            return self._fake.triage(triage_input)

    @contextmanager
    def provider_session(provider_name):
        if provider_name == "real":
            yield ExhaustingProvider()
        else:
            yield CountingOllamaProvider()

    monkeypatch.setattr("sast_triage.application.run.provider_session", provider_session)
    base_args = [
        "triage",
        "--repository",
        str(repo),
        "--semgrep-json",
        str(semgrep),
        "--gitleaks-json",
        str(gitleaks),
        "--output-dir",
        str(output),
    ]

    assert main([*base_args, "--provider", "real"]) == EXIT_PROVIDER_RESOURCE_EXHAUSTED
    checkpoint = json.loads((output / "triage-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "resource_exhausted"
    assert checkpoint["completed_count"] == 1
    assert "x = 1" not in json.dumps(checkpoint)

    assert main([*base_args, "--provider", "ollama", "--resume"]) == EXIT_SUCCESS
    assert calls == {"modal": 2, "ollama": 1}
    assert not (output / "triage-checkpoint.json").exists()
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert len(report["results"]) == 2
    assert report["run_metadata"]["triage_provider"] == "real-modal-qwen -> ollama"
