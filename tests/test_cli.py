"""Offline CLI integration tests using existing scanner artifacts and Fake provider."""

import json
from pathlib import Path

import pytest

from sast_triage.cli import EXIT_SUCCESS, main
from sast_triage.models import ScannerType
from sast_triage.runners.scanners import ScannerRunResult


def test_triage_cli_writes_both_reports_and_metadata(tmp_path: Path) -> None:
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


def test_cli_help_is_available() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["triage", "--help"])
    assert exc_info.value.code == 0


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
        "sast_triage.cli.SemgrepRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.SEMGREP, semgrep, (), True, 0),
    )
    monkeypatch.setattr(
        "sast_triage.cli.GitleaksRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.GITLEAKS, gitleaks, (), True, 0),
    )

    assert main(["scan-and-triage", "--repository", str(repo), "--output-dir", str(output), "--provider", "fake"]) == EXIT_SUCCESS
    metadata = json.loads((output / "run-metadata.json").read_text(encoding="utf-8"))
    assert metadata["cli_mode"] == "scan-and-triage"
    assert json.loads((output / "report.json").read_text(encoding="utf-8"))["results"] == []
