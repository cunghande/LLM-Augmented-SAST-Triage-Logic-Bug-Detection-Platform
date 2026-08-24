"""Tests for the user-friendly one-command CLI entrypoint."""

import json
from pathlib import Path

from sast_triage import entrypoint


def test_repository_shortcut_builds_real_qwen_scan(tmp_path: Path) -> None:
    repository = tmp_path / "target-repos" / "sample-repo"
    expected_root = tmp_path / "triage-runs"

    arguments = entrypoint._expand_repository_shortcut([str(repository)])

    assert arguments[:5] == [
        "scan-and-triage",
        "--repository",
        str(repository),
        "--output-dir",
        arguments[4],
    ]
    assert Path(arguments[4]).parent == expected_root
    assert Path(arguments[4]).name.startswith("sample-repo-qwen14b-")
    expected_cache = tmp_path / "triage-cache" / "sample-repo"
    assert arguments[5:] == [
        "--provider",
        "real",
        "--semgrep-config",
        "p/python",
        "--semgrep-config",
        "p/security-audit",
        "--module2-discovery",
        "--logic-detector",
        "python-idor-business-logic",
        "--decision-cache-dir",
        str(expected_cache),
        "--decision-cache-ttl-hours",
        "168",
        "--provider-cost-per-hour-usd",
        "6.25",
    ]


def test_repository_shortcut_preserves_extra_options(tmp_path: Path) -> None:
    repository = tmp_path / "target-repos" / "sample-repo"

    arguments = entrypoint._expand_repository_shortcut(
        [str(repository), "--no-module2"]
    )

    assert arguments[-1] == "--no-module2"


def test_repository_shortcut_allows_disabling_full_analysis_defaults(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "target-repos" / "sample-repo"

    arguments = entrypoint._expand_repository_shortcut(
        [
            str(repository),
            "--no-module2-discovery",
            "--logic-detector",
            "off",
        ]
    )

    assert arguments.count("--module2-discovery") == 0
    assert arguments.count("--logic-detector") == 1
    assert arguments[-3:] == ["--no-module2-discovery", "--logic-detector", "off"]


def test_repository_shortcut_preserves_cache_and_cost_overrides(tmp_path: Path) -> None:
    repository = tmp_path / "target-repos" / "sample-repo"

    arguments = entrypoint._expand_repository_shortcut(
        [
            str(repository),
            "--decision-cache-dir",
            "custom-cache",
            "--decision-cache-ttl-hours",
            "24",
            "--provider-cost-per-hour-usd",
            "7.00",
        ]
    )

    assert arguments.count("--decision-cache-dir") == 1
    assert arguments.count("--decision-cache-ttl-hours") == 1
    assert arguments.count("--provider-cost-per-hour-usd") == 1
    assert arguments[-6:] == [
        "--decision-cache-dir",
        "custom-cache",
        "--decision-cache-ttl-hours",
        "24",
        "--provider-cost-per-hour-usd",
        "7.00",
    ]


def test_explicit_commands_are_not_rewritten() -> None:
    arguments = ["scan-and-triage", "--repository", "repo"]

    assert entrypoint._expand_repository_shortcut(arguments) == arguments


def test_cache_clear_command_is_not_rewritten() -> None:
    arguments = ["cache-clear", "--cache-dir", ".cache"]

    assert entrypoint._expand_repository_shortcut(arguments) == arguments


def test_display_path_keeps_sibling_output_useful(
    tmp_path: Path, monkeypatch
) -> None:
    current = tmp_path / "target-repos"
    report = tmp_path / "triage-runs" / "run-01" / "report.md"
    current.mkdir()
    monkeypatch.chdir(current)

    displayed = entrypoint._display_path(report)

    assert displayed == str(Path("..") / "triage-runs" / "run-01" / "report.md")


def test_ollama_provider_remains_an_independent_cli_choice(monkeypatch) -> None:
    monkeypatch.delenv("SAST_TRIAGE_LLM_MODEL", raising=False)
    arguments, uses_ollama = entrypoint._prepare_arguments(
        ["scan-and-triage", "--provider", "ollama"]
    )

    assert uses_ollama is True
    assert arguments == ["scan-and-triage", "--provider", "ollama"]
    assert "SAST_TRIAGE_LLM_MODEL" not in entrypoint.os.environ


def test_argument_preparation_does_not_override_explicit_environment(monkeypatch) -> None:
    monkeypatch.setenv("SAST_TRIAGE_LLM_MODEL", "custom-local-model")

    entrypoint._prepare_arguments(["scan-and-triage", "--provider=ollama"])

    assert entrypoint.os.environ["SAST_TRIAGE_LLM_MODEL"] == "custom-local-model"


def test_entrypoint_prints_report_summary(tmp_path: Path, monkeypatch, capsys) -> None:
    output = tmp_path / "output"
    output.mkdir()

    def fake_cli(arguments: list[str]) -> int:
        assert "ollama" in arguments
        (output / "run-metadata.json").write_text(
            json.dumps(
                {
                    "total_findings_parsed": 12,
                    "findings_triaged_ok": 10,
                    "findings_with_errors": 2,
                }
            ),
            encoding="utf-8",
        )
        (output / "report.json").write_text("{}", encoding="utf-8")
        (output / "report.md").write_text("# report\n", encoding="utf-8")
        (output / "report.html").write_text("<!doctype html>\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(entrypoint, "run_cli", fake_cli)

    exit_code = entrypoint.main(
        [
            "scan-and-triage",
            "--repository",
            "repo",
            "--output-dir",
            str(output),
            "--provider",
            "ollama",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Đang bắt đầu scanner" in captured.out
    assert "đã_parse=12" in captured.out
    assert "triage_thành_công=10" in captured.out
    assert "report.json" in captured.out
    assert "report.html" in captured.out


def test_entrypoint_explains_modal_checkpoint_resume(tmp_path: Path, monkeypatch, capsys) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "triage-checkpoint.json").write_text(
        json.dumps(
            {
                "status": "resource_exhausted",
                "failure_code": "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED",
                "completed_count": 3,
                "total_count": 8,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(entrypoint, "run_cli", lambda arguments: 5)

    exit_code = entrypoint.main(
        [
            "scan-and-triage",
            "--repository",
            "repo",
            "--output-dir",
            str(output),
            "--provider",
            "real",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 5
    assert "3/8 finding" in captured.err
    assert "--provider ollama --resume" in captured.err
