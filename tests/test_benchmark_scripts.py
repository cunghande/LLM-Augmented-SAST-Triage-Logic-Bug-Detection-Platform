"""Regression tests for reproducible Sprint 2 benchmark orchestration."""

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_joern_benchmark_script() -> ModuleType:
    script = Path(__file__).parents[1] / "scripts" / "benchmark_realvuln_joern.py"
    spec = importlib.util.spec_from_file_location("benchmark_realvuln_joern", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_logic_llm_benchmark_script() -> ModuleType:
    script = Path(__file__).parents[1] / "scripts" / "benchmark_logic_bugs_llm.py"
    spec = importlib.util.spec_from_file_location("benchmark_logic_bugs_llm", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benchmark_cache_rejects_partial_scanner_run(tmp_path: Path) -> None:
    module = _load_joern_benchmark_script()
    report = tmp_path / "report.json"
    metadata = {
        "commit_sha": "abc123",
        "analysis_backend": "joern",
        "cpg_build_status": "complete",
        "triage_provider": "fake",
        "scanners_succeeded": ["GITLEAKS", "MODULE2"],
    }
    report.write_text(json.dumps({"run_metadata": metadata}), encoding="utf-8")

    assert module._report_is_current(report, "abc123", "fake") is False

    metadata["scanners_succeeded"].append("SEMGREP")
    report.write_text(json.dumps({"run_metadata": metadata}), encoding="utf-8")
    assert module._report_is_current(report, "abc123", "fake") is True


def test_docker_benchmark_command_uses_container_paths(tmp_path: Path) -> None:
    module = _load_joern_benchmark_script()
    repository = tmp_path / "repo"
    output = tmp_path / "output"
    repository.mkdir()
    output.mkdir()

    command = module._pipeline_command(
        runtime="docker",
        app_image="sast-triage-app:test",
        docker_network="sast-triage-test",
        repository=repository,
        run_dir=output,
        repo_id="repo-id",
        provider="fake",
    )

    assert command[:3] == ["docker", "run", "--rm"]
    assert "sast-triage-app:test" in command
    assert "/workspace/repository" in command
    assert "/workspace/output" in command
    assert f"{repository.resolve()}:/workspace/repository:ro" in command
    assert f"{output.resolve()}:/workspace/output" in command


def test_logic_llm_benchmark_resolves_repo_id_from_ground_truth(
    tmp_path: Path,
) -> None:
    module = _load_logic_llm_benchmark_script()
    repos_root = tmp_path / "repos"
    ground_truth = tmp_path / "ground-truth" / "realvuln-long-checkout-name"
    checkout = repos_root / "realvuln-long-checkout-name"
    checkout.mkdir(parents=True)
    ground_truth.mkdir(parents=True)
    (ground_truth / "ground-truth.json").write_text(
        json.dumps({"repo_id": "short-id"}),
        encoding="utf-8",
    )

    assert module._repository_checkout(repos_root, "short-id") == checkout
