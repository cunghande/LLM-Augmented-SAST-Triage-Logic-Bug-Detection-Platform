"""Chạy semantic regression test DjangoGoat bằng Qwen3-14B-AWQ trên Modal."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import modal

from modal_apps.qwen14b_benchmark import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_VERSION,
    ModalQwenProvider,
)
from modal_apps.qwen14b_modal import Qwen14B, app
from sast_triage.models import ArtifactRepositoryMatch, BatchResult
from sast_triage.parsers.gitleaks import parse_gitleaks_json
from sast_triage.parsers.semgrep import parse_semgrep_json
from sast_triage.pipeline.batch import triage_batch
from sast_triage.reporting.json_reporter import write_json_report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = PROJECT_ROOT / "benchmarks" / "ExternalTargets"
ARTIFACT_ROOT = PROJECT_ROOT / "benchmarks" / "BenchmarkOutput"

BRANCHES: tuple[tuple[str, str], ...] = (
    ("master", "5e6aaa6d0497bf24abd179304e6ca51295a8091d"),
    ("broken", "b5123eba8c002adb4f5513197e7e69a724385d29"),
)


def _triage_branch(branch: str, commit_sha: str, provider: ModalQwenProvider) -> BatchResult:
    """Triage một nhánh từ artifact scanner đã tạo, không quét lại repository."""
    repository = TARGET_ROOT / f"DjangoGoat-{branch}"
    artifact_dir = ARTIFACT_ROOT / f"djangogoat-{branch}" / "scanner-artifacts"
    semgrep_result = parse_semgrep_json(artifact_dir / "semgrep.json")
    gitleaks_result = parse_gitleaks_json(artifact_dir / "gitleaks.json")
    return triage_batch(
        repository,
        provider,
        semgrep_result=semgrep_result,
        gitleaks_result=gitleaks_result,
        repository_identifier=f"red-and-black/DjangoGoat@{branch}",
        commit_sha=commit_sha,
        working_tree_state="clean",
        artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
        prompt_version=PROMPT_VERSION,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
        prompt_type="modal-qwen.djangogoat-semantic-v1",
        cli_mode="benchmark-modal-qwen-djangogoat",
    )


def _write_reports(branch: str, result: BatchResult) -> None:
    """Ghi báo cáo canonical JSON cho một nhánh."""
    output_dir = ARTIFACT_ROOT / f"djangogoat-{branch}" / "qwen"
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json_report(result, output_dir / "report.json", overwrite=True)


def _summary(result: BatchResult) -> dict[str, object]:
    """Tạo tóm tắt an toàn, không chứa mã nguồn hoặc response thô."""
    actions: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    for item in result.results:
        action = item.policy_decision.action.value
        actions[action] = actions.get(action, 0) + 1
        if item.triage_decision is not None:
            verdict = item.triage_decision.model_verdict.value
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
    return {
        "findings": len(result.results),
        "findings_with_errors": result.run_metadata.findings_with_errors,
        "scanner_errors": len(result.scanner_errors),
        "model_verdicts": verdicts,
        "policy_actions": actions,
    }


def main() -> int:
    """Chạy hai nhánh trong cùng một phiên Modal để giảm cold-start và chi phí."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    started = time.perf_counter()
    results: dict[str, BatchResult] = {}
    with modal.enable_output(), app.run():
        provider = ModalQwenProvider(Qwen14B())
        for branch, commit_sha in BRANCHES:
            results[branch] = _triage_branch(branch, commit_sha, provider)
    for branch, result in results.items():
        _write_reports(branch, result)
    output = {
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "branches": {branch: _summary(result) for branch, result in results.items()},
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
