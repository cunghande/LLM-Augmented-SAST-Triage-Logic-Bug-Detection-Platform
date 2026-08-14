"""Run a 20-repository, three-repeat offline paired pipeline regression."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.runners.scanners import GitleaksRunner, SemgrepRunner

AUTO_ACTIONS = {"LIKELY_TP", "FP_CANDIDATE"}


def _projection(report_path: Path) -> dict[str, dict[str, str | None]]:
    """Project report decisions without retaining prompts, responses or source."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    projected: dict[str, dict[str, str | None]] = {}
    for result in report.get("results", []):
        finding = result.get("finding", {})
        decision = result.get("triage_decision") or {}
        policy = result.get("policy_decision", {})
        identifier = finding.get("finding_instance_id")
        if not isinstance(identifier, str):
            continue
        projected[identifier] = {
            "scanner": finding.get("scanner"),
            "verdict": decision.get("model_verdict"),
            "action": policy.get("action"),
        }
    return projected


def _run_cli(
    python: Path,
    repository: Path,
    repository_id: str,
    semgrep: Path,
    gitleaks: Path,
    output: Path,
    logic_detector: str,
) -> tuple[int, float]:
    """Run one captured fake-provider branch and return only safe status/timing."""
    command = [
        str(python), "-m", "sast_triage", "triage",
        "--repository", str(repository),
        "--repository-identifier", repository_id,
        "--output-dir", str(output),
        "--provider", "fake",
        "--analysis-backend", "native",
        "--semgrep-json", str(semgrep),
        "--gitleaks-json", str(gitleaks),
        "--logic-detector", logic_detector,
        "--overwrite",
    ]
    started = time.perf_counter()
    completed = subprocess.run(command, capture_output=True, check=False, shell=False, timeout=300)
    return completed.returncode, time.perf_counter() - started


def _stable(reference: dict[str, dict[str, str | None]], candidate: dict[str, dict[str, str | None]], key: str) -> tuple[int, int]:
    """Count stable values for common finding IDs."""
    common = set(reference) & set(candidate)
    return sum(reference[item].get(key) == candidate[item].get(key) for item in common), len(common)


def main() -> int:
    """Scan once per repo, then execute baseline/candidate paired repetitions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    repositories = sorted(path for path in args.repos_root.glob("vc-*-fastapi") if path.is_dir())[: args.limit]
    if len(repositories) != args.limit:
        raise SystemExit(f"Expected {args.limit} FastAPI repositories, found {len(repositories)}.")
    scan_status: list[dict[str, Any]] = []
    run_records: list[dict[str, Any]] = []
    projections: dict[tuple[str, str, int], dict[str, dict[str, str | None]]] = {}
    with tempfile.TemporaryDirectory(prefix="sast-triage-regression-") as temp:
        temporary = Path(temp)
        for repo_index, repository in enumerate(repositories, start=1):
            repository_id = repository.name
            scan_dir = temporary / "scanner" / repository_id
            semgrep = SemgrepRunner(timeout_seconds=300, config="p/python").run(repository, scan_dir)
            gitleaks = GitleaksRunner(timeout_seconds=300).run(repository, scan_dir)
            scan_status.append(
                {
                    "repository": repository_id,
                    "semgrep_succeeded": semgrep.succeeded,
                    "gitleaks_succeeded": gitleaks.succeeded,
                    "semgrep_exit_code": semgrep.exit_code,
                    "gitleaks_exit_code": gitleaks.exit_code,
                }
            )
            if not semgrep.succeeded or not gitleaks.succeeded or semgrep.artifact_path is None or gitleaks.artifact_path is None:
                continue
            for repetition in range(1, args.repetitions + 1):
                for branch, detector in (("baseline", "off"), ("candidate", "fastapi-missing-authz")):
                    output_dir = temporary / "runs" / f"repeat-{repetition}" / branch / repository_id
                    exit_code, elapsed = _run_cli(
                        args.python,
                        repository,
                        repository_id,
                        semgrep.artifact_path,
                        gitleaks.artifact_path,
                        output_dir,
                        detector,
                    )
                    report_path = output_dir / "report.json"
                    projection = _projection(report_path) if exit_code == 0 and report_path.is_file() else {}
                    projections[(repository_id, branch, repetition)] = projection
                    actions = Counter(item.get("action") for item in projection.values())
                    run_records.append(
                        {
                            "repository": repository_id,
                            "repository_index": repo_index,
                            "repetition": repetition,
                            "branch": branch,
                            "exit_code": exit_code,
                            "elapsed_seconds": round(elapsed, 3),
                            "finding_count": len(projection),
                            "module2_finding_count": sum(item.get("scanner") == "MODULE2" for item in projection.values()),
                            "manual_review_count": actions["MANUAL_REVIEW"],
                            "triage_error_count": actions["TRIAGE_ERROR"],
                            "auto_decision_count": sum(actions[action] for action in AUTO_ACTIONS),
                        }
                    )
    common_policy_stable = common_policy_total = 0
    common_verdict_stable = common_verdict_total = 0
    repeat_policy_stable = repeat_policy_total = 0
    repeat_verdict_stable = repeat_verdict_total = 0
    for repository in repositories:
        repository_id = repository.name
        for repetition in range(1, args.repetitions + 1):
            baseline = projections.get((repository_id, "baseline", repetition), {})
            candidate = projections.get((repository_id, "candidate", repetition), {})
            stable, total = _stable(baseline, candidate, "action")
            common_policy_stable += stable
            common_policy_total += total
            stable, total = _stable(baseline, candidate, "verdict")
            common_verdict_stable += stable
            common_verdict_total += total
        for branch in ("baseline", "candidate"):
            reference = projections.get((repository_id, branch, 1), {})
            for repetition in range(2, args.repetitions + 1):
                current = projections.get((repository_id, branch, repetition), {})
                stable, total = _stable(reference, current, "action")
                repeat_policy_stable += stable
                repeat_policy_total += total
                stable, total = _stable(reference, current, "verdict")
                repeat_verdict_stable += stable
                repeat_verdict_total += total
    summary = {
        "benchmark": "sprint2-fastapi-authz-offline-pipeline-regression",
        "provider": "fake",
        "real_llm_quality_claim_supported": False,
        "repository_count": len(repositories),
        "repetitions": args.repetitions,
        "paired_run_count": len(run_records),
        "scanner_success_count": sum(item["semgrep_succeeded"] and item["gitleaks_succeeded"] for item in scan_status),
        "common_policy_action_stability": common_policy_stable / common_policy_total if common_policy_total else 0.0,
        "common_verdict_stability": common_verdict_stable / common_verdict_total if common_verdict_total else 0.0,
        "repeat_policy_action_stability": repeat_policy_stable / repeat_policy_total if repeat_policy_total else 0.0,
        "repeat_verdict_stability": repeat_verdict_stable / repeat_verdict_total if repeat_verdict_total else 0.0,
        "provider_or_pipeline_error_runs": sum(item["exit_code"] != 0 for item in run_records),
        "triage_error_count": sum(item["triage_error_count"] for item in run_records),
        "baseline_finding_count_mean": (
            sum(item["finding_count"] for item in run_records if item["branch"] == "baseline")
            / max(1, sum(item["branch"] == "baseline" for item in run_records))
        ),
        "candidate_finding_count_mean": (
            sum(item["finding_count"] for item in run_records if item["branch"] == "candidate")
            / max(1, sum(item["branch"] == "candidate" for item in run_records))
        ),
        "scan_status": scan_status,
        "runs": run_records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"Pipeline regression: repos={summary['repository_count']} paired_runs={summary['paired_run_count']} "
        f"scanner_success={summary['scanner_success_count']} "
        f"common_policy_stability={summary['common_policy_action_stability']:.3f} "
        f"errors={summary['provider_or_pipeline_error_runs']}"
    )
    return 0 if summary["scanner_success_count"] == len(repositories) and summary["provider_or_pipeline_error_runs"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
