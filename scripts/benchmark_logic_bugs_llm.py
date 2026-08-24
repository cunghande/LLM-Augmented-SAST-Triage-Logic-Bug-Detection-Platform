"""Run a real-LLM pilot over reviewed IDOR/business-rule candidates."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

from sast_triage.logic.index import build_logic_index
from sast_triage.models import ArtifactRepositoryMatch, ModelVerdict
from sast_triage.pipeline.finding import triage_finding
from sast_triage.triage.modal_provider import MODEL_ID, modal_qwen_provider_session

_CLASS_ORDER = (
    "missing_authz_idor",
    "business_rule_bypass",
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detector-report", type=Path, required=True)
    parser.add_argument("--repos-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--positive-per-class", type=int, default=1)
    parser.add_argument("--negative-limit", type=int, default=2)
    parser.add_argument("--prompt-version", default="triage-prompt-v14")
    return parser.parse_args()


def _select_cases(
    report: dict[str, Any],
    positive_per_class: int,
    negative_limit: int,
) -> list[dict[str, Any]]:
    cases = [item for item in report.get("cases", []) if item.get("detected")]
    selected: list[dict[str, Any]] = []
    for logic_class in _CLASS_ORDER:
        bucket = [
            item
            for item in cases
            if item.get("expected") is True
            and item.get("logic_class") == logic_class
        ]
        selected.extend(bucket[:positive_per_class])
    negatives = [item for item in cases if item.get("expected") is False]
    selected.extend(negatives[:negative_limit])
    return selected


def _metric(rows: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [item for item in rows if not item["triage_error"]]
    decisive = [item for item in completed if not item["abstained"]]
    correct = sum(bool(item["correct"]) for item in decisive)
    durations = sorted(
        int(item["provider_duration_ms"])
        for item in completed
        if item["provider_duration_ms"] is not None
    )
    warm_durations = durations[:-1] if len(durations) > 1 else durations
    warm_median = median(warm_durations) if warm_durations else None
    return {
        "cases": len(rows),
        "positive_cases": sum(bool(item["expected"]) for item in rows),
        "negative_cases": sum(not bool(item["expected"]) for item in rows),
        "completed": len(completed),
        "triage_errors": sum(bool(item["triage_error"]) for item in rows),
        "decisive": len(decisive),
        "abstentions": sum(bool(item["abstained"]) for item in completed),
        "correct_decisive": correct,
        "wrong_decisive": len(decisive) - correct,
        "selective_accuracy": correct / len(decisive) if decisive else None,
        "coverage": len(decisive) / len(rows) if rows else None,
        "provider_duration_total_ms": sum(durations),
        "provider_duration_max_ms": max(durations, default=None),
        "warm_provider_duration_median_ms": warm_median,
    }


def _repository_checkout(repos_root: Path, repository_id: str) -> Path:
    """Resolve a benchmark repo ID to its checkout without guessing URL slugs."""
    direct_candidates = (
        repos_root / repository_id,
        repos_root / f"realvuln-{repository_id}",
    )
    for candidate in direct_candidates:
        if candidate.is_dir():
            return candidate

    ground_truth_root = repos_root.parent / "ground-truth"
    for ground_truth_path in sorted(ground_truth_root.glob("*/ground-truth.json")):
        document = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        if str(document.get("repo_id", "")) != repository_id:
            continue
        candidate = repos_root / ground_truth_path.parent.name
        if candidate.is_dir():
            return candidate

    raise FileNotFoundError(f"Repository checkout unavailable: {repository_id}")


def run_pilot(
    detector_report: Path,
    repos_root: Path,
    *,
    positive_per_class: int,
    negative_limit: int,
    prompt_version: str,
) -> dict[str, Any]:
    """Triage a balanced reviewed pilot with the real Modal provider."""
    report = json.loads(detector_report.read_text(encoding="utf-8"))
    selected = _select_cases(report, positive_per_class, negative_limit)
    if {item["logic_class"] for item in selected if item["expected"]} != set(
        _CLASS_ORDER
    ):
        raise ValueError("The selected detector report does not cover both focused classes.")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in selected:
        grouped[str(case["repository"])].append(case)

    rows: list[dict[str, Any]] = []
    with modal_qwen_provider_session() as provider:
        for repository_id, cases in grouped.items():
            repository = _repository_checkout(repos_root, repository_id)
            logic_index = build_logic_index(repository)
            findings = logic_index.discover_findings(())
            for case in cases:
                matched_lines = set(case.get("matched_lines", []))
                candidates = [
                    finding
                    for finding in findings
                    if finding.file_path == case["file_path"]
                    and finding.start_line in matched_lines
                    and finding.metadata.get("logic_class")
                    in set(case.get("accepted_logic_classes", [case["logic_class"]]))
                ]
                if not candidates:
                    raise ValueError(f"Candidate no longer reproducible: {case['case_id']}")
                finding = candidates[0]
                result = triage_finding(
                    finding,
                    repository,
                    provider,
                    prompt_version=prompt_version,
                    output_schema_version="triage-decision-v1",
                    prompt_type="modal-qwen.logic-benchmark",
                    artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
                    logic_index=logic_index,
                )
                decision = result.triage_decision
                triage_error = decision is None
                verdict = decision.model_verdict if decision is not None else None
                abstained = verdict == ModelVerdict.NEEDS_REVIEW
                predicted = verdict == ModelVerdict.LIKELY_TP
                correct = None if triage_error or abstained else predicted == case["expected"]
                rows.append(
                    {
                        "case_id": case["case_id"],
                        "repository": repository_id,
                        "logic_class": case["logic_class"],
                        "expected": case["expected"],
                        "file_path": finding.file_path,
                        "line": finding.start_line,
                        "model_verdict": verdict.value if verdict is not None else None,
                        "model_confidence": (
                            decision.model_confidence.value if decision is not None else None
                        ),
                        "model_summary": decision.summary if decision is not None else None,
                        "model_evidence": list(decision.evidence) if decision is not None else [],
                        "missing_information": (
                            list(decision.missing_information)
                            if decision is not None
                            else []
                        ),
                        "assumptions": (
                            list(decision.assumptions) if decision is not None else []
                        ),
                        "policy_action": result.policy_decision.action.value,
                        "abstained": abstained,
                        "correct": correct,
                        "triage_error": triage_error,
                        "processing_error_codes": [
                            error.error_code for error in result.processing_errors
                        ],
                        "provider_duration_ms": result.provider_duration_ms,
                    }
                )

    return {
        "schema_version": "logic-llm-pilot-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": report.get("dataset"),
        "detector_config_id": report.get("detector_config_id"),
        "model": MODEL_ID,
        "prompt_version": prompt_version,
        "logic_verification_retries": provider.logic_verification_retries,
        "selection": {
            "positive_per_class": positive_per_class,
            "negative_limit": negative_limit,
            "policy": (
                "Detected candidates only: one reviewed positive per class plus "
                "reviewed detector false positives. NEEDS_REVIEW is abstention."
            ),
        },
        "metrics": _metric(rows),
        "cases": rows,
    }


def main() -> int:
    """Run the pilot and write a source-free JSON artifact."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    args = _arguments()
    if args.positive_per_class <= 0 or args.negative_limit < 0:
        raise ValueError("Pilot limits are invalid.")
    result = run_pilot(
        args.detector_report.resolve(),
        args.repos_root.resolve(),
        positive_per_class=args.positive_per_class,
        negative_limit=args.negative_limit,
        prompt_version=args.prompt_version,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["metrics"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
