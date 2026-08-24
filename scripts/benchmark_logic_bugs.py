"""Evaluate the focused IDOR/business-rule detector against reviewed ground truth.

Only explicitly mapped positive and negative labels contribute to metrics.
Predictions outside those labeled locations are reported as unreviewed and are
not silently counted as either true or false positives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sast_triage.logic import LogicBugClass, LogicCandidate
from sast_triage.logic.index import (
    LOGIC_DETECTOR_CONFIG_ID,
    build_logic_index,
)

_POSITIVE_CLASS_MAP: dict[str, LogicBugClass] = {
    "idor": LogicBugClass.MISSING_AUTHZ_IDOR,
    "missing_authorization": LogicBugClass.MISSING_AUTHZ_IDOR,
    "business_logic_flaw": LogicBugClass.BUSINESS_RULE_BYPASS,
    "business_logic_validation_gap": LogicBugClass.BUSINESS_RULE_BYPASS,
}
_NEGATIVE_CLASS_MAP: dict[str, LogicBugClass] = {
    "idor_false_positive": LogicBugClass.MISSING_AUTHZ_IDOR,
    "insecure_direct_object_reference_false_positive": LogicBugClass.MISSING_AUTHZ_IDOR,
}
_SPLIT_POLICY = "repository-sha256-v1-retrospective"


def _split_for_repository(repo_id: str) -> str:
    """Assign a stable repository-level split without cross-repo case leakage."""
    bucket = int.from_bytes(hashlib.sha256(repo_id.encode("utf-8")).digest()[:4]) % 10
    if bucket < 6:
        return "development"
    if bucket < 8:
        return "calibration"
    return "held_out"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth-root", type=Path, required=True)
    parser.add_argument("--repos-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-id", action="append", default=[])
    return parser.parse_args()


def _locations(finding: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    primary = finding.get("location")
    values = [primary] if isinstance(primary, dict) else []
    acceptable = finding.get("acceptable_locations", [])
    if isinstance(acceptable, list):
        values.extend(item for item in acceptable if isinstance(item, dict))
    return tuple(values)


def _accepted_classes(
    finding: dict[str, Any],
    primary: LogicBugClass,
) -> set[LogicBugClass]:
    """Honor explicit acceptable CWE overlap inside the focused two-class scope."""
    accepted = {primary}
    cwes = {
        str(item).upper()
        for item in finding.get("acceptable_cwes", [])
        if isinstance(item, str)
    }
    if "CWE-639" in cwes:
        accepted.add(LogicBugClass.MISSING_AUTHZ_IDOR)
    if "CWE-840" in cwes:
        accepted.add(LogicBugClass.BUSINESS_RULE_BYPASS)
    return accepted


def _candidate_matches(
    candidate: LogicCandidate,
    finding: dict[str, Any],
) -> bool:
    target_file = str(finding.get("file", "")).replace("\\", "/")
    if candidate.file_path.replace("\\", "/") != target_file:
        return False
    for location in _locations(finding):
        function = str(location.get("function", ""))
        if function and function == candidate.function:
            return True
        start = location.get("start_line")
        end = location.get("end_line", start)
        if isinstance(start, int) and isinstance(end, int) and start <= candidate.line <= end:
            return True
    return False


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(row["expected"] and row["detected"] for row in rows)
    fp = sum(not row["expected"] and row["detected"] for row in rows)
    fn = sum(row["expected"] and not row["detected"] for row in rows)
    tn = sum(not row["expected"] and not row["detected"] for row in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "cases": len(rows),
        "positive_cases": tp + fn,
        "negative_cases": fp + tn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_benchmark(
    ground_truth_root: Path,
    repos_root: Path,
    selected_repo_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Run the detector and return metrics with explicit provenance."""
    selected = set(selected_repo_ids)
    rows: list[dict[str, Any]] = []
    unreviewed: list[dict[str, Any]] = []
    analyzed_repositories: list[str] = []
    for ground_truth_path in sorted(ground_truth_root.glob("*/ground-truth.json")):
        document = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        repo_id = str(document.get("repo_id", ground_truth_path.parent.name))
        directory_name = ground_truth_path.parent.name
        if selected and repo_id not in selected and directory_name not in selected:
            continue
        repository = repos_root / directory_name
        if not repository.is_dir():
            continue
        labeled: list[tuple[dict[str, Any], LogicBugClass, bool]] = []
        for finding in document.get("findings", []):
            if not isinstance(finding, dict):
                continue
            vulnerability_class = str(finding.get("vulnerability_class", ""))
            is_vulnerable = bool(finding.get("is_vulnerable"))
            mapped = (
                _POSITIVE_CLASS_MAP.get(vulnerability_class)
                if is_vulnerable
                else _NEGATIVE_CLASS_MAP.get(vulnerability_class)
            )
            if mapped is not None:
                labeled.append((finding, mapped, is_vulnerable))
        if not labeled:
            continue
        index = build_logic_index(repository)
        analyzed_repositories.append(repo_id)
        matched_candidates: set[tuple[str, int, str]] = set()
        for finding, logic_class, expected in labeled:
            accepted_classes = _accepted_classes(finding, logic_class)
            matches = [
                candidate
                for candidate in index.candidates
                if candidate.bug_class in accepted_classes
                and _candidate_matches(candidate, finding)
            ]
            for candidate in matches:
                matched_candidates.add(
                    (candidate.file_path, candidate.line, candidate.bug_class.value)
                )
            rows.append(
                {
                    "case_id": str(finding.get("id", "")),
                    "repository": repo_id,
                    "split": _split_for_repository(repo_id),
                    "logic_class": logic_class.value,
                    "accepted_logic_classes": sorted(
                        item.value for item in accepted_classes
                    ),
                    "expected": expected,
                    "detected": bool(matches),
                    "file_path": str(finding.get("file", "")),
                    "matched_lines": [item.line for item in matches],
                    "matched_logic_classes": sorted(
                        {item.bug_class.value for item in matches}
                    ),
                    "ground_truth_source": str(
                        finding.get("evidence", {}).get("source", "reviewed_ground_truth")
                    ),
                }
            )
        for candidate in index.candidates:
            identity = (
                candidate.file_path,
                candidate.line,
                candidate.bug_class.value,
            )
            if identity in matched_candidates:
                continue
            unreviewed.append(
                {
                    "repository": repo_id,
                    "logic_class": candidate.bug_class.value,
                    "file_path": candidate.file_path,
                    "line": candidate.line,
                    "function": candidate.function,
                }
            )

    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_class[row["logic_class"]].append(row)
    metrics_by_split = {
        split: _metrics([row for row in rows if row["split"] == split])
        for split in ("development", "calibration", "held_out")
    }
    return {
        "schema_version": "idor-business-logic-benchmark-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "detector_config_id": LOGIC_DETECTOR_CONFIG_ID,
        "dataset": "Real-Vuln-Benchmark reviewed ground truth",
        "dataset_kind": "external_repository_ground_truth",
        "metric_policy": (
            "Only explicitly mapped reviewed positive/negative locations contribute "
            "to metrics; unmatched predictions remain unreviewed."
        ),
        "split_policy": _SPLIT_POLICY,
        "split_note": (
            "This repository-level split was frozen after detector development. It is "
            "reported for reproducibility and leakage control, but it is retrospective "
            "and does not support a new held-out quality claim."
        ),
        "quality_claim_supported": False,
        "repositories": analyzed_repositories,
        "overall": _metrics(rows),
        "metrics_by_split": metrics_by_split,
        "by_class": {
            logic_class.value: _metrics(by_class[logic_class.value])
            for logic_class in LogicBugClass
        },
        "cases": rows,
        "unreviewed_candidates": unreviewed,
    }


def main() -> int:
    """Run the benchmark and write deterministic JSON output."""
    args = _arguments()
    result = run_benchmark(
        args.ground_truth_root.resolve(),
        args.repos_root.resolve(),
        tuple(args.repo_id),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
