"""Deterministic benchmark support for the FastAPI authorization detector."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sast_triage.context.repository_index import FastAPIAuthorizationEndpoint
from sast_triage.errors import SastTriageError

_LABELS = frozenset({"MISSING_AUTHZ", "PROTECTED", "UNKNOWN"})
_SPLITS = frozenset({"development", "calibration", "held_out"})
_ADJUDICATION_STATUSES = frozenset({"UNREVIEWED", "AGREED", "ADJUDICATED", "DISPUTED"})


@dataclass(frozen=True, slots=True)
class LogicAuthzCase:
    """One source-free FastAPI authorization benchmark case."""

    case_id: str
    repository_identifier: str
    repository_root: str
    file_path: str
    route_line: int
    expected_state: str
    split: str
    case_type: str = "natural"
    theme: str = "unknown"
    negative_control_type: str | None = None
    reviewer_ids: tuple[str, ...] = ()
    adjudication_status: str = "UNREVIEWED"
    ground_truth_source: str | None = None
    advisory_id: str | None = None
    advisory_url: str | None = None
    commit_sha: str | None = None
    cwe: str | None = None
    http_method: str | None = None
    route_path: str | None = None


@dataclass(frozen=True, slots=True)
class LogicAuthzDataset:
    """Immutable FastAPI authorization benchmark manifest."""

    version: str
    cases: tuple[LogicAuthzCase, ...]
    dataset_kind: str = "curated"
    held_out_frozen: bool = False
    ground_truth_sha256: str | None = None


def load_logic_authz_dataset(file_path: Path) -> LogicAuthzDataset:
    """Load and validate a source-free logic detector manifest."""
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SastTriageError("Logic benchmark file could not be read.", "LOGIC_BENCHMARK_FILE_INVALID") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), str) or not isinstance(raw.get("cases"), list):
        raise SastTriageError("Logic benchmark schema is invalid.", "LOGIC_BENCHMARK_SCHEMA_INVALID")
    cases: list[LogicAuthzCase] = []
    ids: set[str] = set()
    for index, item in enumerate(raw["cases"]):
        if not isinstance(item, dict):
            raise SastTriageError("Logic benchmark case is invalid.", f"LOGIC_BENCHMARK_CASE_{index}")
        required = ("case_id", "repository_identifier", "repository_root", "file_path", "route_line", "expected_state", "split")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required if key != "route_line"):
            raise SastTriageError("Logic benchmark case is missing a required field.", f"LOGIC_BENCHMARK_CASE_{index}")
        if not isinstance(item.get("route_line"), int) or item["route_line"] <= 0:
            raise SastTriageError("Logic benchmark route_line is invalid.", f"LOGIC_BENCHMARK_CASE_{index}")
        if item["expected_state"] not in _LABELS or item["split"] not in _SPLITS:
            raise SastTriageError("Logic benchmark label or split is invalid.", f"LOGIC_BENCHMARK_CASE_{index}")
        case_id = item["case_id"]
        if case_id in ids:
            raise SastTriageError("Logic benchmark case IDs must be unique.", "LOGIC_BENCHMARK_DUPLICATE_CASE")
        ids.add(case_id)
        reviewer_ids = item.get("reviewer_ids", [])
        if not isinstance(reviewer_ids, list) or any(not isinstance(value, str) or not value.strip() for value in reviewer_ids):
            raise SastTriageError("Logic benchmark reviewer IDs are invalid.", f"LOGIC_BENCHMARK_CASE_{index}")
        if len(reviewer_ids) != len(set(reviewer_ids)):
            raise SastTriageError("Logic benchmark reviewer IDs must be unique.", f"LOGIC_BENCHMARK_CASE_{index}")
        adjudication_status = str(item.get("adjudication_status", "UNREVIEWED"))
        if adjudication_status not in _ADJUDICATION_STATUSES:
            raise SastTriageError("Logic benchmark adjudication status is invalid.", f"LOGIC_BENCHMARK_CASE_{index}")
        cases.append(
            LogicAuthzCase(
                case_id=case_id,
                repository_identifier=item["repository_identifier"],
                repository_root=item["repository_root"],
                file_path=item["file_path"].replace("\\", "/"),
                route_line=item["route_line"],
                expected_state=item["expected_state"],
                split=item["split"],
                case_type=str(item.get("case_type", "natural")),
                theme=str(item.get("theme", "unknown")),
                negative_control_type=(str(item["negative_control_type"]) if item.get("negative_control_type") else None),
                reviewer_ids=tuple(reviewer_ids),
                adjudication_status=adjudication_status,
                ground_truth_source=(str(item["ground_truth_source"]) if item.get("ground_truth_source") else None),
                advisory_id=(str(item["advisory_id"]) if item.get("advisory_id") else None),
                advisory_url=(str(item["advisory_url"]) if item.get("advisory_url") else None),
                commit_sha=(str(item["commit_sha"]) if item.get("commit_sha") else None),
                cwe=(str(item["cwe"]) if item.get("cwe") else None),
                http_method=(str(item["http_method"]).upper() if item.get("http_method") else None),
                route_path=(str(item["route_path"]) if item.get("route_path") else None),
            )
        )
    return LogicAuthzDataset(
        version=raw["version"],
        cases=tuple(cases),
        dataset_kind=str(raw.get("dataset_kind", "curated")),
        held_out_frozen=bool(raw.get("held_out_frozen", False)),
        ground_truth_sha256=raw.get("ground_truth_sha256"),
    )


def _score_cases(
    cases: tuple[LogicAuthzCase, ...],
    predictions: dict[tuple[str, str, int], FastAPIAuthorizationEndpoint],
) -> dict[str, Any]:
    """Score one split while excluding expected UNKNOWN from binary metrics."""
    counts: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []
    binary = [case for case in cases if case.expected_state in {"MISSING_AUTHZ", "PROTECTED"}]
    for case in cases:
        endpoint = predictions.get((case.repository_identifier, case.file_path, case.route_line))
        predicted = "UNKNOWN" if endpoint is None else (
            "MISSING_AUTHZ" if endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE" else endpoint.analysis_state
        )
        counts[f"{case.expected_state}_as_{predicted}"] += 1
        case_results.append(
            {
                "case_id": case.case_id,
                "repository_identifier": case.repository_identifier,
                "file_path": case.file_path,
                "route_line": case.route_line,
                "case_type": case.case_type,
                "theme": case.theme,
                "expected_state": case.expected_state,
                "predicted_state": predicted,
                "ground_truth_source": case.ground_truth_source,
                "advisory_id": case.advisory_id,
                "commit_sha": case.commit_sha,
                "cwe": case.cwe,
                "http_method": case.http_method,
                "route_path": case.route_path,
            }
        )
    tp = counts["MISSING_AUTHZ_as_MISSING_AUTHZ"]
    fp = counts["PROTECTED_as_MISSING_AUTHZ"]
    # A detector that cannot resolve a known-positive case has still missed the
    # vulnerability. Keep UNKNOWN visible as a separate diagnostic, but do not
    # silently remove it from recall.
    fn = counts["MISSING_AUTHZ_as_PROTECTED"] + counts["MISSING_AUTHZ_as_UNKNOWN"]
    tn = counts["PROTECTED_as_PROTECTED"]
    unknown = sum(
        1
        for case in binary
        if predictions.get((case.repository_identifier, case.file_path, case.route_line)) is None
        or predictions[(case.repository_identifier, case.file_path, case.route_line)].analysis_state == "UNKNOWN"
    )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "total_cases": len(cases),
        "binary_cases": len(binary),
        "unknown_cases": sum(case.expected_state == "UNKNOWN" for case in cases),
        "predicted_unknown": unknown,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "confusion": dict(sorted(counts.items())),
        "case_results": case_results,
    }


def evaluate_logic_authz_dataset(
    dataset: LogicAuthzDataset,
    endpoints: tuple[FastAPIAuthorizationEndpoint, ...],
) -> dict[str, Any]:
    """Evaluate endpoint facts and report the pre-registered quality gate."""
    predictions = {
        (endpoint.repository_identifier, endpoint.file_path, endpoint.route_line): endpoint
        for endpoint in endpoints
    }
    metrics_by_split = {
        split: _score_cases(tuple(case for case in dataset.cases if case.split == split), predictions)
        for split in ("development", "calibration", "held_out")
    }
    metrics_by_case_type = {
        case_type: _score_cases(
            tuple(case for case in dataset.cases if case.case_type == case_type), predictions
        )
        for case_type in sorted({case.case_type for case in dataset.cases})
    }
    overall = _score_cases(dataset.cases, predictions)
    held_out = metrics_by_split["held_out"]
    held_out_binary = tuple(
        case for case in dataset.cases
        if case.split == "held_out" and case.expected_state in {"MISSING_AUTHZ", "PROTECTED"}
    )
    repository_count = len({case.repository_identifier for case in dataset.cases})
    positive_count = sum(case.expected_state == "MISSING_AUTHZ" for case in dataset.cases)
    negative_count = sum(case.expected_state == "PROTECTED" for case in dataset.cases)
    independently_reviewed = bool(held_out_binary) and all(
        len(case.reviewer_ids) >= 2 and case.adjudication_status in {"AGREED", "ADJUDICATED"}
        for case in held_out_binary
    )
    router_dependency_false_positives = 0
    for case in dataset.cases:
        if case.negative_control_type != "router_dependency":
            continue
        endpoint = predictions.get((case.repository_identifier, case.file_path, case.route_line))
        if endpoint is not None and endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE":
            router_dependency_false_positives += 1
    quality_gate = {
        "precision_min": 0.85,
        "recall_min": 0.80,
        "f1_min": 0.82,
        "case_count_min": 80,
        "positive_count_min": 40,
        "negative_count_min": 40,
        "repository_count_min": 6,
        "passed": (
            held_out["precision"] >= 0.85
            and held_out["recall"] >= 0.80
            and held_out["f1"] >= 0.82
            and router_dependency_false_positives == 0
            and len(dataset.cases) >= 80
            and positive_count >= 40
            and negative_count >= 40
            and repository_count >= 6
            and dataset.held_out_frozen
            and dataset.dataset_kind.lower() not in {"fixture", "synthetic"}
            and independently_reviewed
        ),
    }
    return {
        "benchmark": "fastapi-function-level-authz",
        "version": dataset.version,
        "dataset_kind": dataset.dataset_kind,
        "ground_truth_sha256": dataset.ground_truth_sha256,
        "held_out_frozen": dataset.held_out_frozen,
        "held_out_independently_reviewed": independently_reviewed,
        "router_dependency_false_positives": router_dependency_false_positives,
        "case_count": len(dataset.cases),
        "repository_count": repository_count,
        "positive_count": positive_count,
        "negative_count": negative_count,
        "overall_metrics": overall,
        "metrics_by_split": metrics_by_split,
        "metrics_by_case_type": metrics_by_case_type,
        "quality_gate": quality_gate,
        "quality_claim_supported": bool(quality_gate["passed"]),
    }
