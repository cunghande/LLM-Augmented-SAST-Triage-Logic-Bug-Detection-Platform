"""Deterministic benchmark metrics with explicit held-out semantics."""

from collections import Counter
from collections.abc import Iterable
from typing import Any

from sast_triage.evaluation.benchmark import BenchmarkDataset, BenchmarkRecord
from sast_triage.models import BatchResult, PolicyAction, TriageResult


def _evaluate_records(
    records: Iterable[BenchmarkRecord],
    results: list[TriageResult],
) -> dict[str, Any]:
    """Evaluate one explicit record subset without treating policy actions as labels."""
    records_by_id = {record.finding_instance_id: record for record in records}
    matched = 0
    binary_total = 0
    true_positive = 0
    predicted_positive = 0
    predicted_true_positive = 0
    false_negative = 0
    manual_review = 0
    fp_candidate = 0
    fp_candidate_true = 0
    triage_errors = 0
    context_unavailable = 0
    provider_failures = 0
    action_counts: Counter[str] = Counter()

    for result in results:
        record = records_by_id.get(result.finding.finding_instance_id)
        if record is None:
            continue
        matched += 1
        action = result.policy_decision.action.value
        action_counts[action] += 1
        if action == PolicyAction.MANUAL_REVIEW.value:
            manual_review += 1
        elif action == PolicyAction.FP_CANDIDATE.value:
            fp_candidate += 1
            fp_candidate_true += record.expected_label == "FP"
        elif action == PolicyAction.TRIAGE_ERROR.value:
            triage_errors += 1
        if result.triage_decision is None:
            provider_failures += sum(
                error.stage.value == "TRIAGE" for error in result.processing_errors
            )
        if result.context_summary and "unavailable" in result.context_summary.lower():
            context_unavailable += 1
        if record.expected_label in {"TP", "FP"}:
            binary_total += 1
            if record.expected_label == "TP":
                true_positive += 1
            predicted_is_positive = action in {
                PolicyAction.LIKELY_TP.value,
                PolicyAction.MANUAL_REVIEW.value,
            }
            if predicted_is_positive:
                predicted_positive += 1
            if record.expected_label == "TP" and predicted_is_positive:
                predicted_true_positive += 1
            if record.expected_label == "TP" and action == PolicyAction.FP_CANDIDATE.value:
                false_negative += 1

    precision = predicted_true_positive / predicted_positive if predicted_positive else 0.0
    recall = predicted_true_positive / true_positive if true_positive else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "matched_records": matched,
        "binary_records": binary_total,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_negative_rate": false_negative / true_positive if true_positive else 0.0,
        "manual_review_rate": manual_review / matched if matched else 0.0,
        "fp_candidate_precision": fp_candidate_true / fp_candidate if fp_candidate else 0.0,
        "tp_sent_to_fp_candidate": false_negative,
        "context_availability_rate": 1 - (context_unavailable / matched if matched else 0.0),
        "provider_failure_count": provider_failures,
        "triage_error_count": triage_errors,
        "policy_action_counts": dict(action_counts),
    }


def evaluate_batch(dataset: BenchmarkDataset, batch_result: BatchResult) -> dict[str, Any]:
    """Evaluate overall and per split, permitting quality claims only on held-out data."""
    overall = _evaluate_records(dataset.records, batch_result.results)
    splits = {
        split: _evaluate_records(
            (record for record in dataset.records if record.split == split),
            batch_result.results,
        )
        for split in ("development", "calibration", "held_out")
    }
    has_held_out = splits["held_out"]["matched_records"] > 0
    real_provider = batch_result.run_metadata.triage_provider != "fake"
    non_synthetic = dataset.dataset_kind.lower() not in {"fixture", "synthetic"}
    quality_supported = real_provider and non_synthetic and has_held_out
    reasons: list[str] = []
    if not real_provider:
        reasons.append("the provider is fake")
    if not non_synthetic:
        reasons.append("the dataset is synthetic or a fixture")
    if not has_held_out:
        reasons.append("no held-out record was matched")

    return {
        "benchmark_version": dataset.version,
        "dataset_kind": dataset.dataset_kind,
        **overall,
        "metrics_by_split": splits,
        "quality_claim_supported": quality_supported,
        "quality_claim_note": (
            None
            if quality_supported
            else "No model-quality claim is supported because " + ", ".join(reasons) + "."
        ),
    }
