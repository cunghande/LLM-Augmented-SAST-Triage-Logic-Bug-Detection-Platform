"""Metric đánh giá xác định với ngữ nghĩa ánh xạ policy tường minh."""

from collections import Counter
from typing import Any

from sast_triage.evaluation.benchmark import BenchmarkDataset
from sast_triage.models import BatchResult, PolicyAction


def evaluate_batch(dataset: BenchmarkDataset, batch_result: BatchResult) -> dict[str, Any]:
    """Đánh giá finding khớp nhau mà không xem policy action là nhãn.

    DISPUTED and INSUFFICIENT_CONTEXT are excluded from binary TP/FP counts.
    Fake-provider runs explicitly receive ``quality_claim_supported=False``.
    """
    records = {record.finding_instance_id: record for record in dataset.records}
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

    for result in batch_result.results:
        record = records.get(result.finding.finding_instance_id)
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
            provider_failures += sum(error.stage.value == "TRIAGE" for error in result.processing_errors)
        if result.context_summary and "unavailable" in result.context_summary.lower():
            context_unavailable += 1
        if record.expected_label in {"TP", "FP"}:
            binary_total += 1
            if record.expected_label == "TP":
                true_positive += 1
            predicted_is_positive = action in {PolicyAction.LIKELY_TP.value, PolicyAction.MANUAL_REVIEW.value}
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
        "benchmark_version": dataset.version,
        "dataset_kind": dataset.dataset_kind,
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
        "quality_claim_supported": batch_result.run_metadata.triage_provider != "fake",
        "quality_claim_note": (
            "No model-quality claim is supported by this run."
            if batch_result.run_metadata.triage_provider == "fake"
            else None
        ),
    }
