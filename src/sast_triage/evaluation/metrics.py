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

    # Compute bootstrap confidence intervals if binary records exist
    ci_precision = compute_binary_metric_ci(
        [(r.expected_label == "TP", res.policy_decision.action.value in {PolicyAction.LIKELY_TP.value, PolicyAction.MANUAL_REVIEW.value})
         for res in results if (r := records_by_id.get(res.finding.finding_instance_id)) and r.expected_label in {"TP", "FP"}],
        metric_name="precision",
    )
    ci_recall = compute_binary_metric_ci(
        [(r.expected_label == "TP", res.policy_decision.action.value in {PolicyAction.LIKELY_TP.value, PolicyAction.MANUAL_REVIEW.value})
         for res in results if (r := records_by_id.get(res.finding.finding_instance_id)) and r.expected_label in {"TP", "FP"}],
        metric_name="recall",
    )

    return {
        "matched_records": matched,
        "binary_records": binary_total,
        "precision": precision,
        "precision_ci_95": ci_precision,
        "recall": recall,
        "recall_ci_95": ci_recall,
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


def compute_binary_metric_ci(
    data: list[tuple[bool, bool]],
    metric_name: str = "precision",
    n_bootstraps: int = 1000,
    ci: float = 0.95,
    seed: int = 42,
) -> tuple[float, float]:
    """Compute empirical bootstrap confidence interval for precision or recall.

    Each item in data is a tuple of (is_actual_tp, is_predicted_positive).
    """
    if not data:
        return (0.0, 0.0)

    import random
    rng = random.Random(seed)
    n = len(data)
    boot_vals: list[float] = []

    for _ in range(n_bootstraps):
        sample = [data[rng.randint(0, n - 1)] for _ in range(n)]
        tp_actual = sum(1 for actual, _ in sample if actual)
        pred_pos = sum(1 for _, pred in sample if pred)
        pred_tp = sum(1 for actual, pred in sample if actual and pred)

        if metric_name == "precision":
            val = pred_tp / pred_pos if pred_pos else 0.0
        elif metric_name == "recall":
            val = pred_tp / tp_actual if tp_actual else 0.0
        else:
            val = 0.0
        boot_vals.append(val)

    boot_vals.sort()
    low_idx = int(((1.0 - ci) / 2.0) * n_bootstraps)
    high_idx = int((1.0 - (1.0 - ci) / 2.0) * n_bootstraps)
    high_idx = min(high_idx, n_bootstraps - 1)
    return (round(boot_vals[low_idx], 4), round(boot_vals[high_idx], 4))


def compute_calibration_ece(
    confidences: list[float],
    accuracies: list[int],
    n_bins: int = 5,
) -> dict[str, Any]:
    """Compute Expected Calibration Error (ECE) and reliability diagram data.

    Args:
        confidences: List of predicted probabilities (0.0 to 1.0).
        accuracies: List of binary correctness (1 for correct, 0 for incorrect).
        n_bins: Number of equal-width probability bins.
    """
    if not confidences or len(confidences) != len(accuracies):
        return {"ece": 0.0, "bins": []}

    total_samples = len(confidences)
    bin_width = 1.0 / n_bins
    bin_data: list[dict[str, Any]] = []
    ece = 0.0

    for b in range(n_bins):
        bin_lower = b * bin_width
        bin_upper = (b + 1) * bin_width
        # include upper edge in last bin
        indices = [
            i for i, c in enumerate(confidences)
            if (bin_lower <= c < bin_upper) or (b == n_bins - 1 and c == bin_upper)
        ]
        count = len(indices)
        if count > 0:
            avg_conf = sum(confidences[i] for i in indices) / count
            avg_acc = sum(accuracies[i] for i in indices) / count
            weight = count / total_samples
            ece += weight * abs(avg_acc - avg_conf)
            bin_data.append({
                "bin_range": (round(bin_lower, 2), round(bin_upper, 2)),
                "count": count,
                "avg_confidence": round(avg_conf, 4),
                "avg_accuracy": round(avg_acc, 4),
            })
        else:
            bin_data.append({
                "bin_range": (round(bin_lower, 2), round(bin_upper, 2)),
                "count": 0,
                "avg_confidence": 0.0,
                "avg_accuracy": 0.0,
            })

    return {
        "ece": round(ece, 4),
        "total_samples": total_samples,
        "bins": bin_data,
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

