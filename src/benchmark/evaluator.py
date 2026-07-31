"""
Benchmark Evaluation Engine (Metric 2.0)
========================================
Implements exact Metric 2.0 calculations, decision metrics, security policy metrics,
FP suppression metrics, workload metrics, N/A semantics, high-resolution latency timing,
and run integrity tracking.
"""

import time
import math
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Union, Optional
from pydantic import BaseModel, Field

from src.core.schema import UnifiedFinding, TriageVerdict, EvaluationOutcome, FailureCategory
from src.benchmark.adapters import MatchedSample, MatchType, AdapterMatchReport


class LatencyBreakdown(BaseModel):
    total_wall_clock_ms: float = 0.0
    benchmark_loading_ms: float = 0.0
    context_extraction_ms: float = 0.0
    llm_inference_ms: float = 0.0
    verdict_parsing_ms: float = 0.0
    ground_truth_matching_ms: float = 0.0
    metric_computation_ms: float = 0.0
    per_finding_latency_ms: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_min_ms: float = 0.0
    latency_max_ms: float = 0.0
    latency_mean_ms: float = 0.0
    sample_latencies_ms: List[float] = Field(default_factory=list)
    request_count: int = 0
    success_count: int = 0
    transport_success_count: int = 0
    response_parse_success_count: int = 0
    evaluation_success_count: int = 0
    pipeline_failure_count: int = 0
    failure_count: int = 0
    retry_count: int = 0
    timeout_count: int = 0
    execution_mode: str = "REAL"  # "REAL" or "MOCK"



class StructuredMetric(BaseModel):
    """Structured representation of a numeric metric allowing JSON null + reason or defined float."""
    value: Optional[float] = None
    status: str = "DEFINED"  # "DEFINED" or "UNDEFINED"
    reason: Optional[str] = None
    numerator: int = 0
    denominator: int = 0

    def markdown_render(self, as_percentage: bool = False) -> str:
        if self.status == "UNDEFINED" or self.value is None:
            reason_str = f" ({self.reason})" if self.reason else ""
            return f"N/A{reason_str}"
        if as_percentage:
            return f"{self.value * 100.0:.2f}%"
        return f"{self.value:.4f}"


def make_defined_metric(numerator: int, denominator: int) -> StructuredMetric:
    if denominator == 0:
        return StructuredMetric(value=None, status="UNDEFINED", reason="denominator = 0", numerator=numerator, denominator=denominator)
    val = round(numerator / denominator, 4)
    return StructuredMetric(value=val, status="DEFINED", reason=None, numerator=numerator, denominator=denominator)


def make_undefined_metric(reason: str, numerator: int = 0, denominator: int = 0) -> StructuredMetric:
    return StructuredMetric(value=None, status="UNDEFINED", reason=reason, numerator=numerator, denominator=denominator)


class EvaluationMetrics(BaseModel):
    metric_version: str = "2.0"
    evaluation_status: str = "OK"  # "OK", "ADAPTER_FAILURE", "REPORT_INTEGRITY_FAILURE"

    # Dataset integrity metrics
    total_findings: int = 0
    matched_findings: int = 0
    unmatched_findings: int = 0
    ground_truth_matching_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    ground_truth_tp: int = 0
    ground_truth_fp: int = 0

    # Decision & Outcome Counts
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    tp_abstained: int = 0
    fp_abstained: int = 0
    tp_failure: int = 0
    fp_failure: int = 0

    decided_samples: int = 0
    abstention_count: int = 0
    failed_samples: int = 0

    # Ratio Metrics
    decision_coverage: StructuredMetric = Field(default_factory=StructuredMetric)
    abstention_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    pipeline_failure_rate: StructuredMetric = Field(default_factory=StructuredMetric)

    precision: StructuredMetric = Field(default_factory=StructuredMetric)
    selective_recall: StructuredMetric = Field(default_factory=StructuredMetric)
    recall_among_decided: StructuredMetric = Field(default_factory=StructuredMetric) # Alias
    end_to_end_tp_resolution_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    f1: StructuredMetric = Field(default_factory=StructuredMetric)
    selective_accuracy: StructuredMetric = Field(default_factory=StructuredMetric)

    # Security policy metrics
    policy_false_negative_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    conservative_miss_rate: StructuredMetric = Field(default_factory=StructuredMetric)

    # FP suppression metrics
    correct_fp_suppression_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    safe_fp_suppression_rate: StructuredMetric = Field(default_factory=StructuredMetric) # Alias

    # Workload metrics
    correctly_decided_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    policy_automation_rate: StructuredMetric = Field(default_factory=StructuredMetric)
    manual_review_rate: StructuredMetric = Field(default_factory=StructuredMetric)

    invariants_passed: bool = True
    invariant_errors: List[str] = Field(default_factory=list)


class EvaluationRun(BaseModel):
    evaluation_run_id: str
    generated_at_utc: str
    benchmark_name: str
    benchmark_version: str = "v1.0"
    benchmark_commit_sha: str = "HEAD"
    sample_manifest_hash: str = ""
    model_name: str = "qwen3:8b"
    model_version: str = "qwen3:8b"
    prompt_version: str = "v2.0"
    prompt_hash: str = ""
    policy_version: str = "v1.0"
    policy_hash: str = ""
    scanner_versions: Dict[str, str] = Field(default_factory=lambda: {"semgrep": "1.0.0", "gitleaks": "8.0.0"})
    execution_mode: str = "REAL"  # REAL or MOCK
    metric_version: str = "2.0"
    repository_revisions: Dict[str, str] = Field(default_factory=dict)
    configuration_hash: str = ""
    metrics: EvaluationMetrics
    latency: LatencyBreakdown
    match_report: Optional[Dict[str, Any]] = None
    preflight_run_id: Optional[str] = None
    pilot_run_id: Optional[str] = None
    quality_gate_status: str = "NOT_EVALUATED" # EVALUATION_COMPLETED, MODEL_QUALITY_GATE_MET, MODEL_QUALITY_GATE_NOT_MET


def normalize_verdict_str(verdict: Union[TriageVerdict, str, None]) -> Optional[str]:
    """Normalize verdict into pure security verdict strings (TP, FP, NEEDS_REVIEW, NEEDS_MORE_CONTEXT)."""
    if verdict is None:
        return None
    v_str = verdict.value if isinstance(verdict, TriageVerdict) else str(verdict).upper().strip()

    if v_str in ("TP", "TRIAGED_TP", "TRUE_POSITIVE"):
        return "TP"
    elif v_str in ("FP", "TRIAGED_FP", "FALSE_POSITIVE"):
        return "FP"
    elif v_str == "NEEDS_MORE_CONTEXT":
        return "NEEDS_MORE_CONTEXT"
    elif v_str in ("NEEDS_REVIEW", "MANUAL_REVIEW"):
        return "NEEDS_REVIEW"
    return None


class BenchmarkEvaluator:
    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"eval-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"

    def evaluate_matched_samples(
        self,
        match_report: AdapterMatchReport,
        total_findings_count: int,
        latency_breakdown: Optional[LatencyBreakdown] = None,
        execution_mode: str = "REAL"
    ) -> EvaluationMetrics:
        metrics = EvaluationMetrics()
        metrics.metric_version = "2.0"
        metrics.total_findings = total_findings_count
        metrics.matched_findings = match_report.matched_count
        metrics.unmatched_findings = match_report.unmatched_count

        if total_findings_count > 0:
            metrics.ground_truth_matching_rate = make_defined_metric(match_report.matched_count, total_findings_count)

        if match_report.matched_count == 0 or match_report.adapter_status == "ADAPTER_FAILURE":
            metrics.evaluation_status = "ADAPTER_FAILURE"
            reason = "matched_findings = 0"
            metrics.decision_coverage = make_undefined_metric(reason)
            metrics.abstention_rate = make_undefined_metric(reason)
            metrics.precision = make_undefined_metric(reason)
            metrics.selective_recall = make_undefined_metric(reason)
            metrics.f1 = make_undefined_metric(reason)
            metrics.selective_accuracy = make_undefined_metric(reason)
            metrics.policy_false_negative_rate = make_undefined_metric(reason)
            metrics.correct_fp_suppression_rate = make_undefined_metric(reason)
            return metrics

        # Process matched samples
        tp, fp, tn, fn = 0, 0, 0, 0
        tp_abstained, fp_abstained = 0, 0
        tp_failure, fp_failure = 0, 0
        gt_tp_count, gt_fp_count = 0, 0

        for sample in match_report.matched_samples:
            gt_label = sample.ground_truth_label.upper().strip()
            if gt_label == "TP":
                gt_tp_count += 1
            else:
                gt_fp_count += 1

            finding = sample.finding
            outcome = getattr(finding, "outcome", None)
            verdict_norm = normalize_verdict_str(finding.verdict)

            # Check outcome override
            if outcome == EvaluationOutcome.FAILED or getattr(finding, "failure_category", None) not in (None, FailureCategory.NONE):
                if gt_label == "TP":
                    tp_failure += 1
                else:
                    fp_failure += 1
            elif verdict_norm in ("NEEDS_REVIEW", "NEEDS_MORE_CONTEXT") or outcome == EvaluationOutcome.ABSTAINED:
                if gt_label == "TP":
                    tp_abstained += 1
                else:
                    fp_abstained += 1
            elif verdict_norm == "TP":
                if gt_label == "TP":
                    tp += 1
                else:
                    fp += 1  # False positive prediction (model said TP for GT FP)
            elif verdict_norm == "FP":
                if gt_label == "TP":
                    fn += 1  # False negative prediction (model said FP for GT TP)
                else:
                    tn += 1  # True negative prediction (model said FP for GT FP -> suppressed)
            else:
                # Default fallback abstained
                if gt_label == "TP":
                    tp_abstained += 1
                else:
                    fp_abstained += 1

        metrics.ground_truth_tp = gt_tp_count
        metrics.ground_truth_fp = gt_fp_count
        metrics.tp = tp
        metrics.fp = fp
        metrics.tn = tn
        metrics.fn = fn
        metrics.tp_abstained = tp_abstained
        metrics.fp_abstained = fp_abstained
        metrics.tp_failure = tp_failure
        metrics.fp_failure = fp_failure

        matched_n = match_report.matched_count
        decided_samples = tp + fp + tn + fn
        abstention_count = tp_abstained + fp_abstained
        failed_samples = tp_failure + fp_failure

        metrics.decided_samples = decided_samples
        metrics.abstention_count = abstention_count
        metrics.failed_samples = failed_samples

        metrics.decision_coverage = make_defined_metric(decided_samples, matched_n)
        metrics.abstention_rate = make_defined_metric(abstention_count, matched_n)
        metrics.pipeline_failure_rate = make_defined_metric(failed_samples, matched_n)

        # Precision, Recall among decided, F1, Selective Accuracy
        if (tp + fp) > 0:
            metrics.precision = make_defined_metric(tp, tp + fp)
        else:
            metrics.precision = make_undefined_metric("no positive predictions (TP + FP = 0)", tp, tp + fp)

        if (tp + fn) > 0:
            metrics.selective_recall = make_defined_metric(tp, tp + fn)
            metrics.recall_among_decided = metrics.selective_recall
        else:
            metrics.selective_recall = make_undefined_metric("no decided true positive cases (TP + FN = 0)", tp, tp + fn)
            metrics.recall_among_decided = metrics.selective_recall

        if gt_tp_count > 0:
            metrics.end_to_end_tp_resolution_rate = make_defined_metric(tp, gt_tp_count)
        else:
            metrics.end_to_end_tp_resolution_rate = make_undefined_metric("ground_truth_tp = 0", tp, gt_tp_count)

        if (
            metrics.precision.status == "DEFINED"
            and metrics.selective_recall.status == "DEFINED"
            and (metrics.precision.value + metrics.selective_recall.value) > 0
        ):
            f1_val = round(2 * (metrics.precision.value * metrics.selective_recall.value) / (metrics.precision.value + metrics.selective_recall.value), 4)
            metrics.f1 = StructuredMetric(value=f1_val, status="DEFINED", reason=None, numerator=2*tp, denominator=(2*tp + fp + fn))
        else:
            metrics.f1 = make_undefined_metric("precision or recall is undefined or sum is 0")

        if decided_samples > 0:
            metrics.selective_accuracy = make_defined_metric(tp + tn, decided_samples)
        else:
            metrics.selective_accuracy = make_undefined_metric("no decided predictions (decided_samples = 0)")

        # Security policy metrics
        if gt_tp_count > 0:
            metrics.policy_false_negative_rate = make_defined_metric(fn, gt_tp_count)
            metrics.conservative_miss_rate = make_defined_metric(fn + tp_failure, gt_tp_count)
        else:
            metrics.policy_false_negative_rate = make_undefined_metric("ground_truth_tp = 0")
            metrics.conservative_miss_rate = make_undefined_metric("ground_truth_tp = 0")

        # FP suppression metrics
        if gt_fp_count > 0:
            metrics.correct_fp_suppression_rate = make_defined_metric(tn, gt_fp_count)
            metrics.safe_fp_suppression_rate = metrics.correct_fp_suppression_rate
        else:
            metrics.correct_fp_suppression_rate = make_undefined_metric("no ground-truth FP", tn, gt_fp_count)
            metrics.safe_fp_suppression_rate = metrics.correct_fp_suppression_rate

        # Workload metrics
        metrics.correctly_decided_rate = make_defined_metric(tp + tn, matched_n)
        metrics.policy_automation_rate = make_defined_metric(tp + tn, matched_n)
        metrics.manual_review_rate = make_defined_metric(abstention_count, matched_n)

        # ── Check Mathematical Report Invariants ─────────────────────────────
        invariant_errors = []

        # Invariant 1: matched + unmatched == total
        if metrics.matched_findings + metrics.unmatched_findings != metrics.total_findings:
            invariant_errors.append(f"Invariant 1 failed: matched({metrics.matched_findings}) + unmatched({metrics.unmatched_findings}) != total({metrics.total_findings})")

        # Invariant 2: decided + abstained + failed == matched
        if decided_samples + abstention_count + failed_samples != matched_n:
            invariant_errors.append(f"Invariant 2 failed: decided({decided_samples}) + abstained({abstention_count}) + failed({failed_samples}) != matched({matched_n})")

        # Invariant 3: TP + FN + TP_abstained + TP_failure == ground_truth_tp
        if tp + fn + tp_abstained + tp_failure != gt_tp_count:
            invariant_errors.append(f"Invariant 3 failed: TP({tp}) + FN({fn}) + TP_abstained({tp_abstained}) + TP_failure({tp_failure}) != GT_TP({gt_tp_count})")

        # Invariant 4: TN + FP + FP_abstained + FP_failure == ground_truth_fp
        if tn + fp + fp_abstained + fp_failure != gt_fp_count:
            invariant_errors.append(f"Invariant 4 failed: TN({tn}) + FP({fp}) + FP_abstained({fp_abstained}) + FP_failure({fp_failure}) != GT_FP({gt_fp_count})")

        if invariant_errors:
            metrics.invariants_passed = False
            metrics.invariant_errors = invariant_errors
            metrics.evaluation_status = "REPORT_INTEGRITY_FAILURE"
        else:
            metrics.invariants_passed = True
            metrics.evaluation_status = "OK"

        return metrics
