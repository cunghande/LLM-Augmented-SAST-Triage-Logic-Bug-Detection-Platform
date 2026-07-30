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

from src.core.schema import UnifiedFinding, TriageVerdict
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
    retry_count: int = 0
    timeout_count: int = 0
    execution_mode: str = "REAL"  # "REAL" or "MOCK"


class EvaluationMetrics(BaseModel):
    metric_version: str = "2.0"
    evaluation_status: str = "OK"  # "OK" or "ADAPTER_FAILURE"

    # Dataset integrity metrics
    total_findings: int = 0
    matched_findings: int = 0
    unmatched_findings: int = 0
    ground_truth_matching_rate: Union[float, str] = "N/A"
    ground_truth_tp: int = 0
    ground_truth_fp: int = 0

    # Decision metrics
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    tp_abstained: int = 0
    fp_abstained: int = 0
    tp_failure: int = 0
    fp_failure: int = 0

    decided_samples: int = 0
    decision_coverage: Union[float, str] = "N/A"
    abstention_count: int = 0
    abstention_rate: Union[float, str] = "N/A"
    pipeline_failure_rate: Union[float, str] = "N/A"

    precision: Union[float, str] = "N/A"
    recall_among_decided: Union[float, str] = "N/A"
    f1: Union[float, str] = "N/A"
    selective_accuracy: Union[float, str] = "N/A"

    # Security policy metrics
    policy_false_negative_rate: Union[float, str] = "N/A"
    conservative_miss_rate: Union[float, str] = "N/A"

    # FP suppression metrics
    safe_fp_suppression_rate: Union[float, str] = "N/A"

    # Workload metrics
    safe_auto_processed: int = 0
    safe_workload_reduction: Union[float, str] = "N/A"
    manual_review_load: int = 0
    manual_review_rate: Union[float, str] = "N/A"
    auto_suppression_workload_reduction: Union[float, str] = "N/A"

    na_reasons: Dict[str, str] = Field(default_factory=dict)


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


def normalize_verdict(verdict: Union[TriageVerdict, str, None]) -> str:
    """Normalize verdict into standard enum values (TP, FP, NEEDS_REVIEW, NEEDS_MORE_CONTEXT, PIPELINE_FAILURE)."""
    if verdict is None:
        return "NEEDS_REVIEW"
    v_str = verdict.value if isinstance(verdict, TriageVerdict) else str(verdict).upper().strip()

    if v_str in ("TP", "TRIAGED_TP", "TRUE_POSITIVE"):
        return "TP"
    elif v_str in ("FP", "TRIAGED_FP", "FALSE_POSITIVE"):
        return "FP"
    elif v_str == "NEEDS_MORE_CONTEXT":
        return "NEEDS_MORE_CONTEXT"
    elif v_str in ("PIPELINE_FAILURE", "ERROR", "FAILURE"):
        return "PIPELINE_FAILURE"
    else:
        return "NEEDS_REVIEW"


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

        if match_report.total_findings > 0:
            metrics.ground_truth_matching_rate = round(match_report.matched_count / total_findings_count, 4) if total_findings_count > 0 else 0.0

        if match_report.matched_count == 0 or match_report.adapter_status == "ADAPTER_FAILURE":
            metrics.evaluation_status = "ADAPTER_FAILURE"
            metrics.na_reasons = {
                "precision": "matched_findings = 0",
                "recall_among_decided": "matched_findings = 0",
                "f1": "matched_findings = 0",
                "selective_accuracy": "matched_findings = 0",
                "policy_false_negative_rate": "matched_findings = 0",
                "conservative_miss_rate": "matched_findings = 0",
                "safe_fp_suppression_rate": "matched_findings = 0",
                "decision_coverage": "matched_findings = 0",
                "abstention_rate": "matched_findings = 0",
                "pipeline_failure_rate": "matched_findings = 0",
                "safe_workload_reduction": "matched_findings = 0",
                "manual_review_rate": "matched_findings = 0",
                "auto_suppression_workload_reduction": "matched_findings = 0",
            }
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

            pred = normalize_verdict(sample.finding.verdict)

            if gt_label == "TP":
                if pred == "TP":
                    tp += 1
                elif pred == "FP":
                    fn += 1
                elif pred in ("NEEDS_REVIEW", "NEEDS_MORE_CONTEXT"):
                    tp_abstained += 1
                elif pred == "PIPELINE_FAILURE":
                    tp_failure += 1
            else:  # GT FP
                if pred == "TP":
                    fp += 1
                elif pred == "FP":
                    tn += 1
                elif pred in ("NEEDS_REVIEW", "NEEDS_MORE_CONTEXT"):
                    fp_abstained += 1
                elif pred == "PIPELINE_FAILURE":
                    fp_failure += 1

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
        metrics.decided_samples = decided_samples

        metrics.decision_coverage = round(decided_samples / matched_n, 4) if matched_n > 0 else "N/A"
        metrics.abstention_count = tp_abstained + fp_abstained
        metrics.abstention_rate = round(metrics.abstention_count / matched_n, 4) if matched_n > 0 else "N/A"
        metrics.pipeline_failure_rate = round((tp_failure + fp_failure) / matched_n, 4) if matched_n > 0 else "N/A"

        # Precision, Recall among decided, F1, Selective Accuracy
        if (tp + fp) > 0:
            prec_val = tp / (tp + fp)
            metrics.precision = round(prec_val, 4)
        else:
            metrics.precision = "N/A"
            metrics.na_reasons["precision"] = "no decided positive predictions (TP + FP = 0)"

        if (tp + fn) > 0:
            rec_val = tp / (tp + fn)
            metrics.recall_among_decided = round(rec_val, 4)
        else:
            metrics.recall_among_decided = "N/A"
            metrics.na_reasons["recall_among_decided"] = "no decided true positive cases (TP + FN = 0)"

        if isinstance(metrics.precision, float) and isinstance(metrics.recall_among_decided, float) and (metrics.precision + metrics.recall_among_decided) > 0:
            f1_val = 2 * (metrics.precision * metrics.recall_among_decided) / (metrics.precision + metrics.recall_among_decided)
            metrics.f1 = round(f1_val, 4)
        else:
            metrics.f1 = "N/A"
            metrics.na_reasons["f1"] = "precision or recall is undefined or sum is 0"

        if decided_samples > 0:
            metrics.selective_accuracy = round((tp + tn) / decided_samples, 4)
        else:
            metrics.selective_accuracy = "N/A"
            metrics.na_reasons["selective_accuracy"] = "no decided predictions (decided_samples = 0)"

        # Security policy metrics
        if gt_tp_count > 0:
            metrics.policy_false_negative_rate = round(fn / gt_tp_count, 4)
            metrics.conservative_miss_rate = round((fn + tp_failure) / gt_tp_count, 4)
        else:
            metrics.policy_false_negative_rate = "N/A"
            metrics.conservative_miss_rate = "N/A"
            metrics.na_reasons["policy_false_negative_rate"] = "ground_truth_tp = 0"
            metrics.na_reasons["conservative_miss_rate"] = "ground_truth_tp = 0"

        # FP suppression metrics
        if gt_fp_count > 0:
            metrics.safe_fp_suppression_rate = round(tn / gt_fp_count, 4)
        else:
            metrics.safe_fp_suppression_rate = "N/A"
            metrics.na_reasons["safe_fp_suppression_rate"] = "benchmark contains no matched ground-truth FP samples"

        # Workload metrics
        metrics.safe_auto_processed = tp + tn
        metrics.safe_workload_reduction = round((tp + tn) / matched_n, 4) if matched_n > 0 else "N/A"
        metrics.manual_review_load = metrics.abstention_count
        metrics.manual_review_rate = round(metrics.manual_review_load / matched_n, 4) if matched_n > 0 else "N/A"
        metrics.auto_suppression_workload_reduction = round(tn / matched_n, 4) if matched_n > 0 else "N/A"

        return metrics
