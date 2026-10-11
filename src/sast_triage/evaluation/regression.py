"""Automated benchmark evaluation and regression detection against quality baselines."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError


@dataclass(frozen=True)
class BenchmarkThresholds:
    """Configurable quality thresholds for detecting regressions."""

    min_precision: float = 0.0
    min_recall: float = 0.0
    min_f1: float = 0.0
    max_false_negative_rate: float = 1.0
    max_manual_review_rate: float = 1.0
    max_p95_latency_ms: float | None = None
    max_cost_usd: float | None = None
    allowed_f1_drop: float = 0.05
    allowed_precision_drop: float = 0.05
    allowed_recall_drop: float = 0.05


@dataclass(frozen=True)
class RegressionCheckResult:
    """Deterministic evaluation diff and pass/fail verdict."""

    passed: bool
    violations: tuple[str, ...]
    current_metrics: dict[str, Any]
    baseline_metrics: dict[str, Any] | None = None
    metric_diffs: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize check result to a report-safe dictionary."""
        return {
            "passed": self.passed,
            "violations": list(self.violations),
            "current_metrics": self.current_metrics,
            "baseline_metrics": self.baseline_metrics,
            "metric_diffs": self.metric_diffs,
        }


def check_regression(
    current: dict[str, Any],
    baseline: dict[str, Any] | None = None,
    thresholds: BenchmarkThresholds | None = None,
) -> RegressionCheckResult:
    """Check current metrics against minimum thresholds and baseline numbers."""
    if thresholds is None:
        thresholds = BenchmarkThresholds()

    violations: list[str] = []
    diffs: dict[str, float] = {}

    cur_p = float(current.get("precision", 0.0))
    cur_r = float(current.get("recall", 0.0))
    cur_f1 = float(current.get("f1", 0.0))
    cur_fn = float(current.get("false_negative_rate", 0.0))
    cur_mr = float(current.get("manual_review_rate", 0.0))

    # Absolute threshold checks
    if cur_p < thresholds.min_precision:
        violations.append(
            f"Precision {cur_p:.3f} is below minimum {thresholds.min_precision:.3f}"
        )
    if cur_r < thresholds.min_recall:
        violations.append(
            f"Recall {cur_r:.3f} is below minimum {thresholds.min_recall:.3f}"
        )
    if cur_f1 < thresholds.min_f1:
        violations.append(
            f"F1 {cur_f1:.3f} is below minimum {thresholds.min_f1:.3f}"
        )
    if cur_fn > thresholds.max_false_negative_rate:
        violations.append(
            f"False negative rate {cur_fn:.3f} exceeds maximum {thresholds.max_false_negative_rate:.3f}"
        )
    if cur_mr > thresholds.max_manual_review_rate:
        violations.append(
            f"Manual review rate {cur_mr:.3f} exceeds maximum {thresholds.max_manual_review_rate:.3f}"
        )

    # Latency & cost checks if available
    cur_p95 = current.get("provider_latency_p95_ms")
    if (
        thresholds.max_p95_latency_ms is not None
        and cur_p95 is not None
        and float(cur_p95) > thresholds.max_p95_latency_ms
    ):
        violations.append(
            f"Latency P95 {float(cur_p95):.0f}ms exceeds maximum {thresholds.max_p95_latency_ms:.0f}ms"
        )

    cur_cost = current.get("estimated_cost_usd")
    if (
        thresholds.max_cost_usd is not None
        and cur_cost is not None
        and float(cur_cost) > thresholds.max_cost_usd
    ):
        violations.append(
            f"Cost ${float(cur_cost):.4f} exceeds maximum ${thresholds.max_cost_usd:.4f}"
        )

    # Relative baseline comparisons
    if baseline:
        base_p = float(baseline.get("precision", 0.0))
        base_r = float(baseline.get("recall", 0.0))
        base_f1 = float(baseline.get("f1", 0.0))

        diffs["precision"] = round(cur_p - base_p, 4)
        diffs["recall"] = round(cur_r - base_r, 4)
        diffs["f1"] = round(cur_f1 - base_f1, 4)

        if base_f1 - cur_f1 > thresholds.allowed_f1_drop:
            violations.append(
                f"F1 regression: dropped by {base_f1 - cur_f1:.3f} (from {base_f1:.3f} to {cur_f1:.3f}), "
                f"allowed drop is {thresholds.allowed_f1_drop:.3f}"
            )
        if base_p - cur_p > thresholds.allowed_precision_drop:
            violations.append(
                f"Precision regression: dropped by {base_p - cur_p:.3f} (from {base_p:.3f} to {cur_p:.3f}), "
                f"allowed drop is {thresholds.allowed_precision_drop:.3f}"
            )
        if base_r - cur_r > thresholds.allowed_recall_drop:
            violations.append(
                f"Recall regression: dropped by {base_r - cur_r:.3f} (from {base_r:.3f} to {cur_r:.3f}), "
                f"allowed drop is {thresholds.allowed_recall_drop:.3f}"
            )

    return RegressionCheckResult(
        passed=len(violations) == 0,
        violations=tuple(violations),
        current_metrics=current,
        baseline_metrics=baseline,
        metric_diffs=diffs,
    )


def render_regression_markdown(result: RegressionCheckResult) -> str:
    """Render GitHub-flavored markdown report summarizing regression evaluation."""
    status_emoji = "✅ PASS" if result.passed else "❌ REGRESSION DETECTED"
    lines = [
        f"# Benchmark Regression Report — {status_emoji}",
        "",
        "| Metric | Current | Baseline | Diff | Status |",
        "|---|---:|---:|---:|:---:|",
    ]

    keys = (
        ("F1-Score", "f1"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("False Negative Rate", "false_negative_rate"),
        ("Manual Review Rate", "manual_review_rate"),
    )

    for label, key in keys:
        cur_val = result.current_metrics.get(key)
        cur_str = f"{float(cur_val):.3f}" if cur_val is not None else "N/A"
        base_val = result.baseline_metrics.get(key) if result.baseline_metrics else None
        base_str = f"{float(base_val):.3f}" if base_val is not None else "-"
        diff_val = result.metric_diffs.get(key)
        if diff_val is not None:
            diff_str = f"{'+' if diff_val >= 0 else ''}{diff_val:.3f}"
        else:
            diff_str = "-"
        status = "✅"
        for v in result.violations:
            if label.lower().split("-")[0] in v.lower():
                status = "❌"
                break
        lines.append(f"| **{label}** | {cur_str} | {base_str} | {diff_str} | {status} |")

    lines.append("")
    if result.violations:
        lines.append("### ⚠️ Violations")
        for v in result.violations:
            lines.append(f"- {v}")
        lines.append("")
    else:
        lines.append("All metrics satisfied baseline targets and quality constraints.")
        lines.append("")

    return "\n".join(lines)


def load_metrics_file(path: Path) -> dict[str, Any]:
    """Load JSON metrics or extract metrics from a batch report."""
    if not path.is_file():
        raise SastTriageError(f"Metrics file not found: {path}", "METRICS_FILE_NOT_FOUND")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SastTriageError(f"Cannot parse JSON file: {exc}", "METRICS_FILE_INVALID") from exc

    if "precision" in data or "f1" in data:
        return data
    if "overall" in data and isinstance(data["overall"], dict):
        return data["overall"]
    return data
