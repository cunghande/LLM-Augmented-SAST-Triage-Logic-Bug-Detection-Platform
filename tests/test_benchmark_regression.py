"""Tests for benchmark regression evaluation and quality tracking."""

from __future__ import annotations

import json
from pathlib import Path

from sast_triage.evaluation.regression import (
    BenchmarkThresholds,
    check_regression,
    load_metrics_file,
    render_regression_markdown,
)
from scripts.run_benchmark_regression import main as run_regression_main


def test_check_regression_passes_cleanly() -> None:
    current = {
        "precision": 0.85,
        "recall": 0.80,
        "f1": 0.824,
        "false_negative_rate": 0.20,
        "manual_review_rate": 0.10,
    }
    thresholds = BenchmarkThresholds(min_f1=0.75, min_precision=0.80)
    result = check_regression(current, thresholds=thresholds)

    assert result.passed is True
    assert len(result.violations) == 0


def test_check_regression_detects_threshold_violations() -> None:
    current = {
        "precision": 0.60,
        "recall": 0.50,
        "f1": 0.545,
        "false_negative_rate": 0.50,
        "manual_review_rate": 0.40,
    }
    thresholds = BenchmarkThresholds(
        min_f1=0.70,
        min_precision=0.70,
        max_false_negative_rate=0.30,
    )
    result = check_regression(current, thresholds=thresholds)

    assert result.passed is False
    assert any("F1" in v for v in result.violations)
    assert any("Precision" in v for v in result.violations)
    assert any("False negative rate" in v for v in result.violations)


def test_check_regression_detects_relative_baseline_regression() -> None:
    baseline = {
        "precision": 0.90,
        "recall": 0.85,
        "f1": 0.874,
        "false_negative_rate": 0.15,
        "manual_review_rate": 0.05,
    }
    current = {
        "precision": 0.80,
        "recall": 0.84,
        "f1": 0.819,
        "false_negative_rate": 0.16,
        "manual_review_rate": 0.05,
    }
    thresholds = BenchmarkThresholds(allowed_f1_drop=0.03, allowed_precision_drop=0.05)
    result = check_regression(current, baseline=baseline, thresholds=thresholds)

    assert result.passed is False
    assert any("F1 regression" in v for v in result.violations)
    assert any("Precision regression" in v for v in result.violations)
    assert result.metric_diffs["f1"] < 0


def test_render_regression_markdown_structure() -> None:
    current = {"f1": 0.85, "precision": 0.90, "recall": 0.80}
    baseline = {"f1": 0.88, "precision": 0.92, "recall": 0.84}
    result = check_regression(current, baseline=baseline)
    md = render_regression_markdown(result)

    assert "| **F1-Score** |" in md
    assert "| **Precision** |" in md
    assert "| Metric | Current | Baseline | Diff | Status |" in md
    assert "PASS" in md


def test_load_metrics_file_and_cli_runner(tmp_path: Path) -> None:
    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(
        json.dumps({
            "f1": 0.88,
            "precision": 0.90,
            "recall": 0.86,
            "false_negative_rate": 0.14,
            "manual_review_rate": 0.05,
        }),
        encoding="utf-8",
    )
    loaded = load_metrics_file(metrics_path)
    assert loaded["f1"] == 0.88

    out_dir = tmp_path / "reg_out"
    code = run_regression_main([
        "--metrics-json", str(metrics_path),
        "--output-dir", str(out_dir),
        "--min-f1", "0.80",
        "--fail-on-regression",
    ])
    assert code == 0
    assert (out_dir / "regression_report.json").is_file()
    assert (out_dir / "regression_report.md").is_file()

    # Now test regression failure exit code
    code_fail = run_regression_main([
        "--metrics-json", str(metrics_path),
        "--output-dir", str(out_dir),
        "--min-f1", "0.95",
        "--fail-on-regression",
    ])
    assert code_fail == 1
