#!/usr/bin/env python3
"""Run automated benchmark regression check against quality targets or baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sast_triage.evaluation.regression import (
    BenchmarkThresholds,
    check_regression,
    load_metrics_file,
    render_regression_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automated benchmark regression evaluator for SAST Triage"
    )
    parser.add_argument(
        "--metrics-json",
        type=Path,
        required=True,
        help="Path to current benchmark metrics or report JSON",
    )
    parser.add_argument(
        "--baseline-json",
        type=Path,
        default=None,
        help="Path to historical baseline metrics JSON to compare against",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark-regression-output"),
        help="Directory to write regression reports (default: benchmark-regression-output)",
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=0.0,
        help="Minimum allowed F1 score (default: 0.0)",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.0,
        help="Minimum allowed precision (default: 0.0)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.0,
        help="Minimum allowed recall (default: 0.0)",
    )
    parser.add_argument(
        "--max-fn-rate",
        type=float,
        default=1.0,
        help="Maximum allowed false negative rate (default: 1.0)",
    )
    parser.add_argument(
        "--max-manual-review-rate",
        type=float,
        default=1.0,
        help="Maximum allowed manual review rate (default: 1.0)",
    )
    parser.add_argument(
        "--max-p95-latency-ms",
        type=float,
        default=None,
        help="Maximum allowed P95 latency in milliseconds",
    )
    parser.add_argument(
        "--allowed-f1-drop",
        type=float,
        default=0.05,
        help="Maximum allowed drop in F1 compared to baseline (default: 0.05)",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        default=False,
        help="Exit with code 1 if a regression or threshold violation is detected",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    current_metrics = load_metrics_file(args.metrics_json)
    baseline_metrics = (
        load_metrics_file(args.baseline_json) if args.baseline_json else None
    )

    thresholds = BenchmarkThresholds(
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        min_f1=args.min_f1,
        max_false_negative_rate=args.max_fn_rate,
        max_manual_review_rate=args.max_manual_review_rate,
        max_p95_latency_ms=args.max_p95_latency_ms,
        allowed_f1_drop=args.allowed_f1_drop,
    )

    result = check_regression(current_metrics, baseline_metrics, thresholds)
    markdown_report = render_regression_markdown(result)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = args.output_dir / "regression_report.json"
    report_md_path = args.output_dir / "regression_report.md"

    report_json_path.write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    report_md_path.write_text(markdown_report, encoding="utf-8")

    print(markdown_report)
    print(f"Reports saved to {args.output_dir}/")

    if not result.passed and args.fail_on_regression:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
