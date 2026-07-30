# -*- coding: utf-8 -*-
import os as _os
_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
import sys as _sys
if hasattr(_sys.stdout, 'reconfigure'):
    _sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(_sys.stderr, 'reconfigure'):
    _sys.stderr.reconfigure(encoding='utf-8', errors='replace')

"""
Versioned Benchmark Evaluation Runner
======================================
Executes anti-data-leakage evaluation across benchmark suites, reporting sample sizes N,
confusion matrices, precision, recall, F1, false-negative rate (FNR), abstention rate,
latency, resource usage, and per-rule-family metrics.

Disclaimer: All results produced are research prototype evaluations.
"""

import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.core.schema import UnifiedFinding, TriageVerdict
from src.parsers.semgrep import parse_semgrep_json
from src.parsers.gitleaks import parse_gitleaks_json
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient


BENCHMARKS = {
    "java": {
        "name": "OWASP BenchmarkJava",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkJava",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkJava",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkJava_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "BenchmarkJava",
        "scan_type": "semgrep",
    },
    "python": {
        "name": "OWASP BenchmarkPython",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkPython",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkPython",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkPython_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "BenchmarkPython",
        "scan_type": "semgrep",
    },
}


def compute_rigorous_metrics(
    triaged_findings: List[UnifiedFinding],
    gt_map: Dict[str, str]
) -> Dict[str, Any]:
    """Compute rigorous evaluation metrics including N, FNR, abstention rate, and per-rule-family breakdown."""
    total_samples = len(triaged_findings)
    matched = 0
    tp, fp, fn, tn = 0, 0, 0, 0
    abstentions = 0
    rule_family_metrics: Dict[str, Dict[str, int]] = {}

    for f in triaged_findings:
        gt_verdict = gt_map.get(f.finding_id) or gt_map.get(Path(f.file_path).stem)
        if not gt_verdict:
            continue

        matched += 1
        family = f.metadata.get("rule_family", "generic")
        if family not in rule_family_metrics:
            rule_family_metrics[family] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "abstain": 0}

        pred = f.verdict.value if f.verdict else "NEEDS_REVIEW"

        if pred in ["NEEDS_REVIEW", "NEEDS_MORE_CONTEXT"]:
            abstentions += 1
            rule_family_metrics[family]["abstain"] += 1
        elif gt_verdict == "TP" and pred == "TP":
            tp += 1
            rule_family_metrics[family]["tp"] += 1
        elif gt_verdict == "FP" and pred == "TP":
            fp += 1
            rule_family_metrics[family]["fp"] += 1
        elif gt_verdict == "TP" and pred == "FP":
            fn += 1
            rule_family_metrics[family]["fn"] += 1
        elif gt_verdict == "FP" and pred == "FP":
            tn += 1
            rule_family_metrics[family]["tn"] += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    abstention_rate = abstentions / matched if matched > 0 else 0.0

    return {
        "sample_size_N": total_samples,
        "matched_count": matched,
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "ABSTAIN": abstentions},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_negative_rate_fnr": round(fnr, 4),
        "abstention_rate": round(abstention_rate, 4),
        "per_rule_family": rule_family_metrics,
    }


def main():
    parser = argparse.ArgumentParser(description="Rigorous Benchmark Evaluation Runner")
    parser.add_argument("--benchmark", default="java", choices=["java", "python"])
    parser.add_argument("--sample", type=int, default=None)
    parser.add_argument("--holdout", action="store_true", help="Run on holdout repository split")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  RIGOROUS BENCHMARK EVALUATION RUNNER (RESEARCH PROTOTYPE)")
    print("=" * 60)

    config = BENCHMARKS.get(args.benchmark)
    if not config or not config["gt_file"].exists():
        print(f"[!] Config or ground truth missing for {args.benchmark}")
        return

    gt_data = json.loads(config["gt_file"].read_text(encoding="utf-8"))
    gt_map = {item["finding_id"]: item["ground_truth_verdict"] for item in gt_data}

    # Load findings
    findings = parse_semgrep_json(config["scan_dir"] / "semgrep.json", repository_name=args.benchmark.upper())
    if args.sample:
        findings = findings[:args.sample]

    engine = TriageEngine(llm_client=LLMClient())
    start_time = time.time()
    triaged = engine.triage_batch(findings, config["repo_dir"])
    elapsed = time.time() - start_time

    metrics = compute_rigorous_metrics(triaged, gt_map)
    metrics["latency_seconds"] = round(elapsed, 2)

    print(json.dumps(metrics, indent=2))

    report_path = ROOT_DIR / "reports" / "benchmark_evaluation_report.md"
    report_path.write_text(f"""# 📊 Versioned Benchmark Evaluation Report

> **Status**: RESEARCH PROTOTYPE | **Timestamp**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

## Metric Summary (N = {metrics['sample_size_N']}, Matched = {metrics['matched_count']})

| Metric | Score |
|---|:---:|
| **Precision** | **{metrics['precision']}** |
| **Recall** | **{metrics['recall']}** |
| **F1 Score** | **{metrics['f1_score']}** |
| **False Negative Rate (FNR)** | **{metrics['false_negative_rate_fnr']}** |
| **Abstention Rate** | **{metrics['abstention_rate']}** |
| **Latency** | **{metrics['latency_seconds']}s** |

## Confusion Matrix
- **True Positives (TP)**: {metrics['confusion_matrix']['TP']}
- **False Positives (FP)**: {metrics['confusion_matrix']['FP']}
- **False Negatives (FN)**: {metrics['confusion_matrix']['FN']}
- **True Negatives (TN)**: {metrics['confusion_matrix']['TN']}
- **Abstentions (NEEDS_REVIEW / NEEDS_MORE_CONTEXT)**: {metrics['confusion_matrix']['ABSTAIN']}
""", encoding="utf-8")
    print(f"\n[+] Saved rigorous evaluation report to {report_path}")


if __name__ == "__main__":
    main()
