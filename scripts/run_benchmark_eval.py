# -*- coding: utf-8 -*-
import os as _os
_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
import sys as _sys
if hasattr(_sys.stdout, 'reconfigure'):
    _sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(_sys.stderr, 'reconfigure'):
    _sys.stderr.reconfigure(encoding='utf-8', errors='replace')
"""
Master Benchmark Evaluation Runner
====================================
Orchestrates full evaluation pipeline across all 4 benchmark suites:
  1. OWASP BenchmarkJava  (Java SAST — Semgrep scan)
  2. OWASP BenchmarkPython (Python SAST — Semgrep scan)
  3. Real-Vuln-Benchmark  (Real-world vulns — Semgrep scan)
  4. Samsung CredData      (Secret detection — Gitleaks scan, 25 repos)

Usage:
  python scripts/run_benchmark_eval.py --benchmark all
  python scripts/run_benchmark_eval.py --benchmark java --sample 100
  python scripts/run_benchmark_eval.py --benchmark creddata --mock
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

from src.core.schema import UnifiedFinding, ScannerType, Severity, FindingStatus
from src.parsers.semgrep import parse_semgrep_json, parse_semgrep_sarif
from src.parsers.gitleaks import parse_gitleaks_json
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient
from src.reporters.reporter import evaluate_triage_performance, generate_json_report


# ─── Benchmark Configurations ─────────────────────────────────────────────────

BENCHMARKS = {
    "java": {
        "name": "OWASP BenchmarkJava",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkJava",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkJava",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkJava_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "BenchmarkJava",
        "scan_type": "semgrep",  # Primary scanner
        "language": "java",
        "gt_parser_script": "scripts/parse_owasp_benchmark.py",
    },
    "python": {
        "name": "OWASP BenchmarkPython",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkPython",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkPython",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkPython_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "BenchmarkPython",
        "scan_type": "semgrep",
        "language": "python",
        "gt_parser_script": "scripts/parse_owasp_python_benchmark.py",
    },
    "realvuln": {
        "name": "Real-Vuln-Benchmark",
        "repo_dir": ROOT_DIR / "repos" / "Real-Vuln-Benchmark",
        "scan_dir": ROOT_DIR / "scans" / "Real-Vuln-Benchmark",
        "gt_file": ROOT_DIR / "benchmark" / "RealVuln_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "RealVuln",
        "scan_type": "semgrep",
        "language": "python",
        "gt_parser_script": "scripts/parse_realvuln_benchmark.py",
    },
    "creddata": {
        "name": "Samsung CredData",
        "repo_dir": ROOT_DIR / "repos" / "CredData",
        "scan_dir": ROOT_DIR / "scans" / "CredData",
        "gt_file": ROOT_DIR / "benchmark" / "CredData_ground_truth.json",
        "report_dir": ROOT_DIR / "reports" / "CredData",
        "scan_type": "gitleaks",  # Primary scanner for secrets
        "language": "multi",
        "gt_parser_script": "scripts/parse_creddata_benchmark.py",
    },
}


def check_tool_available(tool_name: str) -> bool:
    """Check if a CLI tool is available in PATH."""
    try:
        result = subprocess.run(
            [tool_name, "--version"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0 or result.stdout.strip() != ""
    except Exception:
        return False


def check_ollama_available() -> bool:
    """Check if Ollama is running and model is available."""
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            return any("qwen3" in n for n in model_names)
    except Exception:
        pass
    return False


def run_semgrep_scan(repo_dir: Path, scan_dir: Path) -> int:
    """Run Semgrep scan on a repository."""
    scan_dir.mkdir(parents=True, exist_ok=True)
    out_json = scan_dir / "semgrep.json"

    if out_json.exists() and out_json.stat().st_size > 100:
        print(f"    [*] Semgrep scan already exists at {out_json}, skipping...")
        return 0

    cmd = ["semgrep", "scan", "--config", "auto", "--json",
           "--output", str(out_json), str(repo_dir)]
    print(f"    [*] Running: {' '.join(cmd[:6])}...")
    result = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600)
    print(f"    [+] Semgrep exit code: {result.returncode}")
    return result.returncode


def run_gitleaks_scan(repo_dir: Path, scan_dir: Path) -> int:
    """Run Gitleaks scan on a repository."""
    scan_dir.mkdir(parents=True, exist_ok=True)
    out_json = scan_dir / "gitleaks.json"

    if out_json.exists() and out_json.stat().st_size > 10:
        print(f"    [*] Gitleaks scan already exists at {out_json}, skipping...")
        return 0

    cmd = ["gitleaks", "detect", "--source", str(repo_dir),
           "--report-format", "json", "--report-path", str(out_json), "--no-git"]
    print(f"    [*] Running: {' '.join(cmd[:6])}...")
    result = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600)
    print(f"    [+] Gitleaks exit code: {result.returncode}")
    return result.returncode


def load_findings_from_scans(scan_dir: Path, repo_name: str,
                              scan_type: str) -> List[UnifiedFinding]:
    """Load parsed findings from scan output files."""
    findings = []

    if scan_type in ("semgrep", "both"):
        semgrep_json = scan_dir / "semgrep.json"
        if semgrep_json.exists():
            findings.extend(parse_semgrep_json(semgrep_json, repo_name))

        semgrep_sarif = scan_dir / "semgrep.sarif"
        if semgrep_sarif.exists():
            findings.extend(parse_semgrep_sarif(semgrep_sarif, repo_name))

    if scan_type in ("gitleaks", "both"):
        gitleaks_json = scan_dir / "gitleaks.json"
        if gitleaks_json.exists():
            findings.extend(parse_gitleaks_json(gitleaks_json, repo_name))

    return findings


def build_ground_truth_map(gt_file: Path) -> Dict[str, str]:
    """Load ground truth JSON and build lookup map."""
    with open(gt_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    gt_map = {}
    for item in gt_data:
        gt_map[item["finding_id"]] = item["ground_truth_verdict"]
        if "rule_id" in item:
            gt_map[item["rule_id"]] = item["ground_truth_verdict"]
    return gt_map


def match_findings_to_ground_truth(
    findings: List[UnifiedFinding],
    gt_file: Path,
    benchmark_key: str
) -> Dict[str, str]:
    """
    Build ground truth map with enhanced matching logic per benchmark type.
    Returns a map: finding_id -> ground_truth_verdict
    """
    with open(gt_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    gt_map = {}

    if benchmark_key in ("java", "python"):
        # OWASP Benchmark: match by test name in file path
        # GT finding_id = "BenchmarkTest00001", match against file stem
        for item in gt_data:
            gt_map[item["finding_id"]] = item["ground_truth_verdict"]

    elif benchmark_key == "realvuln":
        # Real-Vuln: match by file path + CWE + line proximity
        for item in gt_data:
            gt_map[item["finding_id"]] = item["ground_truth_verdict"]
            # Also index by file path for fuzzy matching
            if "file_path" in item:
                file_key = item["file_path"]
                gt_map[file_key] = item["ground_truth_verdict"]

    elif benchmark_key == "creddata":
        # CredData: match by file path + line number
        for item in gt_data:
            gt_map[item["finding_id"]] = item["ground_truth_verdict"]
            if "file_path" in item and "line_start" in item:
                path_key = f"{item['file_path']}:{item['line_start']}"
                gt_map[path_key] = item["ground_truth_verdict"]

    return gt_map


def enhanced_evaluate(
    findings: List[UnifiedFinding],
    gt_map: Dict[str, str],
    benchmark_key: str
) -> Dict[str, Any]:
    """
    Enhanced evaluation with benchmark-specific matching strategies.
    """
    tp = 0  # GT=TP, Pred=TP
    fp = 0  # GT=FP, Pred=TP
    fn = 0  # GT=TP, Pred=FP
    tn = 0  # GT=FP, Pred=FP
    needs_review = 0
    matched = 0
    unmatched = 0

    for f in findings:
        # Try multiple matching strategies
        gt_verdict = None

        # Strategy 1: Direct finding_id match
        gt_verdict = gt_map.get(f.finding_id)

        # Strategy 2: Rule ID match
        if not gt_verdict:
            gt_verdict = gt_map.get(f.rule_id)

        # Strategy 3: File stem match (for OWASP benchmarks)
        if not gt_verdict and benchmark_key in ("java", "python"):
            file_stem = Path(f.file_path).stem
            gt_verdict = gt_map.get(file_stem)

        # Strategy 4: File path match (for RealVuln)
        if not gt_verdict and benchmark_key == "realvuln":
            # Try matching file path suffix
            for gt_key, gt_val in gt_map.items():
                if gt_key in f.file_path or f.file_path.endswith(gt_key):
                    gt_verdict = gt_val
                    break

        # Strategy 5: File path + line match (for CredData)
        if not gt_verdict and benchmark_key == "creddata":
            path_key = f"{f.file_path}:{f.start_line}"
            gt_verdict = gt_map.get(path_key)

        if not gt_verdict:
            unmatched += 1
            continue

        matched += 1
        pred = f.verdict.value if f.verdict else "NEEDS_REVIEW"

        if pred == "NEEDS_REVIEW":
            needs_review += 1
        elif gt_verdict == "TP" and pred == "TP":
            tp += 1
        elif gt_verdict == "FP" and pred == "TP":
            fp += 1
        elif gt_verdict == "TP" and pred == "FP":
            fn += 1
        elif gt_verdict == "FP" and pred == "FP":
            tn += 1

    total_classified = tp + fp + fn + tn + needs_review
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total_classified if total_classified > 0 else 0.0
    fp_reduction = tn / (tn + fp) * 100.0 if (tn + fp) > 0 else 0.0

    return {
        "total_findings": len(findings),
        "matched": matched,
        "unmatched": unmatched,
        "total_classified": total_classified,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "needs_review": needs_review,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fp_reduction_pct": round(fp_reduction, 2),
    }


def run_single_benchmark(
    benchmark_key: str,
    config: Dict,
    llm_client: LLMClient,
    sample: Optional[int] = None,
    skip_scan: bool = False,
) -> Dict[str, Any]:
    """Run full evaluation pipeline for a single benchmark."""
    name = config["name"]
    repo_dir = config["repo_dir"]
    scan_dir = config["scan_dir"]
    gt_file = config["gt_file"]
    report_dir = config["report_dir"]
    scan_type = config["scan_type"]

    print(f"\n{'='*60}")
    print(f"  BENCHMARK: {name}")
    print(f"{'='*60}")

    # Step 0: Ensure ground truth exists
    if not gt_file.exists():
        gt_script = config.get("gt_parser_script")
        if gt_script:
            print(f"  [*] Generating ground truth from {gt_script}...")
            subprocess.run(
                [sys.executable, gt_script],
                cwd=str(ROOT_DIR), encoding="utf-8", errors="replace"
            )

    if not gt_file.exists():
        print(f"  [!] Ground truth file not found: {gt_file}")
        return {"error": f"Ground truth not found for {name}"}

    # Step 1: Scan
    if not skip_scan:
        print(f"  [*] Step 1/3: Scanning with {scan_type}...")
        if scan_type == "semgrep":
            # For RealVuln, scan vc_repos subdirectories
            if benchmark_key == "realvuln":
                vc_repos_dir = repo_dir / "vc_repos"
                if vc_repos_dir.exists():
                    run_semgrep_scan(vc_repos_dir, scan_dir)
                else:
                    run_semgrep_scan(repo_dir, scan_dir)
            else:
                run_semgrep_scan(repo_dir, scan_dir)
        elif scan_type == "gitleaks":
            # For CredData, scan the data directory
            data_dir = repo_dir / "data"
            if data_dir.exists():
                run_gitleaks_scan(data_dir, scan_dir)
            else:
                run_gitleaks_scan(repo_dir, scan_dir)
    else:
        print(f"  [*] Step 1/3: Skipping scan (--skip-scan)")

    # Step 2: Parse findings
    print(f"  [*] Step 2/3: Loading & triaging findings...")
    repo_name = benchmark_key.upper()
    findings = load_findings_from_scans(scan_dir, repo_name, scan_type)
    # Also try "both" scan types
    if not findings:
        findings = load_findings_from_scans(scan_dir, repo_name, "both")

    print(f"    [+] Raw findings loaded: {len(findings)}")

    if not findings:
        print(f"  [!] No findings from scanner. Evaluating with empty results.")
        return {
            "benchmark": name,
            "total_findings": 0,
            "matched": 0,
            "error": "No scan findings produced",
        }

    # Apply sample limit (prioritize actual testcode files containing ground truth over helpers/configs)
    if benchmark_key in ("java", "python"):
        testcode_findings = [f for f in findings if "benchmarktest" in f.file_path.replace("\\", "/").lower()]
    else:
        testcode_findings = [f for f in findings if "testcode" in f.file_path.replace("\\", "/").lower() or "src/" in f.file_path.replace("\\", "/").lower() or "data/" in f.file_path.replace("\\", "/").lower()]

    if testcode_findings:
        findings = testcode_findings

    if sample and sample < len(findings):
        print(f"    [*] Sampling {sample} of {len(findings)} relevant findings...")
        findings = findings[:sample]

    # Step 3: Triage with LLM
    engine = TriageEngine(llm_client=llm_client)
    triaged = []
    start_time = time.time()
    total = len(findings)

    for i, finding in enumerate(findings):
        try:
            triaged_finding = engine.triage_finding(finding, repo_dir)
            triaged.append(triaged_finding)
        except Exception as e:
            print(f"    [!] Error triaging finding {finding.finding_id}: {e}")
            finding.verdict = None
            triaged.append(finding)

        if (i + 1) % 10 == 0 or (i + 1) == total:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(f"    [+] Progress: {i+1}/{total} ({rate:.1f}/s, ETA: {eta:.0f}s)")

    elapsed_total = time.time() - start_time
    print(f"    [+] Triage completed in {elapsed_total:.1f}s")

    # Save triaged results
    report_dir.mkdir(parents=True, exist_ok=True)
    triage_output = report_dir / "triage_result.json"
    generate_json_report(triaged, str(triage_output))
    print(f"    [+] Saved triage results to {triage_output}")

    # Step 4: Evaluate
    print(f"  [*] Step 3/3: Evaluating against ground truth...")
    gt_map = match_findings_to_ground_truth(triaged, gt_file, benchmark_key)
    metrics = enhanced_evaluate(triaged, gt_map, benchmark_key)
    metrics["benchmark"] = name
    metrics["benchmark_key"] = benchmark_key
    metrics["elapsed_seconds"] = round(elapsed_total, 1)

    # Print metrics
    print(f"\n  ┌──────────────────────────────────────────┐")
    print(f"  │  {name:^40s}  │")
    print(f"  ├──────────────────────────────────────────┤")
    print(f"  │  Total Findings   : {metrics['total_findings']:>18d}  │")
    print(f"  │  Matched to GT    : {metrics['matched']:>18d}  │")
    print(f"  │  Unmatched        : {metrics['unmatched']:>18d}  │")
    print(f"  │  ──────────────────────────────────────── │")
    print(f"  │  True Positives   : {metrics['true_positives']:>18d}  │")
    print(f"  │  False Positives  : {metrics['false_positives']:>18d}  │")
    print(f"  │  False Negatives  : {metrics['false_negatives']:>18d}  │")
    print(f"  │  True Negatives   : {metrics['true_negatives']:>18d}  │")
    print(f"  │  Needs Review     : {metrics['needs_review']:>18d}  │")
    print(f"  │  ──────────────────────────────────────── │")
    print(f"  │  Precision        : {metrics['precision']:>17.4f}  │")
    print(f"  │  Recall           : {metrics['recall']:>17.4f}  │")
    print(f"  │  F1 Score         : {metrics['f1_score']:>17.4f}  │")
    print(f"  │  Accuracy         : {metrics['accuracy']:>17.4f}  │")
    print(f"  │  FP Reduction %   : {metrics['fp_reduction_pct']:>16.2f}%  │")
    print(f"  │  Time Elapsed     : {metrics['elapsed_seconds']:>16.1f}s  │")
    print(f"  └──────────────────────────────────────────┘")

    return metrics


def generate_final_report(all_metrics: List[Dict[str, Any]], output_path: Path):
    """Generate comprehensive Markdown evaluation report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_findings = sum(m.get("total_findings", 0) for m in all_metrics)
    total_matched = sum(m.get("matched", 0) for m in all_metrics)

    # Calculate overall metrics
    total_tp = sum(m.get("true_positives", 0) for m in all_metrics)
    total_fp = sum(m.get("false_positives", 0) for m in all_metrics)
    total_fn = sum(m.get("false_negatives", 0) for m in all_metrics)
    total_tn = sum(m.get("true_negatives", 0) for m in all_metrics)
    total_nr = sum(m.get("needs_review", 0) for m in all_metrics)

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)
                  if (overall_precision + overall_recall) > 0 else 0)
    overall_accuracy = ((total_tp + total_tn) /
                        (total_tp + total_fp + total_fn + total_tn + total_nr)
                        if (total_tp + total_fp + total_fn + total_tn + total_nr) > 0 else 0)
    overall_fp_reduction = total_tn / (total_tn + total_fp) * 100 if (total_tn + total_fp) > 0 else 0

    md = [
        "# 📊 LLM SAST Triage — Benchmark Evaluation Report",
        "",
        f"> **Generated**: {timestamp} | **Model**: Qwen 3:8b (Ollama) | **Platform**: LLM-Augmented SAST Triage",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Evaluated the LLM-Augmented SAST Triage platform against **{len(all_metrics)} benchmark suites** ",
        f"covering **{total_findings} total findings** with **{total_matched} ground-truth matched** entries.",
        "",
        "### Overall Metrics",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| **Precision** | **{overall_precision:.4f}** |",
        f"| **Recall** | **{overall_recall:.4f}** |",
        f"| **F1 Score** | **{overall_f1:.4f}** |",
        f"| **Accuracy** | **{overall_accuracy:.4f}** |",
        f"| **FP Reduction Rate** | **{overall_fp_reduction:.2f}%** |",
        f"| Total Findings Processed | {total_findings} |",
        f"| Ground-Truth Matched | {total_matched} |",
        "",
        "### Confusion Matrix (Overall)",
        "",
        "|  | **Predicted TP** | **Predicted FP** | **NEEDS_REVIEW** |",
        "|---|:---:|:---:|:---:|",
        f"| **Actual TP** | ✅ {total_tp} | ❌ {total_fn} | ⚠️ — |",
        f"| **Actual FP** | ❌ {total_fp} | ✅ {total_tn} | ⚠️ — |",
        f"| **Review** | — | — | {total_nr} |",
        "",
        "---",
        "",
        "## Per-Benchmark Results",
        "",
        "| Benchmark | Findings | Matched | Precision | Recall | F1 Score | FP Reduction | Time |",
        "|-----------|:--------:|:-------:|:---------:|:------:|:--------:|:------------:|:----:|",
    ]

    for m in all_metrics:
        if "error" in m and "precision" not in m:
            md.append(f"| {m.get('benchmark', 'N/A')} | {m.get('total_findings', 0)} | "
                      f"{m.get('matched', 0)} | — | — | — | — | — |")
        else:
            md.append(
                f"| **{m.get('benchmark', 'N/A')}** | {m.get('total_findings', 0)} | "
                f"{m.get('matched', 0)} | {m.get('precision', 0):.4f} | "
                f"{m.get('recall', 0):.4f} | {m.get('f1_score', 0):.4f} | "
                f"{m.get('fp_reduction_pct', 0):.1f}% | {m.get('elapsed_seconds', 0):.0f}s |"
            )

    md.extend([
        "",
        "---",
        "",
        "## Detailed Per-Benchmark Analysis",
        "",
    ])

    for m in all_metrics:
        if "error" in m and "precision" not in m:
            continue

        md.extend([
            f"### {m.get('benchmark', 'N/A')}",
            "",
            "| Metric | Value |",
            "|--------|------:|",
            f"| Total Findings | {m.get('total_findings', 0)} |",
            f"| Ground-Truth Matched | {m.get('matched', 0)} |",
            f"| Unmatched | {m.get('unmatched', 0)} |",
            f"| True Positives (TP→TP) | {m.get('true_positives', 0)} |",
            f"| False Positives (FP→TP) | {m.get('false_positives', 0)} |",
            f"| False Negatives (TP→FP) | {m.get('false_negatives', 0)} |",
            f"| True Negatives (FP→FP) | {m.get('true_negatives', 0)} |",
            f"| Needs Review | {m.get('needs_review', 0)} |",
            f"| **Precision** | **{m.get('precision', 0):.4f}** |",
            f"| **Recall** | **{m.get('recall', 0):.4f}** |",
            f"| **F1 Score** | **{m.get('f1_score', 0):.4f}** |",
            f"| **Accuracy** | **{m.get('accuracy', 0):.4f}** |",
            f"| **FP Reduction** | **{m.get('fp_reduction_pct', 0):.2f}%** |",
            f"| Processing Time | {m.get('elapsed_seconds', 0):.1f}s |",
            "",
        ])

    md.extend([
        "---",
        "",
        "## Interpretation Guide",
        "",
        "- **Precision**: Of all findings our LLM classified as TP, what % are actually TP?",
        "- **Recall**: Of all actual TP findings, what % did our LLM correctly identify?",
        "- **F1 Score**: Harmonic mean of Precision and Recall (balanced measure).",
        "- **FP Reduction**: % of actual FP findings correctly identified as FP (noise suppressed).",
        "- **NEEDS_REVIEW**: Findings where LLM confidence was insufficient for auto-classification.",
        "",
        "## Recommended Targets",
        "",
        "| Metric | Target | Status |",
        "|--------|:------:|:------:|",
        f"| Precision | ≥ 0.80 | {'✅' if overall_precision >= 0.80 else '❌'} {overall_precision:.4f} |",
        f"| Recall | ≥ 0.75 | {'✅' if overall_recall >= 0.75 else '❌'} {overall_recall:.4f} |",
        f"| F1 Score | ≥ 0.78 | {'✅' if overall_f1 >= 0.78 else '❌'} {overall_f1:.4f} |",
        f"| FP Reduction | ≥ 60% | {'✅' if overall_fp_reduction >= 60 else '❌'} {overall_fp_reduction:.2f}% |",
        "",
        "---",
        "",
        f"*Report generated by LLM-Augmented SAST Triage Platform — {timestamp}*",
    ])

    output_path.write_text("\n".join(md), encoding="utf-8")
    return str(output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Master Benchmark Evaluation Runner for LLM SAST Triage Platform"
    )
    parser.add_argument(
        "--benchmark", default="all",
        choices=["all", "java", "python", "realvuln", "creddata"],
        help="Which benchmark to evaluate (default: all)"
    )
    parser.add_argument(
        "--sample", type=int, default=None,
        help="Limit number of findings per benchmark (for quick testing)"
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Use mock LLM instead of real Ollama"
    )
    parser.add_argument(
        "--skip-scan", action="store_true",
        help="Skip SAST scanning step (use existing scan results)"
    )
    args = parser.parse_args()

    print("\n" + "#" * 60)
    print("  LLM SAST TRIAGE — BENCHMARK EVALUATION RUNNER")
    print("#" * 60)

    # ── Pre-flight checks ─────────────────────────────────────────────────
    print("\n[*] Pre-flight checks...")

    if not args.mock:
        if check_ollama_available():
            print("    [OK] Ollama + Qwen 3:8b is running")
        else:
            print("    [WARN] Ollama/Qwen 3:8b not detected! Falling back to heuristic mock.")
            print("       Results will not reflect true LLM capability.")
            print("       Run: ollama run qwen3:8b")
    else:
        print("    [INFO] Mock mode enabled (MOCK_LLM=1)")

    if not args.skip_scan:
        semgrep_ok = check_tool_available("semgrep")
        gitleaks_ok = check_tool_available("gitleaks")
        print(f"    {'[OK]' if semgrep_ok else '[FAIL]'} Semgrep {'available' if semgrep_ok else 'NOT FOUND'}")
        print(f"    {'[OK]' if gitleaks_ok else '[FAIL]'} Gitleaks {'available' if gitleaks_ok else 'NOT FOUND'}")
        if not semgrep_ok or not gitleaks_ok:
            missing = []
            if not semgrep_ok:
                missing.append("semgrep")
            if not gitleaks_ok:
                missing.append("gitleaks")
            print(f"\n    [!] MISSING TOOL: {', '.join(missing)}")
            print(f"        Install: pip install semgrep / brew install gitleaks")
            print(f"        Or run with --skip-scan if scan results already exist.")
            sys.exit(1)

    # ── Initialize LLM Client ──────────────────────────────────────────────
    import os
    if args.mock:
        os.environ["MOCK_LLM"] = "1"
    llm_client = LLMClient()
    print(f"    [INFO] LLM Client: {llm_client.api_base} | Model: {llm_client.model} "
          f"| Mock: {llm_client.mock_mode}")

    # ── Determine benchmarks to run ────────────────────────────────────────
    if args.benchmark == "all":
        benchmarks_to_run = list(BENCHMARKS.items())
    else:
        benchmarks_to_run = [(args.benchmark, BENCHMARKS[args.benchmark])]

    # ── Run evaluations ────────────────────────────────────────────────────
    all_metrics = []
    overall_start = time.time()

    for bench_key, bench_config in benchmarks_to_run:
        if not bench_config["repo_dir"].exists():
            print(f"\n[!] Repo directory not found: {bench_config['repo_dir']}")
            print(f"    Clone it first: git clone ... repos/{bench_config['repo_dir'].name}")
            continue

        metrics = run_single_benchmark(
            bench_key, bench_config, llm_client,
            sample=args.sample, skip_scan=args.skip_scan
        )
        all_metrics.append(metrics)

    overall_elapsed = time.time() - overall_start

    # ── Generate final report ──────────────────────────────────────────────
    report_path = ROOT_DIR / "reports" / "benchmark_evaluation_report.md"
    generate_final_report(all_metrics, report_path)
    print(f"\n[OK] Final evaluation report saved to: {report_path}")

    # Save raw metrics JSON
    metrics_path = ROOT_DIR / "reports" / "benchmark_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2, ensure_ascii=False)
    print(f"[OK] Raw metrics saved to: {metrics_path}")

    # ── Print final summary ────────────────────────────────────────────────
    print(f"\n{'#'*60}")
    print(f"  BENCHMARK EVALUATION COMPLETE")
    print(f"{'#'*60}")
    print(f"  Total benchmarks   : {len(all_metrics)}")
    print(f"  Total time         : {overall_elapsed:.1f}s")
    print(f"  Report             : {report_path}")
    print(f"{'#'*60}\n")


if __name__ == "__main__":
    main()
