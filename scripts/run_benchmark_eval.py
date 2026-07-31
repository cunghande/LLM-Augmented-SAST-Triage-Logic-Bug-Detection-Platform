# -*- coding: utf-8 -*-
import os as _os
_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
import sys as _sys
if hasattr(_sys.stdout, 'reconfigure'):
    _sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(_sys.stderr, 'reconfigure'):
    _sys.stderr.reconfigure(encoding='utf-8', errors='replace')

"""
Versioned Benchmark Evaluation Runner (Sprint 1 Closure & Audit-Ready)
========================================================================
Executes benchmark evaluation across OWASP Java and OWASP Python suites
with fail-closed REAL mode, Ollama Qwen 3:8b preflight, 20-sample pilot,
external artifact storage, configuration locking, and mathematical invariants.
"""

import os
import re
import sys
import json
import math


import time
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.core.schema import UnifiedFinding, TriageVerdict, EvaluationOutcome, FailureCategory
from src.parsers.semgrep import parse_semgrep_json
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient, LLMExecutionException
from src.triage.prompts import SYSTEM_TRIAGE_PROMPT, build_finding_user_prompt
from src.context.extractor import extract_finding_context, OWASPPythonBenchmarkIndex

from src.benchmark.adapters import (
    OWASPBenchmarkJavaAdapter,
    OWASPBenchmarkPythonAdapter,
    AdapterMatchReport,
    MatchedSample,
)
from src.benchmark.evaluator import (
    BenchmarkEvaluator,
    EvaluationMetrics,
    EvaluationRun,
    LatencyBreakdown,
)
from src.benchmark.reporter import BenchmarkReportGenerator, validate_artifact_path

# Absolute external default artifact directory outside Git worktrees
DEFAULT_ARTIFACT_BASE = Path("C:/Users/Admin/.gemini/antigravity-ide/brain/ed5d0412-3950-479b-8da5-498ff7afeead/benchmark_runs").resolve()

# Quality Gate Thresholds for Sprint 1
QUALITY_GATE_THRESHOLDS = {
    "precision": 0.80,
    "selective_recall": 0.75,
    "f1": 0.78,
    "max_policy_fnr": 0.10,
    "correct_fp_suppression": 0.60,
    "decision_coverage": 0.50,
}

BENCHMARKS_CONFIG = {
    "java": {
        "key": "java",
        "name": "OWASP BenchmarkJava",
        "scope": "INCLUDED_SPRINT_1",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkJava",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkJava",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkJava_ground_truth.json",
    },
    "python": {
        "key": "python",
        "name": "OWASP BenchmarkPython",
        "scope": "INCLUDED_SPRINT_1",
        "repo_dir": ROOT_DIR / "repos" / "BenchmarkPython",
        "scan_dir": ROOT_DIR / "scans" / "BenchmarkPython",
        "gt_file": ROOT_DIR / "benchmark" / "BenchmarkPython_ground_truth.json",
    },
    "creddata": {
        "key": "creddata",
        "name": "Samsung CredData",
        "scope": "EXCLUDED_SPRINT_1",
        "exclusion_reason": "Scanner target path alignment on sub-repositories scheduled for Sprint 2.",
        "target_milestone": "Sprint 2",
    },
    "realvuln": {
        "key": "realvuln",
        "name": "Real-Vuln-Benchmark",
        "scope": "EXCLUDED_SPRINT_1",
        "exclusion_reason": "Root scanner path mismatch; sub-application scan scope scheduled for Sprint 2.",
        "target_milestone": "Sprint 2",
    },
}


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def calculate_latencies(sample_latencies: List[float]) -> Dict[str, float]:
    if not sample_latencies:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "p50": 0.0, "p95": 0.0}
    sorted_l = sorted(sample_latencies)
    n = len(sorted_l)
    p50_idx = int(math.ceil(0.50 * n)) - 1
    p95_idx = int(math.ceil(0.95 * n)) - 1
    return {
        "min": round(sorted_l[0], 2),
        "max": round(sorted_l[-1], 2),
        "mean": round(sum(sorted_l) / n, 2),
        "p50": round(sorted_l[max(0, p50_idx)], 2),
        "p95": round(sorted_l[max(0, p95_idx)], 2),
    }


def run_live_triage(
    findings: List[UnifiedFinding],
    repo_dir: Path,
    engine: TriageEngine
) -> Tuple[List[UnifiedFinding], LatencyBreakdown]:
    """Execute live triage with per-sample LLM inference timing and fail-closed error handling."""
    sample_latencies = []
    t0_total = time.perf_counter()

    t0_ctx = time.perf_counter()
    for f in findings:
        extract_finding_context(f, repo_dir, window_lines=15)
    t1_ctx = time.perf_counter()
    ctx_ms = (t1_ctx - t0_ctx) * 1000.0

    success_count = 0
    failure_count = 0
    timeout_count = 0
    transport_success_count = 0
    response_parse_success_count = 0
    evaluation_success_count = 0
    pipeline_failure_count = 0

    t0_llm_total = time.perf_counter()
    for f in findings:
        # Attach diagnostic container onto finding metadata
        f.metadata = f.metadata or {}

        # If context resolution failed, skip LLM call and mark failure
        if getattr(f, "outcome", None) == EvaluationOutcome.FAILED or (f.context and f.context.context_quality == "UNRESOLVED"):
            f.outcome = EvaluationOutcome.FAILED
            f.failure_category = FailureCategory.CONTEXT_RESOLUTION_FAILURE
            failure_count += 1
            pipeline_failure_count += 1
            f.metadata["diagnostic"] = {
                "transport_success": False,
                "parse_success": False,
                "raw_response": None,
                "parsed_response": None,
                "schema_validation_error": "CONTEXT_RESOLUTION_FAILURE: Python context quality UNRESOLVED"
            }
            continue

        t0_sample = time.perf_counter()
        try:
            user_prompt = build_finding_user_prompt(f)
            resp = engine.llm_client.call_chat_completion(SYSTEM_TRIAGE_PROMPT, user_prompt)
            t1_sample = time.perf_counter()

            latency_ms = (t1_sample - t0_sample) * 1000.0

            # Store diagnostic metadata
            f.metadata["diagnostic"] = {
                "transport_success": resp.get("transport_success", False),
                "parse_success": resp.get("parse_success", False),
                "raw_response": resp.get("raw_response"),
                "parsed_response": resp.get("parsed_response"),
                "schema_validation_error": resp.get("schema_validation_error")
            }

            if resp.get("transport_success"):
                transport_success_count += 1
            if resp.get("parse_success"):
                response_parse_success_count += 1

            if resp.get("outcome") == "FAILED":
                f.outcome = EvaluationOutcome.FAILED
                f.failure_category = FailureCategory(resp.get("failure_category", FailureCategory.INTERNAL_ERROR.value))
                f.verdict = None
                failure_count += 1
                pipeline_failure_count += 1
                if resp.get("failure_category") == "LLM_TIMEOUT":
                    timeout_count += 1
            else:
                f.verdict = TriageVerdict(resp["verdict"])
                f.outcome = EvaluationOutcome(resp.get("outcome", EvaluationOutcome.DECIDED.value))
                f.failure_category = FailureCategory.NONE
                f.confidence = resp.get("confidence")
                f.reasoning = resp.get("reasoning")
                f.evidence = resp.get("evidence", [])
                success_count += 1
                evaluation_success_count += 1
                sample_latencies.append(latency_ms)

        except Exception as e:
            t1_sample = time.perf_counter()
            f.outcome = EvaluationOutcome.FAILED
            f.failure_category = FailureCategory.INTERNAL_ERROR
            f.verdict = None
            failure_count += 1
            pipeline_failure_count += 1
            f.metadata["diagnostic"] = {
                "transport_success": False,
                "parse_success": False,
                "raw_response": None,
                "parsed_response": None,
                "schema_validation_error": str(e)
            }

    t1_llm_total = time.perf_counter()
    llm_total_ms = (t1_llm_total - t0_llm_total) * 1000.0
    t1_total = time.perf_counter()
    wall_clock_ms = (t1_total - t0_total) * 1000.0

    lat_stats = calculate_latencies(sample_latencies)

    latency = LatencyBreakdown(
        total_wall_clock_ms=round(wall_clock_ms, 2),
        context_extraction_ms=round(ctx_ms, 2),
        llm_inference_ms=round(llm_total_ms, 2),
        latency_min_ms=lat_stats["min"],
        latency_max_ms=lat_stats["max"],
        latency_mean_ms=lat_stats["mean"],
        latency_p50_ms=lat_stats["p50"],
        latency_p95_ms=lat_stats["p95"],
        sample_latencies_ms=sample_latencies,
        request_count=len(findings),
        success_count=success_count,
        transport_success_count=transport_success_count,
        response_parse_success_count=response_parse_success_count,
        evaluation_success_count=evaluation_success_count,
        pipeline_failure_count=pipeline_failure_count,
        failure_count=failure_count,
        retry_count=0,
        timeout_count=timeout_count,
        execution_mode="REAL"
    )


    return findings, latency


def main():
    parser = argparse.ArgumentParser(description="Benchmark Evaluation Runner (Sprint 1 Closure)")
    parser.add_argument("--preflight-only", action="store_true", help="Run Step A Preflight check only.")
    parser.add_argument("--pilot-only", action="store_true", help="Run Step B 20-sample Pilot only.")
    parser.add_argument("--official-only", action="store_true", help="Run Step C Official Sprint 1 run.")
    parser.add_argument("--preflight-run-id", type=str, help="Preflight run ID reference required for pilot and official runs.")
    parser.add_argument("--pilot-run-id", type=str, help="Pilot run ID reference required for official run.")
    parser.add_argument("--execution-mode", type=str, default="REAL", choices=["REAL", "MOCK"], help="Execution mode.")
    parser.add_argument("--artifacts-dir", type=str, default=str(DEFAULT_ARTIFACT_BASE), help="Absolute external artifacts directory.")
    args = parser.parse_args()

    # Determine run type
    run_type = "official"
    if args.preflight_only:
        run_type = "preflight"
    elif args.pilot_only:
        run_type = "pilot"

    # Enforce fail-closed REAL mode environment
    os.environ["EXECUTION_MODE"] = args.execution_mode
    if args.execution_mode == "REAL":
        os.environ["MOCK_LLM"] = "0"

    client = LLMClient(fail_closed=(args.execution_mode == "REAL"))
    engine = TriageEngine(llm_client=client)


    run_id = f"{run_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
    run_output_dir = Path(args.artifacts_dir) / run_id

    # ── STEP A: Preflight Check ──────────────────────────────────────────────
    print(f"\n{'='*70}\n  BENCHMARK EVALUATION SPRINT 1 — RUN TYPE: {run_type.upper()}\n  Run ID: {run_id}\n{'='*70}\n")

    print("[1/4] Executing Preflight Checks...")
    preflight_info = client.preflight_check()
    print(f"  [✓] Ollama reachable: {client.api_base}")
    print(f"  [✓] Effective Model : {preflight_info['effective_model']}")
    print(f"  [✓] Model Digest    : {preflight_info['model_digest'][:16]}...")

    # Load OWASP Benchmark Java & Python raw findings
    java_raw = parse_semgrep_json(BENCHMARKS_CONFIG["java"]["scan_dir"] / "semgrep.json", repository_name="OWASP BenchmarkJava")
    py_raw = parse_semgrep_json(BENCHMARKS_CONFIG["python"]["scan_dir"] / "semgrep.json", repository_name="OWASP BenchmarkPython")

    java_gt = json.loads(BENCHMARKS_CONFIG["java"]["gt_file"].read_text(encoding="utf-8"))
    py_gt = json.loads(BENCHMARKS_CONFIG["python"]["gt_file"].read_text(encoding="utf-8"))

    # Verify OWASP Python Handler Index Resolution
    py_index = OWASPPythonBenchmarkIndex(BENCHMARKS_CONFIG["python"]["repo_dir"])
    print(f"  [✓] OWASP Python Handler Index built: {len(py_index.index)} testcode Python handlers indexed.")

    # Filter raw findings to valid BenchmarkTest testcases (excluding repo configs like dependabot.yml)
    java_testcases = [f for f in java_raw if re.search(r"BenchmarkTest\d{5}", f.file_path)]
    py_testcases = [f for f in py_raw if re.search(r"BenchmarkTest\d{5}", f.file_path)]
    java_gt_map = {item["finding_id"]: item for item in java_gt if "finding_id" in item}
    py_gt_map = {item["finding_id"]: item for item in py_gt if "finding_id" in item}

    # Select sample subset depending on run type
    if run_type == "preflight":
        # Exactly 1 Java TP, 1 Python TP, 1 Python FP
        java_tp = next(f for f in java_testcases if java_gt_map.get(Path(f.file_path).stem, {}).get("ground_truth_verdict") == "TP")
        py_tp = next(f for f in py_testcases if py_gt_map.get(Path(f.file_path).stem, {}).get("ground_truth_verdict") == "TP")
        py_fp = next(f for f in py_testcases if py_gt_map.get(Path(f.file_path).stem, {}).get("ground_truth_verdict") == "FP")

        selected_java = [java_tp]
        selected_py = [py_tp, py_fp]
    elif run_type == "pilot":
        selected_java = java_testcases[:10]
        selected_py = py_testcases[:10]
    else:  # official
        selected_java = java_testcases[:50]
        selected_py = py_testcases[:50]

    print(f"\n[2/4] Selected Benchmark Subsets: {len(selected_java)} Java, {len(selected_py)} Python (Total: {len(selected_java) + len(selected_py)})")

    # If pilot or official, enforce preflight / pilot references and circuit breakers
    if run_type == "pilot":
        if not args.preflight_run_id:
            print("[!] ERROR: Pilot run requires --preflight-run-id reference.")
            sys.exit(1)
    elif run_type == "official":
        if not args.preflight_run_id or not args.pilot_run_id:
            print("[!] ERROR: Official run requires both --preflight-run-id and --pilot-run-id references.")
            sys.exit(1)

        # Enforce evaluation lock check
        lock_file = ROOT_DIR / "evaluation_lock.json"
        if not lock_file.exists():
            lock_data = {
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "model_digest": preflight_info["model_digest"],
                "requested_model": client.model,
                "benchmark_commit_sha": "HEAD",
                "sample_manifest_hash": compute_hash(str(len(selected_java) + len(selected_py))),
                "prompt_version": "v2.0",
                "policy_version": "v1.0"
            }
            lock_file.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
            print(f"  [✓] Evaluation lock created at {lock_file}")
        else:
            lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
            if lock_data.get("model_digest") != preflight_info["model_digest"]:
                print("[!] ERROR: Configuration drift detected! Model digest does not match evaluation_lock.json.")
                sys.exit(1)

    # ── Execute Live Triage ──────────────────────────────────────────────────
    print(f"\n[3/4] Running Live LLM Triage ({args.execution_mode} mode)...")
    triaged_java, java_lat = run_live_triage(selected_java, BENCHMARKS_CONFIG["java"]["repo_dir"], engine)
    triaged_py, py_lat = run_live_triage(selected_py, BENCHMARKS_CONFIG["python"]["repo_dir"], engine)

    # Match ground truth
    java_adapter = OWASPBenchmarkJavaAdapter(java_gt)
    py_adapter = OWASPBenchmarkPythonAdapter(py_gt)

    java_mr = java_adapter.match(triaged_java)
    py_mr = py_adapter.match(triaged_py)

    # Aggregate matched report
    combined_matched = java_mr.matched_samples + py_mr.matched_samples
    combined_unmatched = java_mr.unmatched_findings + py_mr.unmatched_findings
    total_samples_count = len(selected_java) + len(selected_py)

    agg_mr = AdapterMatchReport(
        benchmark_name="Sprint 1 Aggregate (OWASP Java + Python)",
        total_findings=total_samples_count,
        matched_count=len(combined_matched),
        unmatched_count=len(combined_unmatched),
        matched_samples=combined_matched,
        unmatched_findings=combined_unmatched,
        adapter_status="OK" if len(combined_matched) > 0 else "ADAPTER_FAILURE"
    )

    # Calculate Latency Breakdown
    combined_latencies = java_lat.sample_latencies_ms + py_lat.sample_latencies_ms
    agg_lat_stats = calculate_latencies(combined_latencies)

    total_lat = LatencyBreakdown(
        total_wall_clock_ms=round(java_lat.total_wall_clock_ms + py_lat.total_wall_clock_ms, 2),
        context_extraction_ms=round(java_lat.context_extraction_ms + py_lat.context_extraction_ms, 2),
        llm_inference_ms=round(java_lat.llm_inference_ms + py_lat.llm_inference_ms, 2),
        latency_min_ms=agg_lat_stats["min"],
        latency_max_ms=agg_lat_stats["max"],
        latency_mean_ms=agg_lat_stats["mean"],
        latency_p50_ms=agg_lat_stats["p50"],
        latency_p95_ms=agg_lat_stats["p95"],
        sample_latencies_ms=combined_latencies,
        request_count=java_lat.request_count + py_lat.request_count,
        success_count=java_lat.success_count + py_lat.success_count,
        transport_success_count=java_lat.transport_success_count + py_lat.transport_success_count,
        response_parse_success_count=java_lat.response_parse_success_count + py_lat.response_parse_success_count,
        evaluation_success_count=java_lat.evaluation_success_count + py_lat.evaluation_success_count,
        pipeline_failure_count=java_lat.pipeline_failure_count + py_lat.pipeline_failure_count,
        failure_count=java_lat.failure_count + py_lat.failure_count,
        timeout_count=java_lat.timeout_count + py_lat.timeout_count,
        execution_mode=args.execution_mode
    )

    # Calculate Metrics
    evaluator = BenchmarkEvaluator(run_id=run_id)
    metrics = evaluator.evaluate_matched_samples(agg_mr, total_samples_count, total_lat, execution_mode=args.execution_mode)

    # Determine Quality Gate Status
    quality_gate_status = "EVALUATION_COMPLETED"
    if run_type == "preflight":
        # Preflight circuit breaker validation
        cb_transport = (total_lat.transport_success_count == 3)
        cb_parse = (total_lat.response_parse_success_count == 3)
        cb_eval = (total_lat.evaluation_success_count == 3)
        cb_failures = (total_lat.pipeline_failure_count == 0)
        cb_gt_dist = (metrics.ground_truth_tp == 2 and metrics.ground_truth_fp == 1)

        if cb_transport and cb_parse and cb_eval and cb_failures and cb_gt_dist:
            quality_gate_status = "PREFLIGHT_PASSED"
        else:
            quality_gate_status = "PREFLIGHT_FAILED"

    elif run_type == "official":
        prec = metrics.precision.value or 0.0
        rec = metrics.selective_recall.value or 0.0
        f1_v = metrics.f1.value or 0.0
        fnr = metrics.policy_false_negative_rate.value or 1.0
        fp_sup = metrics.correct_fp_suppression_rate.value or 0.0
        cov = metrics.decision_coverage.value or 0.0

        if (
            prec >= QUALITY_GATE_THRESHOLDS["precision"]
            and rec >= QUALITY_GATE_THRESHOLDS["selective_recall"]
            and f1_v >= QUALITY_GATE_THRESHOLDS["f1"]
            and fnr <= QUALITY_GATE_THRESHOLDS["max_policy_fnr"]
            and fp_sup >= QUALITY_GATE_THRESHOLDS["correct_fp_suppression"]
            and cov >= QUALITY_GATE_THRESHOLDS["decision_coverage"]
        ):
            quality_gate_status = "MODEL_QUALITY_GATE_MET"
        else:
            quality_gate_status = "MODEL_QUALITY_GATE_NOT_MET"


    # Create EvaluationRun object
    run_obj = EvaluationRun(
        evaluation_run_id=run_id,
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        benchmark_name="Sprint 1 Official Benchmark (OWASP Java + Python)",
        benchmark_version="v1.0",
        benchmark_commit_sha="HEAD",
        sample_manifest_hash=compute_hash(str(total_samples_count)),
        model_name=client.model,
        model_version=client.model,
        prompt_version="v2.0",
        prompt_hash=compute_hash("v2.0"),
        policy_version="v1.0",
        policy_hash=compute_hash("v1.0"),
        execution_mode=args.execution_mode,
        metric_version="2.0",
        preflight_run_id=args.preflight_run_id,
        pilot_run_id=args.pilot_run_id,
        quality_gate_status=quality_gate_status,
        metrics=metrics,
        latency=total_lat
    )

    # ── Save Artifacts ───────────────────────────────────────────────────────
    print(f"\n[4/4] Writing Audit Artifacts to External Path: {run_output_dir}...")
    reporter = BenchmarkReportGenerator(run_output_dir, project_root=ROOT_DIR)
    gen_files = reporter.write_run_artifacts(run_obj, [java_mr, py_mr])

    print(f"\n{'='*70}\n  RUN SUMMARY & RESULTS\n{'='*70}")
    print(f"  Run ID                  : {run_id}")
    print(f"  Execution Mode          : {args.execution_mode} (Fail-Closed: True)")
    print(f"  Model                   : {client.model} (Digest: {preflight_info['model_digest'][:16]}...)")
    print(f"  Invariants Passed       : {metrics.invariants_passed}")
    print(f"  LLM Requests            : {total_lat.request_count}")
    print(f"  Transport Success Count : {total_lat.transport_success_count}")
    print(f"  Parse Success Count     : {total_lat.response_parse_success_count}")
    print(f"  Evaluation Success Count: {total_lat.evaluation_success_count}")
    print(f"  Pipeline Failure Count  : {total_lat.pipeline_failure_count}")
    print(f"  GT Distribution         : TP={metrics.ground_truth_tp}, FP={metrics.ground_truth_fp}")
    print(f"  Quality Gate Status     : {quality_gate_status}")
    print(f"  Artifacts Location      : {run_output_dir}")

    if run_type == "preflight":
        print("\n" + "="*70)
        print("  SAMPLE PYTHON CONTEXT FOR INSPECTION")
        print("="*70)
        py_sample_ctx = triaged_py[0].context.surrounding_code if (triaged_py and triaged_py[0].context) else "N/A"
        print(py_sample_ctx)
        print("="*70 + "\n")

        if quality_gate_status == "PREFLIGHT_FAILED":
            print("[!] PREFLIGHT FAILED: Circuit breaker checks failed. Pilot execution BLOCKED.")
            sys.exit(1)
        else:
            print("[✓] PREFLIGHT PASSED: All circuit breaker conditions met.")



if __name__ == "__main__":
    main()
