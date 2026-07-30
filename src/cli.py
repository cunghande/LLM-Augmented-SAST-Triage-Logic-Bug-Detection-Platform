import sys
import json
import argparse
from pathlib import Path
from typing import List, Optional

from src.core.schema import (
    UnifiedFinding,
    ScanStage,
    CIMode,
    TriageVerdict,
    Severity,
)
from src.parsers.gitleaks import parse_gitleaks_json
from src.parsers.semgrep import parse_semgrep_sarif, parse_semgrep_json
from src.pipeline.stage_scan import ScanStageRunner
from src.pipeline.stage_validate import ValidateStageRunner
from src.pipeline.stage_patch import PatchStageRunner
from src.pipeline.stage_compare import CompareStageRunner
from src.reporters.storage import ExternalStorageManager
from src.reporters.reporter import generate_json_report, generate_priority_report
from src.risk.scorer import RiskScorer
from src.triage.llm_client import LLMClient


def main():
    parser = argparse.ArgumentParser(description="Codex Security Principles Staged Pipeline CLI (Research Prototype)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: run-staged-pipeline (4-Stage Execution: scan -> validate -> patch -> compare)
    pipeline_cmd = subparsers.add_parser("run-staged-pipeline", help="Run 4-stage pipeline (scan -> validate -> patch -> compare)")
    pipeline_cmd.add_argument("--repo-dir", required=True, help="Target repository directory path")
    pipeline_cmd.add_argument("--scans-dir", required=True, help="Scans directory path")
    pipeline_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    pipeline_cmd.add_argument("--mode", choices=["full", "diff"], default="full", help="Scan mode (full or diff)")
    pipeline_cmd.add_argument("--ci-mode", choices=["REPORT_ONLY", "SHADOW_GATING", "BLOCKING_GATE"], default="REPORT_ONLY", help="CI/CD Gate Mode")
    pipeline_cmd.add_argument("--storage-root", help="External storage root directory outside git worktree")

    # Subcommand: scan (Stage 1)
    scan_cmd = subparsers.add_parser("scan", help="Stage 1: SCAN SAST Findings & Logic Bug Candidates")
    scan_cmd.add_argument("--repo-dir", required=True, help="Target repository directory path")
    scan_cmd.add_argument("--scans-dir", required=True, help="Scans directory path")
    scan_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")

    # Subcommand: validate (Stage 2)
    val_cmd = subparsers.add_parser("validate", help="Stage 2: VALIDATE Findings & Evaluate Evidence")
    val_cmd.add_argument("--input", required=True, help="Input findings JSON file from scan stage")
    val_cmd.add_argument("--repo-dir", required=True, help="Target repository directory path")
    val_cmd.add_argument("--output", required=True, help="Output validated findings JSON file")

    # Subcommand: patch (Stage 3)
    patch_cmd = subparsers.add_parser("patch", help="Stage 3: PATCH Selected Validated Findings Only")
    patch_cmd.add_argument("--input", required=True, help="Input validated findings JSON file")
    patch_cmd.add_argument("--repo-dir", required=True, help="Target repository directory path")
    patch_cmd.add_argument("--output", required=True, help="Output remediation findings JSON file")
    patch_cmd.add_argument("--select-ids", nargs="*", help="Optional finding IDs to patch")

    # Subcommand: compare (Stage 4)
    cmp_cmd = subparsers.add_parser("compare", help="Stage 4: COMPARE Current Findings against Baseline")
    cmp_cmd.add_argument("--current", required=True, help="Current scan findings JSON file")
    cmp_cmd.add_argument("--baseline", required=True, help="Baseline scan findings JSON file")

    args = parser.parse_args()

    storage_mgr = ExternalStorageManager(storage_root=getattr(args, "storage_root", None))

    if args.command == "run-staged-pipeline":
        repo_dir = Path(args.repo_dir)
        scans_dir = Path(args.scans_dir)
        repo_name = args.repo_name
        run_id = f"run-{int(__import__('time').time())}"
        run_dir = storage_mgr.get_run_dir(repo_name, run_id)

        print(f"[*] Starting 4-Stage Pipeline Run: {run_id}")
        print(f"[*] Artifacts stored securely outside Git worktree at: {run_dir}")

        # Stage 1: SCAN
        print("[*] Stage 1/4: SCANNING (SAST Ingestion & Logic Bug Candidates)...")
        scanner = ScanStageRunner()
        findings, manifest, coverage = scanner.run_stage_scan(repo_dir, scans_dir, repo_name=repo_name)
        storage_mgr.save_scan_manifest(manifest, run_dir)
        storage_mgr.save_coverage_report(coverage, run_dir)
        storage_mgr.save_findings_json(findings, "stage1_scan_findings.json", run_dir)
        print(f"    [+] Ingested {len(findings)} findings/candidates. Complete scan: {coverage.is_complete_scan}")

        # Stage 2: VALIDATE
        print("[*] Stage 2/4: VALIDATING (LLM Context & Evidence Triage)...")
        validator = ValidateStageRunner()
        validated_findings = validator.run_stage_validate(findings, repo_dir)

        # Risk scoring
        scorer = RiskScorer()
        validated_findings = scorer.score_batch(validated_findings)
        storage_mgr.save_findings_json(validated_findings, "stage2_validated_findings.json", run_dir)

        # Stage 3: PATCH
        print("[*] Stage 3/4: PATCHING (Generating Remediation for Selected Validated Findings)...")
        patcher = PatchStageRunner()
        patched_findings = patcher.run_stage_patch(validated_findings, repo_dir)
        storage_mgr.save_findings_json(patched_findings, "stage3_patched_findings.json", run_dir)

        # Stage 4: COMPARE
        print("[*] Stage 4/4: COMPARING (Relationship-Aware Correlation)...")
        comparator = CompareStageRunner()
        correlated_findings, summary = comparator.run_stage_compare(patched_findings, [])
        storage_mgr.save_findings_json(correlated_findings, "stage4_correlated_findings.json", run_dir)

        # CI Gate Policy Evaluation
        ci_mode = CIMode(args.ci_mode)
        high_risk_count = sum(1 for f in correlated_findings if f.risk_score and f.risk_score >= 60.0 and f.verdict == TriageVerdict.TRUE_POSITIVE)
        
        print(f"\n[+] Correlation Summary: {summary}")
        print(f"[+] High/Critical Risk TP Count: {high_risk_count}")
        print(f"[+] CI Gate Mode: {ci_mode.value}")

        if ci_mode == CIMode.SHADOW_GATING:
            if high_risk_count > 0:
                print(f"[SHADOW GATE LOG] Build would have failed under BLOCKING_GATE mode ({high_risk_count} High Risk TPs).")
        elif ci_mode == CIMode.BLOCKING_GATE:
            if high_risk_count > 0:
                print(f"[BLOCKING GATE FAIL] Failing build due to {high_risk_count} High Risk TPs.")
                sys.exit(1)

        # Enforce exit code based on CoverageReport (0 = clean complete, 2 = incomplete scan)
        exit_code = coverage.suggested_exit_code
        print(f"[+] Pipeline completed. Exit Code: {exit_code}")
        sys.exit(exit_code)

    elif args.command == "scan":
        scanner = ScanStageRunner()
        findings, manifest, coverage = scanner.run_stage_scan(Path(args.repo_dir), Path(args.scans_dir), repo_name=args.repo_name)
        print(f"[OK] Stage 1 SCAN complete. Found {len(findings)} findings. Exit code: {coverage.suggested_exit_code}")
        sys.exit(coverage.suggested_exit_code)

    elif args.command == "validate":
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = [UnifiedFinding(**item) for item in data]
        validator = ValidateStageRunner()
        validated = validator.run_stage_validate(findings, Path(args.repo_dir))
        generate_json_report(validated, args.output)
        print(f"[OK] Stage 2 VALIDATE complete. Output saved to {args.output}")

    elif args.command == "patch":
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = [UnifiedFinding(**item) for item in data]
        patcher = PatchStageRunner()
        patched = patcher.run_stage_patch(findings, Path(args.repo_dir), selected_finding_ids=args.select_ids)
        generate_json_report(patched, args.output)
        print(f"[OK] Stage 3 PATCH complete. Output saved to {args.output}")

    elif args.command == "compare":
        with open(args.current, "r", encoding="utf-8") as f:
            cur_data = json.load(f)
        with open(args.baseline, "r", encoding="utf-8") as f:
            base_data = json.load(f)
        cur_findings = [UnifiedFinding(**item) for item in cur_data]
        base_findings = [UnifiedFinding(**item) for item in base_data]

        comparator = CompareStageRunner()
        correlated, summary = comparator.run_stage_compare(cur_findings, base_findings)
        print(f"[OK] Stage 4 COMPARE complete. Summary: {summary}")


if __name__ == "__main__":
    main()
