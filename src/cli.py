import sys
import json
import argparse
from pathlib import Path
from typing import List

from src.core.schema import UnifiedFinding
from src.parsers.gitleaks import parse_gitleaks_json
from src.parsers.semgrep import parse_semgrep_sarif, parse_semgrep_json
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient
from src.reporters.reporter import generate_json_report, generate_markdown_report, evaluate_triage_performance


def load_scans_from_dir(scans_dir: Path, repo_name: str = "CN_WEB") -> List[UnifiedFinding]:
    """Discover and parse all scan files under scans_dir."""
    findings: List[UnifiedFinding] = []

    # Look for Gitleaks JSON
    gitleaks_files = list(scans_dir.glob("**/*gitleaks*.json")) + list(scans_dir.glob("**/gitleaks.json"))
    for gf in set(gitleaks_files):
        print(f"[+] Parsing Gitleaks report: {gf}")
        findings.extend(parse_gitleaks_json(gf, repo_name))

    # Look for Semgrep JSON / SARIF
    semgrep_sarif_files = list(scans_dir.glob("**/*.sarif"))
    for sf in set(semgrep_sarif_files):
        print(f"[+] Parsing Semgrep SARIF report: {sf}")
        findings.extend(parse_semgrep_sarif(sf, repo_name))

    semgrep_json_files = list(scans_dir.glob("**/*semgrep*.json"))
    for sj in set(semgrep_json_files):
        # Ignore already unified output files
        if "unified" in sj.name:
            continue
        print(f"[+] Parsing Semgrep JSON report: {sj}")
        findings.extend(parse_semgrep_json(sj, repo_name))

    return findings


def main():
    parser = argparse.ArgumentParser(description="LLM-Augmented SAST Triage Platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: parse
    parse_cmd = subparsers.add_parser("parse", help="Parse scanner output into unified finding schema")
    parse_cmd.add_argument("--scanner", choices=["gitleaks", "semgrep-json", "semgrep-sarif"], required=True)
    parse_cmd.add_argument("--input", required=True, help="Input scan file path")
    parse_cmd.add_argument("--output", required=False, help="Output unified JSON file path")
    parse_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")

    # Subcommand: triage
    triage_cmd = subparsers.add_parser("triage", help="Run automated LLM triage on scan findings")
    triage_cmd.add_argument("--scans-dir", required=True, help="Directory containing raw scan files")
    triage_cmd.add_argument("--repo-dir", required=True, help="Path to target repository code")
    triage_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    triage_cmd.add_argument("--output", default="reports/CN_WEB/triage_result.json", help="Output JSON report path")
    triage_cmd.add_argument("--api-base", help="Local LLM API Base (e.g. http://localhost:11434/v1)")
    triage_cmd.add_argument("--model", help="LLM Model name (e.g. qwen3:8b)")

    # Subcommand: evaluate
    eval_cmd = subparsers.add_parser("evaluate", help="Evaluate triage performance against ground truth benchmark")
    eval_cmd.add_argument("--triage-result", required=True, help="Triaged findings JSON file")
    eval_cmd.add_argument("--benchmark", required=True, help="Ground truth benchmark JSON file")

    args = parser.parse_args()

    if args.command == "parse":
        input_path = Path(args.input)
        if args.scanner == "gitleaks":
            findings = parse_gitleaks_json(input_path, args.repo_name)
        elif args.scanner == "semgrep-json":
            findings = parse_semgrep_json(input_path, args.repo_name)
        elif args.scanner == "semgrep-sarif":
            findings = parse_semgrep_sarif(input_path, args.repo_name)
        else:
            findings = []

        print(f"[OK] Successfully parsed {len(findings)} findings.")
        if args.output:
            out_file = generate_json_report(findings, args.output)
            print(f"[OK] Saved unified findings to {out_file}")
        else:
            print(json.dumps([f.model_dump() for f in findings], indent=2))

    elif args.command == "triage":
        scans_dir = Path(args.scans_dir)
        repo_dir = Path(args.repo_dir)

        print(f"[*] Discovering findings under {scans_dir}...")
        findings = load_scans_from_dir(scans_dir, args.repo_name)
        print(f"[+] Total raw findings discovered: {len(findings)}")

        if not findings:
            print("[!] No findings found to triage.")
            sys.exit(0)

        # Initialize LLM Client and Triage Engine
        client = LLMClient(api_base=args.api_base, model=args.model)
        print(f"[*] Initialized LLM Client -> Endpoint: {client.api_base} | Model: {client.model}")

        engine = TriageEngine(llm_client=client)
        print("[*] Running LLM triage pipeline...")
        triaged = engine.triage_batch(findings, repo_dir)

        json_out = generate_json_report(triaged, args.output)
        md_out = generate_markdown_report(triaged, Path(args.output).with_suffix(".md"))

        print(f"[OK] Triage complete!")
        print(f"     - JSON Report: {json_out}")
        print(f"     - Markdown Report: {md_out}")

    elif args.command == "evaluate":
        triage_path = Path(args.triage_result)
        benchmark_path = Path(args.benchmark)

        with open(triage_path, "r", encoding="utf-8") as f:
            triage_data = json.load(f)
        triaged_findings = [UnifiedFinding(**item) for item in triage_data]

        with open(benchmark_path, "r", encoding="utf-8") as f:
            bm_data = json.load(f)

        ground_truth_map = {}
        for item in bm_data:
            ground_truth_map[item["finding_id"]] = item["ground_truth_verdict"]
            if "rule_id" in item:
                ground_truth_map[item["rule_id"]] = item["ground_truth_verdict"]

        metrics = evaluate_triage_performance(triaged_findings, ground_truth_map)
        print("\n" + "="*50)
        print("         TRIAGE EVALUATION METRICS SUMMARY       ")
        print("="*50)
        for key, val in metrics.items():
            print(f"  {key:25s}: {val}")
        print("="*50 + "\n")


if __name__ == "__main__":
    main()
