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
from src.reporters.reporter import generate_json_report, generate_markdown_report, evaluate_triage_performance, generate_priority_report
from src.logic_bugs.detector import LogicBugDetector
from src.logic_bugs.ast_graph import extract_code_graph
from src.logic_bugs.neo4j_exporter import Neo4jExporter
from src.risk.scorer import RiskScorer
from src.remediation.generator import RemediationGenerator
from src.pipeline.parallel_pipeline import ParallelAnalysisPipeline


def load_scans_from_dir(scans_dir: Path, repo_name: str = "CN_WEB") -> List[UnifiedFinding]:
    """Discover and parse all scan files under scans_dir."""
    findings: List[UnifiedFinding] = []

    gitleaks_files = list(scans_dir.glob("**/*gitleaks*.json")) + list(scans_dir.glob("**/gitleaks.json"))
    for gf in set(gitleaks_files):
        print(f"[+] Parsing Gitleaks report: {gf}")
        findings.extend(parse_gitleaks_json(gf, repo_name))

    semgrep_sarif_files = list(scans_dir.glob("**/*.sarif"))
    for sf in set(semgrep_sarif_files):
        print(f"[+] Parsing Semgrep SARIF report: {sf}")
        findings.extend(parse_semgrep_sarif(sf, repo_name))

    semgrep_json_files = list(scans_dir.glob("**/*semgrep*.json"))
    for sj in set(semgrep_json_files):
        if "unified" in sj.name:
            continue
        print(f"[+] Parsing Semgrep JSON report: {sj}")
        findings.extend(parse_semgrep_json(sj, repo_name))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Modular LLM-augmented SAST and Logic-Bug Analysis Pipeline CLI (Research Prototype)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: run-pipeline (Parallel Two-Branch Architecture)
    pipeline_cmd = subparsers.add_parser("run-pipeline", help="Run parallel dual-branch analysis pipeline (Branch A + Branch B)")
    pipeline_cmd.add_argument("--repo-dir", required=True, help="Target repository directory path")
    pipeline_cmd.add_argument("--scans-dir", required=True, help="Scans directory path")
    pipeline_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    pipeline_cmd.add_argument("--output-dir", default="reports/CN_WEB", help="Output report directory")

    # Subcommand: parse
    parse_cmd = subparsers.add_parser("parse", help="Parse scanner output into unified finding schema")
    parse_cmd.add_argument("--scanner", choices=["gitleaks", "semgrep-json", "semgrep-sarif"], required=True)
    parse_cmd.add_argument("--input", required=True, help="Input scan file path")
    parse_cmd.add_argument("--output", required=False, help="Output unified JSON file path")
    parse_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")

    # Subcommand: triage
    triage_cmd = subparsers.add_parser("triage", help="Run Branch A automated LLM triage on SAST findings")
    triage_cmd.add_argument("--scans-dir", required=True, help="Directory containing raw scan files")
    triage_cmd.add_argument("--repo-dir", required=True, help="Path to target repository code")
    triage_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    triage_cmd.add_argument("--output", default="reports/CN_WEB/triage_result.json", help="Output JSON report path")

    # Subcommand: detect-logic-bugs
    lb_cmd = subparsers.add_parser("detect-logic-bugs", help="Run Branch B logic-bug candidate detection")
    lb_cmd.add_argument("--repo-dir", required=True, help="Path to target repository code")
    lb_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    lb_cmd.add_argument("--output", default="reports/CN_WEB/logic_bugs.json", help="Output logic bugs JSON path")

    # Subcommand: score-risk
    risk_cmd = subparsers.add_parser("score-risk", help="Calculate rubric risk scores (0-100)")
    risk_cmd.add_argument("--input", required=True, help="Input findings JSON file")
    risk_cmd.add_argument("--output", default="reports/CN_WEB/risk_report.json", help="Output risk scored JSON path")

    # Subcommand: generate-remediation
    patch_cmd = subparsers.add_parser("generate-remediation", help="Generate PATCH_CANDIDATE proposals")
    patch_cmd.add_argument("--input", required=True, help="Input triaged findings JSON file")
    patch_cmd.add_argument("--output", default="reports/CN_WEB/remediation_report.json", help="Output remediation JSON path")

    # Subcommand: priority-report
    priority_cmd = subparsers.add_parser("priority-report", help="Generate priority ranked security report")
    priority_cmd.add_argument("--input", required=True, help="Input risk-scored findings JSON file")
    priority_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    priority_cmd.add_argument("--output", default="reports/CN_WEB/priority_report.md", help="Output priority Markdown report path")

    # Subcommand: export-neo4j
    neo_cmd = subparsers.add_parser("export-neo4j", help="Export Lightweight Security Context Graph to Neo4j Database")
    neo_cmd.add_argument("--repo-dir", default="repos/CN_WEB", help="Repository directory path")
    neo_cmd.add_argument("--repo-name", default="CN_WEB", help="Repository name")
    neo_cmd.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j bolt URI")
    neo_cmd.add_argument("--user", default="neo4j", help="Neo4j username")
    neo_cmd.add_argument("--password", default="password123", help="Neo4j password")

    args = parser.parse_args()

    if args.command == "run-pipeline":
        pipeline = ParallelAnalysisPipeline()
        merged = pipeline.execute_pipeline(Path(args.repo_dir), Path(args.scans_dir), repo_name=args.repo_name)
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        generate_json_report(merged, out_dir / "triage_result.json")
        generate_priority_report(merged, out_dir / "priority_report.md", repo_name=args.repo_name)
        print(f"[OK] Pipeline execution finished! Results saved to {out_dir}")

    elif args.command == "parse":
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

    elif args.command == "triage":
        scans_dir = Path(args.scans_dir)
        repo_dir = Path(args.repo_dir)
        findings = load_scans_from_dir(scans_dir, args.repo_name)
        if not findings:
            print("[!] No findings found to triage.")
            sys.exit(0)

        client = LLMClient()
        engine = TriageEngine(llm_client=client)
        triaged = engine.triage_batch(findings, repo_dir)
        scorer = RiskScorer()
        triaged = scorer.score_batch(triaged)
        remediation_gen = RemediationGenerator()
        triaged = remediation_gen.generate_remediation_batch(triaged)

        json_out = generate_json_report(triaged, args.output)
        md_out = generate_markdown_report(triaged, Path(args.output).with_suffix(".md"))
        print(f"[OK] Triage complete! Output: {json_out}")

    elif args.command == "detect-logic-bugs":
        repo_dir = Path(args.repo_dir)
        client = LLMClient()
        detector = LogicBugDetector(llm_client=client)
        logic_findings = detector.detect_bugs_in_repo(repo_dir, args.repo_name)
        out_file = generate_json_report(logic_findings, args.output)
        print(f"[OK] Found {len(logic_findings)} logic flaw candidates. Output: {out_file}")

    elif args.command == "score-risk":
        in_path = Path(args.input)
        with open(in_path, "r", encoding="utf-8") as f:
            findings_data = json.load(f)
        findings = [UnifiedFinding(**item) for item in findings_data]
        scorer = RiskScorer()
        scored = scorer.score_batch(findings)
        out_file = generate_json_report(scored, args.output)
        print(f"[OK] Risk scoring complete! Saved to {out_file}")

    elif args.command == "generate-remediation":
        in_path = Path(args.input)
        with open(in_path, "r", encoding="utf-8") as f:
            findings_data = json.load(f)
        findings = [UnifiedFinding(**item) for item in findings_data]
        gen = RemediationGenerator()
        remediated = gen.generate_remediation_batch(findings)
        out_file = generate_json_report(remediated, args.output)
        print(f"[OK] Remediation patch generation complete! Saved to {out_file}")

    elif args.command == "priority-report":
        in_path = Path(args.input)
        with open(in_path, "r", encoding="utf-8") as f:
            findings_data = json.load(f)
        findings = [UnifiedFinding(**item) for item in findings_data]
        scorer = RiskScorer()
        findings = scorer.score_batch(findings)
        gen = RemediationGenerator()
        findings = gen.generate_remediation_batch(findings)
        out_file = generate_priority_report(findings, args.output, repo_name=args.repo_name)
        print(f"[OK] Priority Report generated! Saved to {out_file}")

    elif args.command == "export-neo4j":
        repo_dir = Path(args.repo_dir)
        traces = extract_code_graph(repo_dir)
        exporter = Neo4jExporter(uri=args.uri, user=args.user, password=args.password)
        exporter.export_traces(traces, repo_name=args.repo_name)
        exporter.close()


if __name__ == "__main__":
    main()
