"""
Parallel Pipeline & Finding Merger Module
==========================================
Executes Branch A (SAST Triage) and Branch B (Logic-Bug Analysis) in parallel,
merges findings, runs Risk Scoring and Remediation, with fail-safe error preservation.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from src.core.schema import UnifiedFinding, TriageVerdict, ActionGroup, FindingStatus
from src.parsers.semgrep import parse_semgrep_json
from src.parsers.gitleaks import parse_gitleaks_json
from src.triage.engine import TriageEngine
from src.logic_bugs.detector import LogicBugDetector
from src.risk.scorer import RiskScorer
from src.remediation.generator import RemediationGenerator
from src.triage.llm_client import LLMClient


class ParallelAnalysisPipeline:
    """
    Modular parallel analysis pipeline orchestrating:
    - Branch A: SAST Triage (Semgrep / Gitleaks -> UnifiedFinding -> Triage Engine)
    - Branch B: Logic-Bug Analysis (Direct Repository Analysis -> LogicBugDetector)
    - Finding Merger: Deduplication & Unification
    - Post-Merger Processing: Risk Scoring & Patch Remediation Candidates
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()
        self.triage_engine = TriageEngine(self.llm_client)
        self.logic_detector = LogicBugDetector(self.llm_client)
        self.risk_scorer = RiskScorer()
        self.remediation_generator = RemediationGenerator(self.llm_client)

    def run_sast_triage_branch(self, repo_dir: Path, scan_dir: Path, repo_name: str) -> List[UnifiedFinding]:
        """Branch A: Load SAST scans (Semgrep & Gitleaks), extract context, and triage."""
        findings: List[UnifiedFinding] = []
        try:
            semgrep_file = scan_dir / "semgrep.json"
            if semgrep_file.exists():
                findings.extend(parse_semgrep_json(semgrep_file, repository_name=repo_name))

            gitleaks_file = scan_dir / "gitleaks.json"
            if gitleaks_file.exists():
                findings.extend(parse_gitleaks_json(gitleaks_file, repository_name=repo_name))

            triaged = self.triage_engine.triage_batch(findings, repo_dir)
            return triaged
        except Exception as e:
            print(f"[!] Warning: Branch A failed safely ({e})")
            for f in findings:
                f.verdict = TriageVerdict.NEEDS_REVIEW
                f.action_group = ActionGroup.MANUAL_REVIEW
                f.processing_error = f"Branch A error: {str(e)}"
            return findings

    def run_logic_bug_branch(self, repo_dir: Path, repo_name: str) -> List[UnifiedFinding]:
        """Branch B: Direct repository analysis to discover LOGIC_BUG_CANDIDATE findings."""
        try:
            return self.logic_detector.detect_bugs_in_repo(repo_dir, repo_name)
        except Exception as e:
            print(f"[!] Warning: Branch B failed safely ({e})")
            return []

    def merge_findings(self, branch_a_findings: List[UnifiedFinding], branch_b_findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Merge finding streams and deduplicate by stable fingerprint."""
        seen_fingerprints = set()
        merged: List[UnifiedFinding] = []

        for finding in branch_a_findings + branch_b_findings:
            fp = finding.compute_fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                merged.append(finding)

        return merged

    def execute_pipeline(self, repo_dir: Path, scan_dir: Path, repo_name: str = "CN_WEB") -> List[UnifiedFinding]:
        """Execute end-to-end parallel pipeline."""
        print(f"[*] Executing Branch A (SAST Triage Branch) for {repo_name}...")
        branch_a_findings = self.run_sast_triage_branch(repo_dir, scan_dir, repo_name)

        print(f"[*] Executing Branch B (Logic-Bug Analysis Branch) for {repo_name}...")
        branch_b_findings = self.run_logic_bug_branch(repo_dir, repo_name)

        print(f"[*] Merging findings (Branch A: {len(branch_a_findings)}, Branch B: {len(branch_b_findings)})...")
        merged_findings = self.merge_findings(branch_a_findings, branch_b_findings)

        print(f"[*] Running Risk Scoring Engine & Patch Candidate Generation on {len(merged_findings)} findings...")
        for finding in merged_findings:
            try:
                self.risk_scorer.score_finding(finding)
                if finding.verdict == TriageVerdict.TRUE_POSITIVE:
                    self.remediation_generator.generate_remediation(finding, repo_dir)
            except Exception as e:
                print(f"[!] Warning: Risk scoring / remediation error on {finding.finding_id}: {e}")

        return merged_findings
