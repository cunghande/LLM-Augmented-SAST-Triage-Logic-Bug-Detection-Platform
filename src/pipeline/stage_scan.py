"""
Stage 1: SCAN Stage Module
==========================
Ingests SAST findings and extracts LOGIC_BUG_CANDIDATE items without treating them
as confirmed vulnerabilities. Constructs immutable ScanManifest and CoverageReport.
"""

import datetime
import hashlib
import subprocess
from pathlib import Path
from typing import List, Tuple, Dict, Any
from src.core.schema import (
    UnifiedFinding,
    ScanManifest,
    CoverageReport,
    ScannerType,
    BranchType,
)
from src.parsers.semgrep import parse_semgrep_json
from src.parsers.gitleaks import parse_gitleaks_json
from src.logic_bugs.detector import LogicBugDetector
from src.context.context_policy import GuardRequirementPolicy
from src.triage.llm_client import LLMClient


def get_git_commit_sha(repo_dir: Path) -> str:
    """Retrieve full 40-character commit SHA of target repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_dir), capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "0000000000000000000000000000000000000000"


class ScanStageRunner:
    """Stage 1: SCAN runner for SAST ingestion & logic bug candidate extraction."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()
        self.logic_detector = LogicBugDetector(self.llm_client)
        self.guard_policy = GuardRequirementPolicy()

    def run_stage_scan(self, repo_dir: Path, scan_dir: Path, repo_name: str = "CN_WEB") -> Tuple[List[UnifiedFinding], ScanManifest, CoverageReport]:
        """Execute Stage 1 SCAN."""
        commit_sha = get_git_commit_sha(repo_dir)
        timestamp_str = datetime.datetime.utcnow().isoformat() + "Z"
        manifest_id = f"MANIFEST-{repo_name}-{hashlib.md5((repo_name + commit_sha + timestamp_str).encode()).hexdigest()[:10].upper()}"

        manifest = ScanManifest(
            manifest_id=manifest_id,
            repository=repo_name,
            commit_sha=commit_sha,
            scanner_versions={"semgrep": "1.80.0", "gitleaks": "8.18.0"},
            model_version=self.llm_client.model,
            prompt_version="v2.0",
            policy_version="v1.0",
            timestamp_utc=timestamp_str
        )

        findings: List[UnifiedFinding] = []
        ast_failures: List[str] = []
        skipped_regions: List[str] = []

        # 1. Ingest Semgrep SAST findings
        semgrep_file = scan_dir / "semgrep.json"
        if semgrep_file.exists():
            findings.extend(parse_semgrep_json(semgrep_file, repository_name=repo_name))

        # 2. Ingest Gitleaks SAST findings
        gitleaks_file = scan_dir / "gitleaks.json"
        if gitleaks_file.exists():
            findings.extend(parse_gitleaks_json(gitleaks_file, repository_name=repo_name))

        # 3. Extract Logic-Bug Candidates (Branch B)
        try:
            logic_candidates = self.logic_detector.detect_bugs_in_repo(repo_dir, repo_name=repo_name)
            for lc in logic_candidates:
                # Add GuardRequirementPolicy evidence
                ev = self.guard_policy.get_guard_evidence_for_route(lc.file_path, lc.snippet)
                lc.guard_policy_evidence = ev
                findings.append(lc)
        except Exception as e:
            ast_failures.append(f"Logic bug AST analysis error: {str(e)}")

        # Attach ScanManifest to every finding
        for f in findings:
            f.scan_manifest = manifest

        # Compute coverage statistics
        all_code_files = list(repo_dir.glob("**/*.py")) + list(repo_dir.glob("**/*.js")) + list(repo_dir.glob("**/*.ts"))
        total_files = len(all_code_files)
        analyzed_files = len(set([f.file_path for f in findings if f.file_path]))

        is_complete = len(ast_failures) == 0
        suggested_exit = 0 if is_complete else 2

        coverage = CoverageReport(
            total_files=total_files,
            analyzed_files=analyzed_files,
            unsupported_files=[],
            ast_failures=ast_failures,
            unresolved_symbols=[],
            llm_failures=[],
            skipped_analysis_regions=skipped_regions,
            is_complete_scan=is_complete,
            suggested_exit_code=suggested_exit
        )

        return findings, manifest, coverage
