"""
Stage 2: VALIDATE Stage Module
==============================
Performs LLM triage, evidence validation, and context policy checks.
Classifies candidate findings into validated TP, FP, NEEDS_REVIEW, or NEEDS_MORE_CONTEXT.
Candidates are strictly NOT treated as confirmed vulnerabilities until validated.
"""

from pathlib import Path
from typing import List, Optional
from src.core.schema import UnifiedFinding, TriageVerdict, ActionGroup
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient


class ValidateStageRunner:
    """Stage 2: VALIDATE runner for LLM context triage & evidence validation."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()
        self.triage_engine = TriageEngine(self.llm_client)

    def run_stage_validate(self, findings: List[UnifiedFinding], repo_dir: Path) -> List[UnifiedFinding]:
        """Execute Stage 2 VALIDATE."""
        validated_findings = []
        for finding in findings:
            # If finding is already triaged by LogicBugDetector or previous run, validate evidence
            if not finding.verdict:
                triaged = self.triage_engine.triage_finding(finding, repo_dir)
                validated_findings.append(triaged)
            else:
                # Enforce evidence check: missing evidence forces NEEDS_MORE_CONTEXT or NEEDS_REVIEW
                if not finding.evidence and not finding.evidence_ref:
                    finding.verdict = TriageVerdict.NEEDS_MORE_CONTEXT
                    finding.action_group = ActionGroup.MANUAL_REVIEW
                validated_findings.append(finding)

        return validated_findings
