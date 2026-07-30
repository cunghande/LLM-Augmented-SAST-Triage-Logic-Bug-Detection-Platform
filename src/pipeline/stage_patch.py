"""
Stage 3: PATCH Stage Module
===========================
Generates PATCH_CANDIDATE proposals strictly for selected, validated findings.
Unvalidated candidates or False Positives are explicitly excluded from patch generation.
"""

from pathlib import Path
from typing import List, Optional
from src.core.schema import UnifiedFinding, TriageVerdict, ActionGroup
from src.remediation.generator import RemediationGenerator
from src.triage.llm_client import LLMClient


class PatchStageRunner:
    """Stage 3: PATCH runner for generating remediation patches on validated findings."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.remediation_generator = RemediationGenerator(self.llm_client)

    def run_stage_patch(self, validated_findings: List[UnifiedFinding], repo_dir: Path, selected_finding_ids: Optional[List[str]] = None) -> List[UnifiedFinding]:
        """
        Execute Stage 3 PATCH.
        Patches are generated ONLY for:
        1. Selected finding IDs (if provided explicitly)
        2. Validated True Positives (TP) with HIGH_CONFIDENCE_TP action group
        """
        for finding in validated_findings:
            should_patch = False
            if selected_finding_ids:
                if finding.finding_id in selected_finding_ids:
                    should_patch = True
            else:
                if finding.verdict == TriageVerdict.TRUE_POSITIVE and finding.action_group == ActionGroup.HIGH_CONFIDENCE_TP:
                    should_patch = True

            if should_patch:
                self.remediation_generator.generate_remediation(finding, repo_dir)

        return validated_findings
