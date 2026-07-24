from pathlib import Path
from typing import List, Optional
from src.core.schema import (
    UnifiedFinding,
    TriageVerdict,
    ActionGroup,
    FindingStatus,
)
from src.context.extractor import extract_finding_context
from src.triage.prompts import SYSTEM_TRIAGE_PROMPT, build_finding_user_prompt
from src.triage.llm_client import LLMClient


class TriageEngine:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()

    def triage_finding(self, finding: UnifiedFinding, repo_dir: Path) -> UnifiedFinding:
        """Triage a single finding by extracting context and invoking LLM."""
        # Step 1: Extract code context
        extract_finding_context(finding, repo_dir)

        # Step 2: Build user prompt
        user_prompt = build_finding_user_prompt(finding)

        # Step 3: Query LLM
        res = self.llm_client.call_chat_completion(SYSTEM_TRIAGE_PROMPT, user_prompt)

        # Step 4: Parse verdict & confidence
        raw_verdict = res.get("verdict", "NEEDS_REVIEW")
        if raw_verdict == "TP":
            finding.verdict = TriageVerdict.TRUE_POSITIVE
        elif raw_verdict == "FP":
            finding.verdict = TriageVerdict.FALSE_POSITIVE
        else:
            finding.verdict = TriageVerdict.NEEDS_REVIEW

        finding.confidence = res.get("confidence", 0.5)
        finding.reasoning = res.get("reasoning", "")
        finding.evidence = res.get("evidence", [])
        finding.model_version = self.llm_client.model
        finding.prompt_version = "v1.0"

        # Step 5: Confidence Routing Policy
        conf = finding.confidence
        verdict = finding.verdict

        if conf >= 0.85 and verdict == TriageVerdict.FALSE_POSITIVE:
            finding.action_group = ActionGroup.AUTO_SUPPRESS_CANDIDATE
        elif conf >= 0.80 and verdict == TriageVerdict.TRUE_POSITIVE:
            finding.action_group = ActionGroup.HIGH_CONFIDENCE_TP
        else:
            finding.action_group = ActionGroup.MANUAL_REVIEW

        finding.status = FindingStatus.TRIAGED
        return finding

    def triage_batch(self, findings: List[UnifiedFinding], repo_dir: Path) -> List[UnifiedFinding]:
        """Triage a batch of findings."""
        triaged_findings = []
        for finding in findings:
            triaged = self.triage_finding(finding, repo_dir)
            triaged_findings.append(triaged)
        return triaged_findings
