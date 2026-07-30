"""
SAST Triage Engine Module (Branch A Engine)
===========================================
Performs SAST finding evaluation using LLM evaluation calls, multi-tier context,
decision metadata tracking, evidence references, and fail-safe handling.
"""

import hashlib
from pathlib import Path
from typing import List, Optional
from src.core.schema import (
    UnifiedFinding,
    TriageVerdict,
    ActionGroup,
    FindingStatus,
    EvidenceReference,
    DecisionMetadata,
)
from src.context.extractor import extract_finding_context
from src.triage.prompts import SYSTEM_TRIAGE_PROMPT, PROMPT_VERSION, build_finding_user_prompt
from src.triage.llm_client import LLMClient


class TriageEngine:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()

    def triage_finding(self, finding: UnifiedFinding, repo_dir: Path) -> UnifiedFinding:
        """Triage a single SAST finding by extracting context and querying LLM."""
        try:
            # Step 1: Extract multi-tier context
            extract_finding_context(finding, repo_dir)

            # Step 2: Build user prompt
            user_prompt = build_finding_user_prompt(finding)
            context_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()[:12]

            # Step 3: Query LLM
            res = self.llm_client.call_chat_completion(SYSTEM_TRIAGE_PROMPT, user_prompt)

            # Step 4: Parse verdict & decision score
            raw_verdict = res.get("verdict", "NEEDS_REVIEW").upper()
            if raw_verdict == "TP":
                finding.verdict = TriageVerdict.TRUE_POSITIVE
            elif raw_verdict == "FP":
                finding.verdict = TriageVerdict.FALSE_POSITIVE
            elif raw_verdict == "NEEDS_MORE_CONTEXT":
                finding.verdict = TriageVerdict.NEEDS_MORE_CONTEXT
            else:
                finding.verdict = TriageVerdict.NEEDS_REVIEW

            decision_score = float(res.get("decision_score", res.get("confidence", 0.5)))
            finding.confidence = decision_score
            finding.reasoning = res.get("reasoning", "LLM evaluation complete.")
            finding.evidence = res.get("evidence", [])

            # Parse structured evidence reference
            ev_dict = res.get("evidence_ref", {})
            if isinstance(ev_dict, dict) and ev_dict.get("file_path"):
                finding.evidence_ref = EvidenceReference(
                    file_path=ev_dict.get("file_path", finding.file_path),
                    line_number=int(ev_dict.get("line_number", finding.start_line)),
                    symbol=ev_dict.get("symbol"),
                    source=ev_dict.get("source"),
                    sink=ev_dict.get("sink"),
                    guard=ev_dict.get("guard"),
                )
            else:
                finding.evidence_ref = EvidenceReference(
                    file_path=finding.file_path,
                    line_number=finding.start_line,
                    symbol=finding.context.enclosing_function if finding.context else None,
                    guard="UNKNOWN"
                )

            finding.decision_metadata = DecisionMetadata(
                decision_score=decision_score,
                model_version=self.llm_client.model,
                prompt_version=PROMPT_VERSION,
                context_hash=context_hash,
                policy_version="v1.0"
            )

            # Step 5: Routing policy
            if decision_score >= 0.85 and finding.verdict == TriageVerdict.FALSE_POSITIVE:
                finding.action_group = ActionGroup.AUTO_SUPPRESS_CANDIDATE
            elif decision_score >= 0.80 and finding.verdict == TriageVerdict.TRUE_POSITIVE:
                finding.action_group = ActionGroup.HIGH_CONFIDENCE_TP
            else:
                finding.action_group = ActionGroup.MANUAL_REVIEW

            finding.status = FindingStatus.TRIAGED
            return finding

        except Exception as e:
            # Fail-safe principle: Error preserves original finding for manual review
            finding.verdict = TriageVerdict.NEEDS_REVIEW
            finding.action_group = ActionGroup.MANUAL_REVIEW
            finding.processing_error = f"Triage engine error: {str(e)}"
            finding.status = FindingStatus.NEW
            return finding

    def triage_batch(self, findings: List[UnifiedFinding], repo_dir: Path) -> List[UnifiedFinding]:
        """Triage a batch of findings safely."""
        triaged_findings = []
        for finding in findings:
            triaged = self.triage_finding(finding, repo_dir)
            triaged_findings.append(triaged)
        return triaged_findings
