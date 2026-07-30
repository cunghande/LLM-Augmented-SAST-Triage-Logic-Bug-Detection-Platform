"""
Logic-Bug Detector Engine (Branch B)
=====================================
Analyzes repository code directly to construct LightweightSecurityContextGraphs
and emit LOGIC_BUG_CANDIDATE findings.
"""

import hashlib
from pathlib import Path
from typing import List, Optional
from src.core.schema import (
    UnifiedFinding,
    ScannerType,
    BranchType,
    Severity,
    TriageVerdict,
    ActionGroup,
    FindingStatus,
    LightweightSecurityContextGraph,
    FindingContext,
    EvidenceReference,
)
from src.logic_bugs.ast_graph import extract_code_graph, TracePath
from src.logic_bugs.analyzer import discover_high_risk_routes
from src.logic_bugs.prompts import LOGIC_BUG_SYSTEM_PROMPT, build_logic_bug_user_prompt
from src.triage.llm_client import LLMClient


class LogicBugDetector:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()

    def detect_bugs_in_repo(self, repo_dir: Path, repo_name: str = "CN_WEB") -> List[UnifiedFinding]:
        """Discover logic bug candidates in a repository (Branch B)."""
        candidates = discover_high_risk_routes(repo_dir)
        findings: List[UnifiedFinding] = []

        for idx, trace in enumerate(candidates):
            guard_names = [g.name for g in trace.guards]
            user_prompt = build_logic_bug_user_prompt(
                entrypoint=trace.entrypoint.name,
                file_path=trace.sensitive_sink.file_path,
                line_number=trace.sensitive_sink.line_number,
                guards=guard_names,
                sink=trace.sensitive_sink.name,
                code_snippet=trace.sensitive_sink.code_snippet
            )

            res = self.llm_client.call_chat_completion(LOGIC_BUG_SYSTEM_PROMPT, user_prompt)

            if res.get("has_logic_bug", False) or res.get("verdict") == "TP":
                bug_type = res.get("bug_type", "LOGIC_FLAW")
                conf = float(res.get("confidence", 0.85))
                reasoning = res.get("reasoning", "Potential logic flaw candidate detected in data flow.")
                evidence = res.get("evidence_trace", res.get("evidence", []))

                raw_id = f"LOGIC-BUG-{repo_name}-{bug_type}-{trace.sensitive_sink.file_path}-{trace.sensitive_sink.line_number}-{idx}"
                finding_id = f"LB-{hashlib.md5(raw_id.encode('utf-8')).hexdigest()[:10].upper()}"

                finding = UnifiedFinding(
                    finding_id=finding_id,
                    scanner=ScannerType.LOGIC_BUG,
                    branch_type=BranchType.LOGIC_BUG_BRANCH,
                    rule_id=f"logic-bug.{bug_type.lower()}",
                    repository=repo_name,
                    commit_sha="HEAD",
                    file_path=trace.sensitive_sink.file_path,
                    start_line=trace.sensitive_sink.line_number,
                    end_line=trace.sensitive_sink.line_number,
                    snippet=trace.sensitive_sink.code_snippet,
                    severity=Severity.HIGH,
                    metadata={
                        "bug_type": bug_type,
                        "entrypoint": trace.entrypoint.name,
                        "has_auth_guard": trace.has_auth_guard,
                        "candidate_status": "LOGIC_BUG_CANDIDATE",
                        "rule_family": "logic-bug-detection"
                    },
                    context=FindingContext(
                        enclosing_function=trace.entrypoint.name,
                        line_window=f"L{trace.sensitive_sink.line_number}",
                        surrounding_code=trace.sensitive_sink.code_snippet,
                        redacted=True
                    ),
                    verdict=TriageVerdict.TRUE_POSITIVE,
                    confidence=conf,
                    reasoning=reasoning,
                    evidence=evidence,
                    evidence_ref=EvidenceReference(
                        file_path=trace.sensitive_sink.file_path,
                        line_number=trace.sensitive_sink.line_number,
                        symbol=trace.sensitive_sink.name,
                        source=trace.entrypoint.name,
                        sink=trace.sensitive_sink.name,
                        guard=", ".join(guard_names) if guard_names else "NONE",
                        code_path=[trace.entrypoint.name, trace.sensitive_sink.name]
                    ),
                    action_group=ActionGroup.HIGH_CONFIDENCE_TP if conf >= 0.80 else ActionGroup.MANUAL_REVIEW,
                    security_context_graph=LightweightSecurityContextGraph(
                        bug_type=bug_type,
                        entrypoint=trace.entrypoint.name,
                        guards=guard_names,
                        guard_categories=trace.guard_categories,
                        sensitive_sink=trace.sensitive_sink.name,
                        has_auth_guard=trace.has_auth_guard,
                        trace_path=[trace.entrypoint.name, trace.sensitive_sink.name]
                    ),
                    status=FindingStatus.NEW
                )
                finding.compute_fingerprint()
                findings.append(finding)

        return findings
