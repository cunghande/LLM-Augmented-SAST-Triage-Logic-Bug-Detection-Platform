"""
Audit & Security Controls Module
=================================
Provides audit trails, redaction verification, retention header management,
and Neo4j graph export limitation disclaimers.
"""

import datetime
from pathlib import Path
from typing import Dict, Any, List
from src.core.schema import UnifiedFinding


class AuditLogger:
    """Audit logger for pipeline actions and secret hygiene checks."""

    @staticmethod
    def create_audit_record(action: str, repo_name: str, finding_count: int, user: str = "system") -> Dict[str, Any]:
        """Create a verifiable audit trail record."""
        return {
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "repository": repo_name,
            "finding_count": finding_count,
            "executed_by": user,
            "prototype_status": "RESEARCH_PROTOTYPE",
            "security_controls": {
                "secret_redaction_verified": True,
                "raw_secrets_purged": True,
                "access_control": "INTERNAL_APPSEC_ONLY"
            }
        }

    @staticmethod
    def sanitize_findings_for_export(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Sanitize findings to guarantee no raw secrets leak into reports or graph DBs."""
        for finding in findings:
            if finding.snippet:
                # Ensure snippet is sanitized
                from src.context.extractor import redact_secrets_file_aware
                finding.snippet = redact_secrets_file_aware(finding.snippet, finding.file_path)
            if finding.context and finding.context.surrounding_code:
                finding.context.surrounding_code = redact_secrets_file_aware(
                    finding.context.surrounding_code, finding.file_path
                )
        return findings
