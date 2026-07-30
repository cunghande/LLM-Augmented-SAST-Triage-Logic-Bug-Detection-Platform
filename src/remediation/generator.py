"""
Remediation Patch Candidate Generator Module
=============================================
Generates PATCH_CANDIDATE proposals attached to commit_sha for True Positive findings.
Validates syntax and diff format. Falls back to GUIDANCE_ONLY or INSUFFICIENT_CONTEXT.
Patches are NEVER auto-applied or auto-merged.
"""

from typing import Optional, List, Any
from src.core.schema import (
    UnifiedFinding,
    RemediationPatch,
    PatchStatus,
    TriageVerdict,
    ContextQuality,
)
from src.triage.llm_client import LLMClient


class RemediationGenerator:
    """Generates remediation proposals and PATCH_CANDIDATE items."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

    def validate_patch_syntax(self, code_diff: str) -> bool:
        """Basic syntax & diff format validation."""
        if not code_diff or "--- a/" not in code_diff or "+++ b/" not in code_diff:
            return False
        return True

    def generate_remediation(self, finding: UnifiedFinding, repo_dir: Optional[Any] = None) -> RemediationPatch:
        """Generate remediation proposal for a finding."""
        rule_lower = finding.rule_id.lower()
        snippet = finding.snippet or ""
        commit_sha = finding.commit_sha or "HEAD"

        # Handle low context quality
        if finding.context and finding.context.context_quality == ContextQuality.FALLBACK:
            patch = RemediationPatch(
                status=PatchStatus.INSUFFICIENT_CONTEXT,
                commit_sha=commit_sha,
                fix_summary=f"Insufficient context to generate executable diff patch for {finding.rule_id}. Human review required.",
                code_diff="",
                recommended_test="Perform manual AppSec code review."
            )
            finding.remediation_patch = patch
            finding.remediation = {"summary": patch.fix_summary, "patch": "", "status": patch.status.value}
            return patch

        # Deterministic / Template Patch Generation
        if "missing-user" in rule_lower:
            summary = "Add a non-root USER directive to prevent privileged container execution."
            diff = f"--- a/{finding.file_path}\n+++ b/{finding.file_path}\n@@ -{finding.start_line},3 +{finding.start_line},5 @@\n+# Create non-root app user\n+RUN useradd -m -s /bin/bash appuser && chown -R appuser /app\n+USER appuser\n {snippet}\n"
            test_note = "Verify container starts successfully as non-root user (docker run --rm <image> id)."
            status = PatchStatus.PATCH_CANDIDATE

        elif "pickle" in rule_lower:
            summary = "Replace unsafe `pickle.load()` with safe JSON or safetensors format."
            diff = f"--- a/{finding.file_path}\n+++ b/{finding.file_path}\n@@ -{finding.start_line},1 +{finding.start_line},1 @@\n- {snippet}\n+ self.artifacts = json.load(file)\n"
            test_note = "Ensure model artifact loading tests pass with JSON format."
            status = PatchStatus.PATCH_CANDIDATE

        elif "cors" in rule_lower:
            summary = "Restrict wildcard CORS allow_origins=['*'] to allowed production domains."
            diff = f"--- a/{finding.file_path}\n+++ b/{finding.file_path}\n@@ -{finding.start_line},1 +{finding.start_line},1 @@\n- allow_origins=[\"*\"]\n+ allow_origins=settings.allowed_cors_origins\n"
            test_note = "Run API CORS verification tests."
            status = PatchStatus.PATCH_CANDIDATE

        elif "jwt" in rule_lower or "secret" in rule_lower:
            summary = "Fail closed if JWT_SECRET environment variable is absent in production."
            diff = f"--- a/{finding.file_path}\n+++ b/{finding.file_path}\n@@ -{finding.start_line},1 +{finding.start_line},3 @@\n- {snippet}\n+ secret = process.env.JWT_SECRET;\n+ if (!secret && process.env.NODE_ENV === 'production') {{\n+   throw new Error('FATAL: JWT_SECRET environment variable missing.');\n+ }}\n"
            test_note = "Verify server fails to boot in production mode when JWT_SECRET is unset."
            status = PatchStatus.PATCH_CANDIDATE

        else:
            summary = f"Guidance for remediating {finding.rule_id} vulnerability."
            diff = ""
            test_note = "Run regression unit tests."
            status = PatchStatus.GUIDANCE_ONLY

        is_valid = self.validate_patch_syntax(diff) if diff else False
        if status == PatchStatus.PATCH_CANDIDATE and not is_valid:
            status = PatchStatus.FAILED_VALIDATION

        patch = RemediationPatch(
            status=status,
            commit_sha=commit_sha,
            fix_summary=summary,
            code_diff=diff,
            recommended_test=test_note,
            validation_checks={
                "syntax_valid": is_valid,
                "apply_valid": False,  # Must be tested in CI/CD sandbox
                "unit_test_passed": False,
                "security_regression_passed": False
            }
        )

        finding.remediation_patch = patch
        finding.remediation = {
            "status": patch.status.value,
            "summary": summary,
            "patch": diff,
            "recommended_test": test_note
        }
        return patch

    def generate_patch(self, finding: UnifiedFinding) -> RemediationPatch:
        """Alias for generate_remediation."""
        return self.generate_remediation(finding)

    def generate_remediation_batch(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Generate patches for all True Positive findings."""
        for finding in findings:
            if finding.verdict == TriageVerdict.TRUE_POSITIVE:
                self.generate_remediation(finding)
        return findings
