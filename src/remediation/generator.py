from typing import List
from src.core.schema import UnifiedFinding, RemediationPatch, TriageVerdict


class RemediationGenerator:
    """Generate Code Diff Patch and Fix Suggestions for True Positive Findings."""

    def generate_patch(self, finding: UnifiedFinding) -> RemediationPatch:
        rule_lower = finding.rule_id.lower()
        snippet = finding.snippet or ""

        # 1. Dockerfile Missing USER
        if "missing-user" in rule_lower:
            summary = "Add a non-root USER directive to prevent privileged container execution."
            diff = f"""--- a/{finding.file_path}
+++ b/{finding.file_path}
@@ -{finding.start_line},3 +{finding.start_line},5 @@
+# Create non-root app user and switch privileges
+RUN useradd -m -s /bin/bash appuser && chown -R appuser /app
+USER appuser
 {snippet}
"""
            test_note = "Verify container starts successfully as non-root user (docker run --rm <image> id)."

        # 2. Avoid Pickle Deserialization
        elif "pickle" in rule_lower:
            summary = "Replace unsafe `pickle.load()` with safe JSON or safetensors format."
            diff = f"""--- a/{finding.file_path}
+++ b/{finding.file_path}
@@ -{finding.start_line},1 +{finding.start_line},1 @@
- {snippet}
+ # Use json.load() or torch.load(..., weights_only=True) for safe deserialization
+ self.artifacts = json.load(file)
"""
            test_note = "Ensure model artifact loading tests pass with JSON or safetensors checkpoint files."

        # 3. Wildcard CORS Policy
        elif "cors" in rule_lower:
            summary = "Restrict wildcard CORS allow_origins=['*'] to allowed production domains."
            diff = f"""--- a/{finding.file_path}
+++ b/{finding.file_path}
@@ -{finding.start_line},1 +{finding.start_line},1 @@
- allow_origins=["*"]
+ allow_origins=settings.allowed_cors_origins  # e.g., ["https://mycompany.com"]
"""
            test_note = "Run API CORS verification tests to ensure unauthorized origins are rejected."

        # 4. Fallback Secret / Secret Leak
        elif "jwt" in rule_lower or "secret" in rule_lower:
            summary = "Fail closed if JWT_SECRET environment variable is absent in production."
            diff = f"""--- a/{finding.file_path}
+++ b/{finding.file_path}
@@ -{finding.start_line},1 +{finding.start_line},3 @@
- {snippet}
+ secret = process.env.JWT_SECRET;
+ if (!secret && process.env.NODE_ENV === 'production') {{
+   throw new Error('FATAL: JWT_SECRET environment variable is missing.');
+ }}
"""
            test_note = "Verify server fails to boot in production mode when JWT_SECRET is unset."

        # Generic Remediation
        else:
            summary = f"Remediate {finding.rule_id} vulnerability."
            diff = f"""--- a/{finding.file_path}
+++ b/{finding.file_path}
@@ -{finding.start_line},1 +{finding.start_line},1 @@
- {snippet}
+ // TODO: Apply secure sanitization / parameterized query for {finding.rule_id}
"""
            test_note = "Run regression unit tests."

        patch = RemediationPatch(
            fix_summary=summary,
            code_diff=diff,
            recommended_test=test_note
        )
        finding.remediation_patch = patch
        finding.remediation = {
            "summary": summary,
            "patch": diff,
            "recommended_test": test_note
        }
        return patch

    def generate_remediation_batch(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Generate patches for all True Positive findings."""
        for finding in findings:
            if finding.verdict == TriageVerdict.TRUE_POSITIVE:
                self.generate_patch(finding)
        return findings
