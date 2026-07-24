from src.core.schema import UnifiedFinding


SYSTEM_TRIAGE_PROMPT = """You are an expert Application Security (AppSec) Code Reviewer and SAST Triage Specialist.
Your task is to analyze static analysis security findings (from tools like Semgrep or Gitleaks) alongside source code context, and classify each finding accurately.

### Verdict Options:
- "TP" (True Positive): Real security vulnerability, secret leak, or security risk that requires developer action or code fix.
- "FP" (False Positive): Noise, test file, example credential, non-reachable pattern, mock secret, or safe code construct misflagged by the scanner.
- "NEEDS_REVIEW": Ambiguous finding where context is insufficient or requires security reviewer inspection.

### Rules for Triage:
1. Evaluate code context carefully. Check if credentials are mock/test tokens, or if fallbacks allow unsafe execution in production.
2. Secrets in test files, `.example` files, or mock test fixtures are usually False Positives (FP) unless they pose real risk.
3. Fallback secrets (e.g. `JWT_SECRET || 'dev_secret'`) in production code are True Positives (TP) because they lead to insecure defaults in production.
4. Output MUST be strictly valid JSON with no markdown wrapping or extra text outside JSON.

### Output JSON Schema:
{
  "verdict": "TP" | "FP" | "NEEDS_REVIEW",
  "confidence": 0.0 - 1.0,
  "reasoning": "Short 1-3 sentence explanation of the classification decision.",
  "evidence": [
    "Specific line or code evidence supporting verdict"
  ]
}
"""


def build_finding_user_prompt(finding: UnifiedFinding) -> str:
    """Build user prompt for a specific finding."""
    context_str = ""
    if finding.context:
        if finding.context.enclosing_function:
            context_str += f"Enclosing Function/Scope: {finding.context.enclosing_function}\n"
        if finding.context.surrounding_code:
            context_str += f"Code Snippet Window ({finding.context.line_window}):\n```\n{finding.context.surrounding_code}\n```\n"

    metadata_str = ""
    if finding.metadata:
        metadata_str = f"Scanner Metadata: {finding.metadata}\n"

    user_prompt = f"""Target Repository: {finding.repository}
File: {finding.file_path} (Lines {finding.start_line}-{finding.end_line})
Scanner: {finding.scanner.value}
Rule ID: {finding.rule_id}
Severity: {finding.severity.value}

Raw Match/Snippet:
```
{finding.snippet}
```

{context_str}{metadata_str}
Analyze this finding and output the classification JSON.
"""
    return user_prompt
