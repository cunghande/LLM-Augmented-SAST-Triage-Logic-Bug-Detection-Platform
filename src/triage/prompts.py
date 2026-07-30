"""
Triage Prompt Library
=====================
System and user prompts for SAST finding triage. Supports versioning, structured evidence,
and context-aware abstention (NEEDS_MORE_CONTEXT).
"""

from src.core.schema import UnifiedFinding


PROMPT_VERSION = "v2.0"

SYSTEM_TRIAGE_PROMPT = """You are an expert Application Security (AppSec) Code Reviewer and SAST Triage Specialist.
Your task is to analyze static analysis security findings (Semgrep/Gitleaks) alongside source code context and classify each finding accurately.

### Verdict Options:
- "TP" (True Positive): Real security vulnerability, secret leak, or security risk requiring developer action.
- "FP" (False Positive): Noise, test file, example credential, non-reachable pattern, mock secret, or safe code construct misflagged by scanner.
- "NEEDS_REVIEW": Ambiguous finding where context is insufficient or requires manual security reviewer inspection.
- "NEEDS_MORE_CONTEXT": Context is incomplete, missing AST definitions, or truncated, preventing a definitive verdict without hallucination.

### Rules for Triage:
1. Evaluate code context carefully. Check if credentials are mock/test tokens, or if fallbacks allow unsafe execution in production.
2. Secrets in test files, `.example` files, or mock test fixtures are False Positives (FP) unless they pose real risk.
3. Fallback secrets (e.g. `JWT_SECRET || 'dev_secret'`) in production code are True Positives (TP) because they lead to insecure defaults in production.
4. DO NOT GUESS OR HALLUCINATE. If context is missing, return "NEEDS_MORE_CONTEXT" or "NEEDS_REVIEW".
5. Output MUST be strictly valid JSON with no markdown wrapping.

### Output JSON Schema:
{
  "verdict": "TP" | "FP" | "NEEDS_REVIEW" | "NEEDS_MORE_CONTEXT",
  "decision_score": 0.0 - 1.0,
  "reasoning": "Short 1-3 sentence explanation of the classification decision.",
  "evidence": [
    "Specific line or code evidence supporting verdict"
  ],
  "evidence_ref": {
    "file_path": "path/to/file",
    "line_number": 123,
    "symbol": "function_or_symbol_name",
    "source": "source_or_input",
    "sink": "sink_or_operation",
    "guard": "guard_name_or_NONE"
  }
}
"""


def build_finding_user_prompt(finding: UnifiedFinding) -> str:
    """Build user prompt for a specific finding."""
    context_str = ""
    if finding.context:
        context_str += f"Context Quality: {finding.context.context_quality.value}\n"
        if finding.context.enclosing_function:
            context_str += f"Enclosing Function: {finding.context.enclosing_function}\n"
        if finding.context.enclosing_class:
            context_str += f"Enclosing Class: {finding.context.enclosing_class}\n"
        if finding.context.surrounding_code:
            context_str += f"Code Snippet Window ({finding.context.line_window}):\n```\n{finding.context.surrounding_code}\n```\n"

    metadata_str = ""
    if finding.metadata:
        metadata_str = f"Scanner Metadata: {finding.metadata}\n"

    secret_tax_str = f"Secret Taxonomy: {finding.secret_taxonomy.value}\n" if finding.secret_taxonomy else ""

    user_prompt = f"""Target Repository: {finding.repository}
File: {finding.file_path} (Lines {finding.start_line}-{finding.end_line})
Scanner: {finding.scanner.value}
Branch: {finding.branch_type.value}
Rule ID: {finding.rule_id}
Severity: {finding.severity.value}
{secret_tax_str}

Raw Match/Snippet:
```
{finding.snippet}
```

{context_str}{metadata_str}
Analyze this finding and output the classification JSON.
"""
    return user_prompt
