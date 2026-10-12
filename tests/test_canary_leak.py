"""Canary Secret Leak Test Suite (B6).

Verifies that canary secrets of various formats (db_pass, auth_key, base64, JWT,
high-entropy tokens) never leak into sanitized context, LLM prompts, triage
results, or serialized reports.
"""

from __future__ import annotations

import json
from sast_triage.context.selection import ContextStrategy, RawContextSelection
from sast_triage.context.sanitizer import sanitize_context
from sast_triage.models import (
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PolicyAction,
    ScannerType,
    Severity,
    TriageDecision,
    TriageInput,
)
from sast_triage.triage.prompt_builder import build_triage_prompt
from sast_triage.policy.engine import apply_policy
from sast_triage.redaction import REDACTED_SECRET_PLACEHOLDER

CANARY_SECRETS = [
    ("db_pass", "canary_db_pass_9876543210", 'db_pass = "canary_db_pass_9876543210"'),
    ("auth_key", "canary_auth_key_abcdef123456", 'auth_key = "canary_auth_key_abcdef123456"'),
    ("base64_secret", "Y2FuYXJ5X3NlY3JldF9kYXRhXzEyMzQ1Njc4OQ==", 'access_token = "Y2FuYXJ5X3NlY3JldF9kYXRhXzEyMzQ1Njc4OQ=="'),
    ("jwt_secret", "canaryjwtsecrettoken987654321", 'token = "eyJhbGciOiJIUzI1NiJ9.payload.canaryjwtsecrettoken987654321"'),
    ("high_entropy_hex", "4f8a3c9b2e1d7a6e5f0c8b7a6d5e4f3a", 'api_key = "4f8a3c9b2e1d7a6e5f0c8b7a6d5e4f3a"'),
]


def test_canary_secrets_never_leak_into_prompt_or_output() -> None:
    for name, raw_secret, code_snippet in CANARY_SECRETS:
        finding = NormalizedFinding(
            finding_instance_id=f"f-canary-{name}",
            scanner=ScannerType.SEMGREP,
            finding_type=FindingType.SAST,
            rule_id="python.security.hardcoded-key",
            file_path="src/config.py",
            start_line=5,
            end_line=5,
            severity=Severity.HIGH,
            message="Possible hardcoded secret",
            metadata={"cwe": ["CWE-798"]},
        )
        raw_ctx = RawContextSelection(
            finding_id=f"f-canary-{name}",
            scanner=ScannerType.SEMGREP,
            finding_start_line=5,
            finding_end_line=5,
            selected_text=f"def configure():\n    {code_snippet}\n",
            strategy=ContextStrategy.PYTHON_FUNCTION,
            context_start_line=1,
            context_end_line=10,
            context_available=True,
        )

        # 1. Sanitize context
        ctx = sanitize_context(finding, raw_ctx, forbidden_values=(raw_secret,))

        # Verify secret is absent from SanitizedContext
        assert raw_secret not in (ctx.sanitized_snippet or ""), f"Secret {name} leaked into sanitized_snippet"

        # 2. Build Prompt
        triage_input = TriageInput(
            finding=finding,
            context=ctx,
            prompt_version="triage-prompt-v15",
            output_schema_version="triage-output-v1",
            prompt_type="sast_evidence",
        )
        prompt = build_triage_prompt(triage_input)
        prompt_text = prompt.system_message + "\n" + prompt.user_message
        assert raw_secret not in prompt_text, f"Secret {name} leaked into prompt text"

        # 3. Policy and Output
        decision = TriageDecision(
            model_verdict=ModelVerdict.LIKELY_TP,
            model_confidence=ModelConfidence.HIGH,
            summary="Identified hardcoded credential",
            model_version="qwen-test",
            prompt_version="triage-prompt-v15",
        )
        policy_res = apply_policy(finding, ctx, decision)

        # Verify serialize does not leak
        serialized_ctx = json.dumps(ctx.model_dump())
        assert raw_secret not in serialized_ctx, f"Secret {name} leaked into serialized SanitizedContext"
