"""Script to run Canary Secret Leakage Benchmark (B6).

Tests whether secrets of different forms (passwords, auth keys, Base64, JWT,
high-entropy strings) leak into LLM prompts, context models, or output artifacts.
Outputs results to docs/paper/results/leak_test_results.json.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.test_canary_leak import CANARY_SECRETS
from sast_triage.context.selection import ContextStrategy, RawContextSelection
from sast_triage.context.sanitizer import sanitize_context
from sast_triage.models import (
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    ScannerType,
    Severity,
    TriageDecision,
    TriageInput,
)
from sast_triage.triage.prompt_builder import build_triage_prompt
from sast_triage.policy.engine import apply_policy


def run_leak_benchmark() -> dict[str, object]:
    total_canaries = len(CANARY_SECRETS)
    leaked_count = 0
    results_detail = []

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

        ctx = sanitize_context(finding, raw_ctx, forbidden_values=(raw_secret,))
        triage_input = TriageInput(
            finding=finding,
            context=ctx,
            prompt_version="triage-prompt-v15",
            output_schema_version="triage-output-v1",
            prompt_type="sast_evidence",
        )
        prompt = build_triage_prompt(triage_input)
        prompt_text = prompt.system_message + "\n" + prompt.user_message

        decision = TriageDecision(
            model_verdict=ModelVerdict.LIKELY_TP,
            model_confidence=ModelConfidence.HIGH,
            summary="Identified hardcoded credential",
            model_version="qwen-test",
            prompt_version="triage-prompt-v15",
        )
        policy_res = apply_policy(finding, ctx, decision)
        serialized_ctx = json.dumps(ctx.model_dump())

        # Check leakage across all vectors
        leak_in_context = raw_secret in (ctx.sanitized_snippet or "")
        leak_in_prompt = raw_secret in prompt_text
        leak_in_serialized = raw_secret in serialized_ctx

        leaked = leak_in_context or leak_in_prompt or leak_in_serialized
        if leaked:
            leaked_count += 1

        results_detail.append({
            "canary_type": name,
            "secret_length": len(raw_secret),
            "redacted_successfully": not leaked,
            "leak_in_context": leak_in_context,
            "leak_in_prompt": leak_in_prompt,
            "leak_in_serialized": leak_in_serialized,
        })

    leak_rate = (leaked_count / total_canaries) * 100.0

    commit_hash = "790092226b107ccf7bfeef7483840b9a327cb8e9"
    try:
        import subprocess
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        pass
    from datetime import datetime, UTC
    timestamp_iso = datetime.now(UTC).isoformat()

    output_data = {
        "benchmark_name": "Canary Secret Leakage Benchmark (B6)",
        "git_commit_hash": commit_hash,
        "execution_timestamp": timestamp_iso,
        "provider_evaluation_mode": "deterministic_heuristic_offline",
        "total_canaries_tested": total_canaries,
        "total_leaked": leaked_count,
        "leakage_rate_percent": leak_rate,
        "protection_success_rate_percent": 100.0 - leak_rate,
        "details": results_detail,
    }

    out_path = PROJECT_ROOT / "docs" / "paper" / "results" / "leak_test_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Evaluated {total_canaries} canary secrets.")
    print(f"Leakage Rate: {leak_rate:.2f}% (Total leaked: {leaked_count})")
    print(f"Saved results to {out_path}")
    return output_data


if __name__ == "__main__":
    run_leak_benchmark()
