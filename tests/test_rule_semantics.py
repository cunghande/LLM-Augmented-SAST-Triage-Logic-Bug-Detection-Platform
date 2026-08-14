"""Tests for the exact internal rule-semantics allowlist."""

from sast_triage.rule_semantics import RuleSemantics, classify_rule_semantics
from sast_triage.triage.system_prompt import build_system_message


def test_known_semgrep_hash_rule_is_usage_based() -> None:
    """A pinned Semgrep SHA1 rule is classified by exact ID."""
    semantics = classify_rule_semantics(
        "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1"
    )

    assert semantics == RuleSemantics.USAGE_BASED


def test_similar_unknown_hash_rule_requires_security_context() -> None:
    """A similar name does not inherit usage-based behavior."""
    semantics = classify_rule_semantics("custom.insecure-hash-experiment")

    assert semantics == RuleSemantics.SECURITY_CONTEXT_REQUIRED


def test_unrelated_rule_is_not_intrinsic() -> None:
    """An unrelated source-to-sink rule remains outside intrinsic semantics."""
    assert classify_rule_semantics("python.sql-injection") == RuleSemantics.NOT_INTRINSIC


def test_v11_prompt_explains_usage_based_evidence_without_v10_contradiction() -> None:
    """Prompt v11 distinguishes usage-based and security-context rules."""
    prompt = build_system_message("model", "triage-prompt-v11")

    assert "STRICT EVIDENCE CALIBRATION (v11)" in prompt
    assert "For USAGE_BASED rules" in prompt
    assert "without attacker input or proof of a security purpose" in prompt
