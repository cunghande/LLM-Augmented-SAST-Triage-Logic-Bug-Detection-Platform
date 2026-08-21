"""Internal rule-semantics helpers shared by analysis, evidence, and policy."""

from __future__ import annotations

from enum import Enum

from sast_triage.models import NormalizedFinding


class RuleMechanism(str, Enum):
    """Security mechanism required to validate one scanner finding."""

    TAINT_FLOW = "taint_flow"
    INTRINSIC_USAGE = "intrinsic_usage"
    CONFIGURATION = "configuration"
    RULE_SPECIFIC = "rule_specific"


_CONFIGURATION_TOKENS = (
    "secure-cookie",
    "secure-set-cookie",
    "cookie-secure",
    "csrf",
    "debug-mode",
)
_INTRINSIC_TOKENS = (
    "insecure-hash",
    "weak-random",
)
_TAINT_TOKENS = (
    "command",
    "deserial",
    "injection",
    "path-travers",
    "pickle",
    "raw-html",
    "render-template-string",
    "sql",
    "ssrf",
    "template-unescaped",
    "urllib",
    "xpath",
    "xss",
    "xxe",
)


def mechanism_for_rule_id(rule_id: str) -> RuleMechanism:
    """Classify a rule identifier without trusting severity or repository text."""
    rule = rule_id.lower()
    if any(token in rule for token in _CONFIGURATION_TOKENS):
        return RuleMechanism.CONFIGURATION
    if any(token in rule for token in _INTRINSIC_TOKENS):
        return RuleMechanism.INTRINSIC_USAGE
    if any(token in rule for token in _TAINT_TOKENS):
        return RuleMechanism.TAINT_FLOW
    return RuleMechanism.RULE_SPECIFIC


def rule_mechanism(finding: NormalizedFinding) -> RuleMechanism:
    """Classify a finding without trusting scanner severity or repository text."""
    return mechanism_for_rule_id(finding.rule_id)


def requires_dataflow(finding: NormalizedFinding) -> bool:
    """Return whether validation requires an attacker-controlled source-to-sink path."""
    return rule_mechanism(finding) == RuleMechanism.TAINT_FLOW


def sink_only_evidence_is_sufficient(finding: NormalizedFinding) -> bool:
    """Return whether observing the matched operation can complete static evidence."""
    return rule_mechanism(finding) in {
        RuleMechanism.CONFIGURATION,
        RuleMechanism.INTRINSIC_USAGE,
    }
