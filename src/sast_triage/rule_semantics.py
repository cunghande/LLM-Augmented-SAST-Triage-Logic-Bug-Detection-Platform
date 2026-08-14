"""Internal rule-semantics registry used by evidence and policy gates."""

from enum import Enum


class RuleSemantics(str, Enum):
    """Describe what evidence is required to satisfy a scanner rule."""

    USAGE_BASED = "USAGE_BASED"
    SECURITY_CONTEXT_REQUIRED = "SECURITY_CONTEXT_REQUIRED"
    NOT_INTRINSIC = "NOT_INTRINSIC"


_USAGE_BASED_RULE_IDS = frozenset(
    {
        "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5",
        "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1",
        "python.lang.security.insecure-hash-function.insecure-hash-function",
    }
)


def classify_rule_semantics(rule_id: str) -> RuleSemantics:
    """Classify an exact rule ID without relying on fuzzy policy matching."""
    normalized = rule_id.strip().lower()
    if normalized in _USAGE_BASED_RULE_IDS:
        return RuleSemantics.USAGE_BASED
    if any(token in normalized for token in ("insecure-hash", "weak-random", "secure-cookie")):
        return RuleSemantics.SECURITY_CONTEXT_REQUIRED
    return RuleSemantics.NOT_INTRINSIC
