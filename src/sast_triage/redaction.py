"""Exact secret redaction primitive for SAST Triage Platform.

This module provides a pure-function helper that replaces all exact
occurrences of a known secret value in a text string with a safe
placeholder.  It does NOT discover secrets — the caller must supply the
exact secret to redact.

Security constraints:
- Never logs the input text or secret.
- Never hashes, stores, or creates telemetry from the raw secret.
- Never mutates input strings.
- Exception messages never contain the input text or secret value.
"""

from dataclasses import dataclass

from sast_triage.errors import SastTriageError

REDACTED_SECRET_PLACEHOLDER: str = "<REDACTED_SECRET>"
"""Placeholder that replaces raw secret values in all public models."""


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Immutable result of an exact-secret redaction operation.

    Attributes:
        redacted_text: The text after all occurrences of the secret have
            been replaced with the placeholder.
        replacements: The number of replacements performed (0 when the
            secret was not found in the text).
    """

    redacted_text: str
    replacements: int


def redact_exact_secret(text: str, secret: str) -> RedactionResult:
    """Replace all exact occurrences of *secret* in *text* with the
    redaction placeholder.

    This is a **pure function**: it does not mutate its arguments, does
    not log, and does not create any side-channel output from the raw
    secret value.

    Args:
        text: The source text that may contain the secret.
        secret: The exact secret value to redact.  Must be a non-empty,
            non-whitespace-only string.

    Returns:
        A frozen ``RedactionResult`` with the sanitized text and the
        count of replacements performed.

    Raises:
        SastTriageError: If *secret* is empty or contains only
            whitespace.  The exception message never includes the
            input text or the secret value.
    """
    if not isinstance(secret, str) or not secret.strip():
        raise SastTriageError(
            safe_message="Secret value for redaction must be a non-empty, non-whitespace string.",
            error_code="REDACTION_EMPTY_SECRET",
        )

    count = text.count(secret)
    if count == 0:
        return RedactionResult(redacted_text=text, replacements=0)

    redacted = text.replace(secret, REDACTED_SECRET_PLACEHOLDER)
    return RedactionResult(redacted_text=redacted, replacements=count)
