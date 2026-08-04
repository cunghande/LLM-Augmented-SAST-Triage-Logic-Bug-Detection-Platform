"""Tests for exact secret redaction primitive."""

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.redaction import (
    REDACTED_SECRET_PLACEHOLDER,
    redact_exact_secret,
)

CANARY = "CANARY_SUPER_SECRET_DO_NOT_LEAK"


# --- Basic replacement ---


def test_single_occurrence_redacted() -> None:
    text = f"AWS_KEY={CANARY}"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 1
    assert CANARY not in result.redacted_text
    assert REDACTED_SECRET_PLACEHOLDER in result.redacted_text
    assert result.redacted_text == f"AWS_KEY={REDACTED_SECRET_PLACEHOLDER}"


def test_multiple_occurrences_redacted() -> None:
    text = f"key1={CANARY} key2={CANARY} key3={CANARY}"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 3
    assert CANARY not in result.redacted_text
    assert result.redacted_text.count(REDACTED_SECRET_PLACEHOLDER) == 3


def test_no_match_returns_zero_replacements() -> None:
    text = "safe_text_without_any_secret"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 0
    assert result.redacted_text == text


# --- Edge cases ---


def test_multiline_redaction() -> None:
    text = f"line1\npassword={CANARY}\nline3\ntoken={CANARY}\n"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 2
    assert CANARY not in result.redacted_text
    assert result.redacted_text.count(REDACTED_SECRET_PLACEHOLDER) == 2


def test_unicode_surrounding_text() -> None:
    text = f"密码={CANARY} 令牌={CANARY}"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 2
    assert CANARY not in result.redacted_text
    assert "密码=" in result.redacted_text
    assert "令牌=" in result.redacted_text


def test_text_already_contains_placeholder_no_raw_secret() -> None:
    text = f"key={REDACTED_SECRET_PLACEHOLDER}"
    result = redact_exact_secret(text, CANARY)
    assert result.replacements == 0
    assert result.redacted_text == text
    assert REDACTED_SECRET_PLACEHOLDER in result.redacted_text


def test_double_call_idempotent() -> None:
    text = f"token={CANARY}"
    first = redact_exact_secret(text, CANARY)
    assert first.replacements == 1
    assert CANARY not in first.redacted_text

    second = redact_exact_secret(first.redacted_text, CANARY)
    assert second.replacements == 0
    assert second.redacted_text == first.redacted_text
    assert second.redacted_text.count(REDACTED_SECRET_PLACEHOLDER) == 1


# --- Rejection of invalid secret ---


def test_empty_secret_rejected() -> None:
    with pytest.raises(SastTriageError, match="non-empty"):
        redact_exact_secret("some text", "")


def test_whitespace_only_secret_rejected() -> None:
    with pytest.raises(SastTriageError, match="non-empty"):
        redact_exact_secret("some text", "   \t\n  ")


# --- Security guarantees ---


def test_repr_does_not_contain_canary_after_redaction() -> None:
    text = f"secret={CANARY}"
    result = redact_exact_secret(text, CANARY)
    result_repr = repr(result)
    assert CANARY not in result_repr


def test_result_is_frozen() -> None:
    result = redact_exact_secret("x", CANARY)
    with pytest.raises(AttributeError):
        result.redacted_text = "mutated"  # type: ignore[misc]


def test_original_text_not_mutated() -> None:
    text = f"key={CANARY}"
    original = text  # same reference
    redact_exact_secret(text, CANARY)
    assert text == original  # Python strings are immutable, but verify contract
