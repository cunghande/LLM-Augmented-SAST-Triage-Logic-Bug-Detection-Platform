"""Fail-closed validation for structured triage provider output."""

import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sast_triage.errors import SastTriageError
from sast_triage.models import TriageDecision

_MAX_TEXT_LENGTH = 4_000
_MAX_LIST_ITEMS = 20
_FORBIDDEN_KEYS = frozenset(
    {
        "policy_action",
        "policy_decision",
        "snippet",
        "raw_source",
        "source_snippet",
        "provider_response",
        "traceback",
    }
)


def _walk_forbidden(node: Any, forbidden_values: tuple[str, ...]) -> None:
    """Reject forbidden keys or values without including payload in errors."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            if str(key) in _FORBIDDEN_KEYS:
                raise SastTriageError(
                    safe_message="Structured provider output contains a forbidden field.",
                    error_code="TRIAGE_OUTPUT_FORBIDDEN_FIELD",
                    retryable=False,
                )
            _walk_forbidden(value, forbidden_values)
    elif isinstance(node, list):
        for item in node:
            _walk_forbidden(item, forbidden_values)
    elif isinstance(node, str) and any(value in node for value in forbidden_values):
        raise SastTriageError(
            safe_message="Structured provider output contains a forbidden value.",
            error_code="TRIAGE_OUTPUT_FORBIDDEN_VALUE",
            retryable=False,
        )


def _validate_sizes(node: Any) -> None:
    """Reject oversized structured output fields."""
    if isinstance(node, str) and len(node) > _MAX_TEXT_LENGTH:
        raise SastTriageError(
            safe_message="Structured provider output contains an oversized text field.",
            error_code="TRIAGE_OUTPUT_TOO_LARGE",
            retryable=False,
        )
    if isinstance(node, list):
        if len(node) > _MAX_LIST_ITEMS:
            raise SastTriageError(
                safe_message="Structured provider output contains too many list items.",
                error_code="TRIAGE_OUTPUT_TOO_LARGE",
                retryable=False,
            )
        for item in node:
            _validate_sizes(item)
    elif isinstance(node, Mapping):
        for value in node.values():
            _validate_sizes(value)


def parse_triage_decision(
    response: str | bytes | bytearray | Mapping[str, Any],
    *,
    prompt_version: str,
    forbidden_values: tuple[str, ...] = (),
) -> TriageDecision:
    """Parse and validate a provider response into a TriageDecision.

    Only a JSON object matching the domain model is accepted.  No policy action
    is accepted and no provider response text is copied into an error message.
    """
    if isinstance(response, (str, bytes, bytearray)):
        try:
            decoded = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise SastTriageError(
                safe_message="Structured provider output is not valid JSON.",
                error_code="TRIAGE_OUTPUT_INVALID_JSON",
                retryable=False,
            ) from None
    elif isinstance(response, Mapping):
        decoded = dict(response)
    else:
        raise SastTriageError(
            safe_message="Structured provider output has an unsupported type.",
            error_code="TRIAGE_OUTPUT_INVALID_TYPE",
            retryable=False,
        )

    if not isinstance(decoded, dict):
        raise SastTriageError(
            safe_message="Structured provider output must be a JSON object.",
            error_code="TRIAGE_OUTPUT_INVALID_ROOT",
            retryable=False,
        )
    _walk_forbidden(decoded, forbidden_values)
    _validate_sizes(decoded)
    try:
        decision = TriageDecision.model_validate(decoded)
    except ValidationError:
        raise SastTriageError(
            safe_message="Structured provider output failed schema validation.",
            error_code="TRIAGE_OUTPUT_SCHEMA_INVALID",
            retryable=False,
        ) from None
    if decision.prompt_version != prompt_version:
        raise SastTriageError(
            safe_message="Structured provider output prompt version mismatch.",
            error_code="TRIAGE_OUTPUT_VERSION_MISMATCH",
            retryable=False,
        )
    return decision
