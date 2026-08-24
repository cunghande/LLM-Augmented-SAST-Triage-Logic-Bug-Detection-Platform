"""Safe deterministic estimates for provider token and cost telemetry."""

from __future__ import annotations

import math

from sast_triage.models import TriageDecision, TriageInput
from sast_triage.triage.prompt_builder import build_triage_prompt

TOKEN_COUNT_METHOD = "utf8-bytes-div-4-v1"
COST_MODEL_VERSION = "provider-wall-time-v1"


def estimate_text_tokens(text: str) -> int:
    """Return a documented approximation without loading a model tokenizer."""
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 4))


def estimate_input_tokens(triage_input: TriageInput, model_version: str) -> int:
    """Estimate tokens in the exact safe system/user prompt envelope."""
    prompt = build_triage_prompt(triage_input, model_version=model_version)
    return estimate_text_tokens(prompt.system_message) + estimate_text_tokens(
        prompt.user_message
    )


def estimate_output_tokens(decision: TriageDecision | None) -> int | None:
    """Estimate tokens in the validated decision, never a raw provider response."""
    if decision is None:
        return None
    return estimate_text_tokens(decision.model_dump_json())


def estimate_provider_cost(
    provider_duration_ms: int,
    hourly_rate_usd: float | None,
    *,
    cache_hit: bool,
) -> float | None:
    """Estimate provider cost from measured wall time and a caller-supplied rate."""
    if hourly_rate_usd is None:
        return None
    if cache_hit:
        return 0.0
    return round(provider_duration_ms * hourly_rate_usd / 3_600_000, 8)
