"""Offline tests for the real provider boundary."""

import json

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
    TriageInput,
)
from sast_triage.triage.real_provider import RealTriageProvider


def _input() -> TriageInput:
    finding = NormalizedFinding(
        finding_instance_id="f-1", scanner=ScannerType.SEMGREP, finding_type=FindingType.SAST,
        rule_id="r", file_path="app.py", start_line=1, severity=Severity.LOW,
        message="message",
    )
    context = SanitizedContext(
        finding_id="f-1", sanitized_snippet="safe", context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1, context_end_line=1, finding_start_line=1,
        path_category=PathCategory.UNKNOWN, source_kind=SourceKind.WORKTREE, context_available=True,
    )
    return TriageInput(
        finding=finding, context=context, prompt_version="p1",
        output_schema_version="s1", prompt_type="real",
    )


def _response() -> bytes:
    decision = {
        "model_verdict": "LIKELY_TP", "model_confidence": "HIGH", "summary": "summary",
        "evidence": ["evidence"], "missing_information": [], "assumptions": [],
        "model_version": "model", "prompt_version": "p1",
    }
    return json.dumps({"choices": [{"message": {"content": json.dumps(decision)}}]}).encode()


def test_real_provider_uses_injected_transport_and_validates_output() -> None:
    calls: list[tuple[str, dict[str, object], dict[str, str], float]] = []

    def transport(url: str, payload: dict[str, object], headers: dict[str, str], timeout: float) -> bytes:
        calls.append((url, payload, headers, timeout))
        return _response()

    provider = RealTriageProvider(
        api_key="secret-key", base_url="https://llm.example", model="model",
        reasoning_effort="none", transport=transport,
    )
    decision = provider.triage(_input())
    assert decision.model_verdict.value == "LIKELY_TP"
    assert "RAW_PROVIDER_SNIPPET" not in json.dumps(calls[0][1])
    assert calls[0][2]["Authorization"] == "Bearer secret-key"
    assert calls[0][1]["reasoning_effort"] == "none"


def test_real_provider_configuration_and_response_fail_safe() -> None:
    with pytest.raises(SastTriageError) as exc_info:
        RealTriageProvider(api_key="", base_url="https://x", model="m")
    assert exc_info.value.error_code == "TRIAGE_CONFIGURATION_ERROR"

    provider = RealTriageProvider(
        api_key="key", base_url="https://x", model="m", transport=lambda *_: b"bad",
    )
    with pytest.raises(SastTriageError) as response_error:
        provider.triage(_input())
    assert response_error.value.error_code == "TRIAGE_PROVIDER_RESPONSE_INVALID"

    with pytest.raises(SastTriageError) as reasoning_error:
        RealTriageProvider(api_key="key", base_url="https://x", model="m", reasoning_effort="invalid")
    assert reasoning_error.value.error_code == "TRIAGE_CONFIGURATION_ERROR"
