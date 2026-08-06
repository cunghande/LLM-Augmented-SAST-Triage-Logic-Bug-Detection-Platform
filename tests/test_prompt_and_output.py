"""Tests for provider-safe prompt construction and output validation."""

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
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt


def _input() -> TriageInput:
    finding = NormalizedFinding(
        finding_instance_id="f-1",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="rule-1",
        file_path="app/main.py",
        start_line=2,
        end_line=2,
        severity=Severity.HIGH,
        message="check this",
        snippet="RAW_SNIPPET_MUST_NOT_BE_IN_PROMPT",
        metadata={"category": "security"},
    )
    context = SanitizedContext(
        finding_id="f-1",
        sanitized_snippet="SAFE_CONTEXT",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=3,
        finding_start_line=2,
        finding_end_line=2,
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )
    return TriageInput(
        finding=finding,
        context=context,
        prompt_version="prompt-v1",
        output_schema_version="decision-v1",
        prompt_type="real.default",
    )


def _decision(prompt_version: str = "prompt-v1") -> dict[str, object]:
    return {
        "model_verdict": "LIKELY_TP",
        "model_confidence": "HIGH",
        "summary": "short summary",
        "evidence": ["evidence"],
        "missing_information": [],
        "assumptions": [],
        "model_version": "model-v1",
        "prompt_version": prompt_version,
    }


def test_prompt_builder_uses_sanitized_context_and_excludes_finding_snippet() -> None:
    prompt = build_triage_prompt(_input())
    assert "SAFE_CONTEXT" in prompt.user_message
    assert "RAW_SNIPPET_MUST_NOT_BE_IN_PROMPT" not in prompt.user_message
    assert "không tin cậy" in prompt.system_message
    assert "summary" in prompt.system_message
    assert "evidence" in prompt.system_message
    assert "missing_information" in prompt.system_message
    assert "model_verdict" in prompt.system_message
    assert "verdict/confidence" in prompt.system_message
    assert "<think>" in prompt.system_message


def test_prompt_builder_requires_detailed_reviewer_reason_and_model_identity() -> None:
    prompt = build_triage_prompt(_input(), model_version="qwen3:8b")
    assert "qwen3:8b" in prompt.system_message
    assert "cơ chế/rủi ro" in prompt.system_message
    assert "bằng chứng cụ thể" in prompt.system_message
    assert "Không được đoán" in prompt.system_message
    assert "đúng vulnerability mechanism" in prompt.system_message
    assert "source-to-sink" in prompt.system_message
    assert "append" in prompt.system_message
    assert "XPath query" in prompt.system_message
    assert "<ANALYSIS_TARGET>" in prompt.user_message


def test_prompt_builder_is_deterministic() -> None:
    first = build_triage_prompt(_input())
    second = build_triage_prompt(_input())
    assert first == second


def test_output_validator_accepts_valid_json_and_rejects_policy_injection() -> None:
    decision = parse_triage_decision(json.dumps(_decision()), prompt_version="prompt-v1")
    assert decision.model_verdict.value == "LIKELY_TP"
    with pytest.raises(SastTriageError) as exc_info:
        parse_triage_decision(
            json.dumps({**_decision(), "policy_action": "FP_CANDIDATE"}),
            prompt_version="prompt-v1",
        )
    assert exc_info.value.error_code == "TRIAGE_OUTPUT_FORBIDDEN_FIELD"


@pytest.mark.parametrize("raw", ["not json", "[]", 42])
def test_output_validator_fails_closed(raw: object) -> None:
    with pytest.raises(SastTriageError):
        parse_triage_decision(raw, prompt_version="prompt-v1")


def test_output_validator_rejects_canary_without_echoing_it() -> None:
    canary = "STRUCTURED_OUTPUT_CANARY_DO_NOT_LEAK"
    with pytest.raises(SastTriageError) as exc_info:
        parse_triage_decision(
            json.dumps({**_decision(), "summary": canary}),
            prompt_version="prompt-v1",
            forbidden_values=(canary,),
        )
    assert canary not in str(exc_info.value)
