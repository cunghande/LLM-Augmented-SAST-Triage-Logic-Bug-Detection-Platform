"""Offline tests cho adapter Qwen3-14B Modal của CLI."""

import json

import modal
import pytest

from modal_apps.qwen14b_modal import MODEL_ID
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
from sast_triage.triage.modal_provider import ModalQwenProvider


def _input() -> TriageInput:
    finding = NormalizedFinding(
        finding_instance_id="f-1",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="r",
        file_path="app.py",
        start_line=1,
        severity=Severity.LOW,
        message="message",
        snippet="RAW_MODAL_SNIPPET",
    )
    context = SanitizedContext(
        finding_id="f-1",
        sanitized_snippet="safe context",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=1,
        finding_start_line=1,
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )
    return TriageInput(
        finding=finding,
        context=context,
        prompt_version="p1",
        output_schema_version="s1",
        prompt_type="real",
    )


class _RemoteMethod:
    def __init__(self, response: str | BaseException) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def remote(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class _RemoteModel:
    def __init__(self, response: str | BaseException) -> None:
        self.chat = _RemoteMethod(response)


def test_modal_provider_builds_safe_structured_request() -> None:
    response = json.dumps(
        {
            "model_verdict": "LIKELY_TP",
            "model_confidence": "HIGH",
            "summary": "summary",
            "evidence": ["evidence"],
            "missing_information": [],
            "assumptions": [],
            "model_version": MODEL_ID,
            "prompt_version": "p1",
        }
    )
    remote = _RemoteModel(response)
    decision = ModalQwenProvider(remote).triage(_input())

    assert decision.model_verdict.value == "LIKELY_TP"
    request_text = json.dumps(remote.chat.calls[0])
    assert "RAW_MODAL_SNIPPET" not in request_text
    schema = remote.chat.calls[0]["json_schema"]
    assert isinstance(schema, dict)
    assert schema["properties"]["prompt_version"]["enum"] == ["p1"]


def test_modal_resource_exhaustion_has_dedicated_safe_error() -> None:
    provider = ModalQwenProvider(
        _RemoteModel(modal.exception.ResourceExhaustedError("private provider detail"))
    )

    with pytest.raises(SastTriageError) as exc_info:
        provider.triage(_input())

    assert exc_info.value.error_code == "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED"
    assert "private provider detail" not in exc_info.value.safe_message
