"""Offline tests cho adapter Qwen3-14B Modal của CLI."""

import json
import subprocess
import sys
from pathlib import Path

import modal
import pytest

from modal_apps.qwen14b_benchmark import ModalQwenProvider as BenchmarkModalQwenProvider
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


def test_modal_app_import_does_not_require_pydantic(tmp_path: Path) -> None:
    script = """
import importlib.abc
import sys

class BlockPydantic(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "pydantic" or fullname.startswith("pydantic."):
            raise ModuleNotFoundError("pydantic blocked for Modal image regression test")
        return None

sys.meta_path.insert(0, BlockPydantic())
from sast_triage.triage.qwen14b_modal_app import MODEL_ID
print(MODEL_ID)
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == MODEL_ID


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


def _logic_input(prompt_version: str = "triage-prompt-v13") -> TriageInput:
    base = _input()
    finding = base.finding.model_copy(
        update={
            "scanner": ScannerType.MODULE2,
            "metadata": {"logic_class": "missing_authz_idor"},
        }
    )
    context = base.context.model_copy(
        update={
            "sanitized_snippet": json.dumps(
                {
                    "logic_analysis": {
                        "logic_class": "missing_authz_idor",
                        "retrieval_resolution": {
                            "status": "resolved_by_bounded_static_retrieval",
                            "facts": {
                                "caller_controlled_source": True,
                                "exact_object_authorization_guard_observed": False,
                            },
                        },
                    }
                }
            )
        }
    )
    return base.model_copy(
        update={
            "finding": finding,
            "context": context,
            "prompt_version": prompt_version,
        }
    )


def _complete_taint_input() -> TriageInput:
    base = _input()
    context = base.context.model_copy(
        update={
            "sanitized_snippet": json.dumps(
                {
                    "deterministic_verification": {
                        "mechanism": "taint_flow",
                        "evidence_complete": True,
                        "has_evidence_conflict": False,
                        "source_user_controlled": True,
                        "source_reaches_sink": True,
                    }
                }
            )
        }
    )
    return base.model_copy(
        update={"context": context, "prompt_version": "triage-prompt-v13"}
    )


def _modal_response(verdict: str, prompt_version: str) -> str:
    return json.dumps(
        {
            "model_verdict": verdict,
            "model_confidence": "HIGH",
            "summary": "summary",
            "evidence": ["evidence"],
            "missing_information": [] if verdict != "NEEDS_REVIEW" else ["missing"],
            "assumptions": [],
            "model_version": MODEL_ID,
            "prompt_version": prompt_version,
        }
    )


class _RemoteMethod:
    def __init__(self, response: str | BaseException | list[str | BaseException]) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def remote(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        response = (
            self.response.pop(0)
            if isinstance(self.response, list)
            else self.response
        )
        if isinstance(response, BaseException):
            raise response
        return response


class _RemoteModel:
    def __init__(self, response: str | BaseException | list[str | BaseException]) -> None:
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
    assert remote.chat.calls[0]["temperature"] == 0.0
    assert remote.chat.calls[0]["seed"] == 42


def test_modal_provider_retries_truncated_json_with_larger_budget() -> None:
    valid_response = json.dumps(
        {
            "model_verdict": "LIKELY_FP",
            "model_confidence": "HIGH",
            "summary": "summary",
            "evidence": ["evidence"],
            "missing_information": [],
            "assumptions": [],
            "model_version": MODEL_ID,
            "prompt_version": "p1",
        }
    )
    remote = _RemoteModel(['{"model_verdict":', valid_response])

    decision = ModalQwenProvider(remote).triage(_input())

    assert decision.model_verdict.value == "LIKELY_FP"
    assert [call["max_tokens"] for call in remote.chat.calls] == [512, 1536]


def test_modal_provider_runs_one_v13_logic_verifier_pass() -> None:
    remote = _RemoteModel(
        [
            _modal_response("NEEDS_REVIEW", "triage-prompt-v13"),
            _modal_response("LIKELY_TP", "triage-prompt-v13"),
        ]
    )

    provider = ModalQwenProvider(remote)
    decision = provider.triage(_logic_input())

    assert decision.model_verdict.value == "LIKELY_TP"
    assert provider.logic_verification_retries == 1
    assert [call["max_tokens"] for call in remote.chat.calls] == [512, 768]
    retry_messages = remote.chat.calls[1]["messages"]
    assert isinstance(retry_messages, list)
    assert "STATIC EVIDENCE VERIFIER PASS" in retry_messages[0]["content"]
    assert "retrieval_resolution" in retry_messages[1]["content"]


def test_modal_provider_retries_complete_taint_abstention() -> None:
    remote = _RemoteModel(
        [
            _modal_response("NEEDS_REVIEW", "triage-prompt-v13"),
            _modal_response("LIKELY_TP", "triage-prompt-v13"),
        ]
    )

    provider = ModalQwenProvider(remote)
    decision = provider.triage(_complete_taint_input())

    assert decision.model_verdict.value == "LIKELY_TP"
    assert provider.logic_verification_retries == 1
    assert [call["max_tokens"] for call in remote.chat.calls] == [512, 768]


def test_modal_provider_does_not_retry_logic_before_v13() -> None:
    remote = _RemoteModel(_modal_response("NEEDS_REVIEW", "triage-prompt-v12"))

    decision = ModalQwenProvider(remote).triage(
        _logic_input(prompt_version="triage-prompt-v12")
    )

    assert decision.model_verdict.value == "NEEDS_REVIEW"
    assert len(remote.chat.calls) == 1


def test_modal_provider_does_not_retry_unknown_logic_class() -> None:
    triage_input = _logic_input().model_copy(
        update={
            "finding": _logic_input().finding.model_copy(
                update={"metadata": {"logic_class": "untrusted-new-class"}}
            )
        }
    )
    remote = _RemoteModel(_modal_response("NEEDS_REVIEW", "triage-prompt-v13"))

    provider = ModalQwenProvider(remote)
    decision = provider.triage(triage_input)

    assert decision.model_verdict.value == "NEEDS_REVIEW"
    assert provider.logic_verification_retries == 0
    assert len(remote.chat.calls) == 1


def test_benchmark_modal_provider_retries_truncated_json() -> None:
    triage_input = _input().model_copy(update={"prompt_version": "triage-prompt-v9"})
    valid_response = json.dumps(
        {
            "model_verdict": "LIKELY_TP",
            "model_confidence": "HIGH",
            "summary": "summary",
            "evidence": ["evidence"],
            "missing_information": [],
            "assumptions": [],
            "model_version": MODEL_ID,
            "prompt_version": "triage-prompt-v9",
        }
    )
    remote = _RemoteModel(['{"model_verdict":', valid_response])

    decision = BenchmarkModalQwenProvider(remote).triage(triage_input)

    assert decision.model_verdict.value == "LIKELY_TP"
    assert [call["max_tokens"] for call in remote.chat.calls] == [512, 1536]
    retry_messages = remote.chat.calls[1]["messages"]
    assert isinstance(retry_messages, list)
    assert "OUTPUT RECOVERY" in retry_messages[0]["content"]


@pytest.mark.parametrize("provider_type", [ModalQwenProvider, BenchmarkModalQwenProvider])
def test_modal_provider_uses_minimal_schema_after_two_invalid_full_outputs(
    provider_type: type[ModalQwenProvider] | type[BenchmarkModalQwenProvider],
) -> None:
    triage_input = _input().model_copy(update={"prompt_version": "triage-prompt-v9"})
    remote = _RemoteModel(
        [
            '{"model_verdict":',
            '{"model_verdict":',
            json.dumps(
                {
                    "model_verdict": "LIKELY_TP",
                    "model_confidence": "HIGH",
                }
            ),
        ]
    )

    decision = provider_type(remote).triage(triage_input)

    assert decision.model_verdict.value == "LIKELY_TP"
    assert [call["max_tokens"] for call in remote.chat.calls] == [512, 1536, 128]
    minimal_schema = remote.chat.calls[2]["json_schema"]
    assert isinstance(minimal_schema, dict)
    assert set(minimal_schema["properties"]) == {
        "model_verdict",
        "model_confidence",
    }


def test_modal_resource_exhaustion_has_dedicated_safe_error() -> None:
    provider = ModalQwenProvider(
        _RemoteModel(modal.exception.ResourceExhaustedError("private provider detail"))
    )

    with pytest.raises(SastTriageError) as exc_info:
        provider.triage(_input())

    assert exc_info.value.error_code == "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED"
    assert "private provider detail" not in exc_info.value.safe_message
