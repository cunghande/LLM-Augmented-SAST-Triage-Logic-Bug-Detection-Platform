"""Provider Qwen3-14B-AWQ trên Modal cho CLI ``--provider real``."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager

import modal

from sast_triage.errors import SastTriageError
from sast_triage.logic import LogicBugClass
from sast_triage.models import (
    ModelConfidence,
    ModelVerdict,
    TriageDecision,
    TriageInput,
)
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt
from sast_triage.triage.qwen14b_modal_app import MODEL_ID, Qwen14B, app, download_model


def _decision_schema(prompt_version: str) -> dict[str, object]:
    """Tạo JSON schema chính xác cho output triage của Modal model."""
    properties: dict[str, object] = {
        "model_verdict": {
            "type": "string",
            "enum": ["LIKELY_TP", "LIKELY_FP", "NEEDS_REVIEW"],
        },
        "model_confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"],
        },
        "summary": {"type": "string", "minLength": 1},
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "missing_information": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "assumptions": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "model_version": {"type": "string", "enum": [MODEL_ID]},
        "prompt_version": {"type": "string", "enum": [prompt_version]},
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def minimal_recovery_schema() -> dict[str, object]:
    """Return a tiny strict schema used only after full-schema serialization fails."""
    properties: dict[str, object] = {
        "model_verdict": {
            "type": "string",
            "enum": ["LIKELY_TP", "LIKELY_FP", "NEEDS_REVIEW"],
        },
        "model_confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"],
        },
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def parse_minimal_recovery_decision(
    response: str,
    *,
    prompt_version: str,
) -> TriageDecision:
    """Validate a minimal LLM verdict and build a source-free standard explanation."""
    try:
        payload = json.loads(response)
        if not isinstance(payload, dict) or set(payload) != {
            "model_verdict",
            "model_confidence",
        }:
            raise ValueError
        verdict = ModelVerdict(payload["model_verdict"])
        confidence = ModelConfidence(payload["model_confidence"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise SastTriageError(
            "Minimal Modal recovery output failed validation.",
            "TRIAGE_OUTPUT_SCHEMA_INVALID",
            retryable=False,
        ) from None
    return TriageDecision(
        model_verdict=verdict,
        model_confidence=confidence,
        summary="LLM đã trả về verdict hợp lệ qua schema phục hồi tối giản.",
        evidence=["Policy sử dụng Evidence Card đã được kiểm tra và làm sạch."],
        missing_information=[],
        assumptions=["Phần giải thích đầy đủ không được dùng do lỗi serialization."],
        model_version=MODEL_ID,
        prompt_version=prompt_version,
    )


def _translate_modal_exception(exc: BaseException) -> SastTriageError:
    """Chuyển lỗi Modal thành mã an toàn mà không làm lộ payload."""
    if isinstance(exc, modal.exception.ResourceExhaustedError):
        return SastTriageError(
            "Modal capacity, quota, or credit is exhausted. Progress was checkpointed.",
            "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED",
            retryable=True,
        )
    if isinstance(exc, modal.exception.AuthError):
        return SastTriageError(
            "Modal authentication is unavailable. Run 'modal setup' once on this machine.",
            "TRIAGE_PROVIDER_MODAL_AUTH_ERROR",
            retryable=False,
        )
    if isinstance(exc, modal.exception.TimeoutError):
        return SastTriageError(
            "Modal Qwen request timed out.",
            "TRIAGE_PROVIDER_MODAL_TIMEOUT",
            retryable=True,
        )
    return SastTriageError(
        "Modal Qwen request failed.",
        "TRIAGE_PROVIDER_MODAL_ERROR",
        retryable=True,
    )


class ModalQwenProvider:
    """Adapter đồng bộ gửi TriageInput an toàn đến Qwen3-14B trên Modal."""

    provider_name = "real-modal-qwen"
    model_version = MODEL_ID

    def __init__(self, remote_model: object) -> None:
        self._remote_model = remote_model
        self._completed = 0
        self._logic_verification_retries = 0

    @property
    def logic_verification_retries(self) -> int:
        """Return the number of bounded logic verifier calls attempted."""
        return self._logic_verification_retries

    def _should_retry_logic_verification(
        self,
        triage_input: TriageInput,
        decision: TriageDecision,
    ) -> bool:
        """Retry only bounded v13 logic abstentions with generated metadata."""
        return (
            triage_input.prompt_version == "triage-prompt-v13"
            and decision.model_verdict == ModelVerdict.NEEDS_REVIEW
            and triage_input.finding.metadata.get("logic_class")
            in {bug_class.value for bug_class in LogicBugClass}
        )

    def _retry_logic_verification(
        self,
        triage_input: TriageInput,
        messages: list[dict[str, str]],
        first_decision: TriageDecision,
    ) -> TriageDecision:
        """Run one bounded verifier pass and fail safely back to the first decision."""
        verifier_messages = [
            {
                "role": "system",
                "content": (
                    messages[0]["content"]
                    + "\n\nLOGIC VERIFIER PASS: The first pass abstained. Re-evaluate "
                    "the same sanitized Evidence Card using retrieval_resolution and the "
                    "specialized rubric. Do not request facts already marked resolved. "
                    "Return NEEDS_REVIEW only if a specific unresolved limitation could "
                    "change the verdict. Never invent runtime execution or a PoC."
                ),
            },
            messages[1],
        ]
        self._logic_verification_retries += 1
        try:
            response = self._remote_model.chat.remote(
                messages=verifier_messages,
                thinking=False,
                max_tokens=768,
                json_schema=_decision_schema(triage_input.prompt_version),
                temperature=0.0,
                seed=42,
            )
            verified = parse_triage_decision(
                response,
                prompt_version=triage_input.prompt_version,
            )
        except (
            SastTriageError,
            modal.exception.Error,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            return first_decision
        return verified

    def triage(self, triage_input: TriageInput) -> TriageDecision:
        """Gửi prompt đã sanitize, yêu cầu JSON schema và validate response."""
        if not isinstance(triage_input, TriageInput):
            raise SastTriageError(
                "Modal Qwen provider requires TriageInput.",
                "TRIAGE_INVALID_INPUT",
            )
        prompt = build_triage_prompt(triage_input, model_version=self.model_version)
        messages = [
            {"role": "system", "content": prompt.system_message},
            {"role": "user", "content": prompt.user_message},
        ]
        decision: TriageDecision | None = None
        for max_tokens in (512, 1536):
            try:
                response = self._remote_model.chat.remote(
                    messages=messages,
                    thinking=False,
                    max_tokens=max_tokens,
                    json_schema=_decision_schema(triage_input.prompt_version),
                    temperature=0.0,
                    seed=42,
                )
            except modal.exception.ResourceExhaustedError as exc:
                raise _translate_modal_exception(exc) from None
            except modal.exception.AuthError as exc:
                raise _translate_modal_exception(exc) from None
            except modal.exception.TimeoutError as exc:
                raise _translate_modal_exception(exc) from None
            except (modal.exception.Error, RuntimeError, TypeError, ValueError) as exc:
                raise _translate_modal_exception(exc) from None

            try:
                decision = parse_triage_decision(
                    response,
                    prompt_version=triage_input.prompt_version,
                )
                break
            except SastTriageError as exc:
                recoverable_output_codes = {
                    "TRIAGE_OUTPUT_INVALID_JSON",
                    "TRIAGE_OUTPUT_SCHEMA_INVALID",
                }
                if exc.error_code not in recoverable_output_codes:
                    raise
                if max_tokens == 1536:
                    break

        if decision is None:
            recovery_messages = [
                {
                    "role": "system",
                    "content": (
                        prompt.system_message
                        + "\n\nMINIMAL OUTPUT RECOVERY: Return only model_verdict and "
                        "model_confidence using the supplied strict schema."
                    ),
                },
                messages[1],
            ]
            try:
                response = self._remote_model.chat.remote(
                    messages=recovery_messages,
                    thinking=False,
                    max_tokens=128,
                    json_schema=minimal_recovery_schema(),
                    temperature=0.0,
                    seed=42,
                )
                decision = parse_minimal_recovery_decision(
                    response,
                    prompt_version=triage_input.prompt_version,
                )
            except modal.exception.ResourceExhaustedError as exc:
                raise _translate_modal_exception(exc) from None
            except modal.exception.AuthError as exc:
                raise _translate_modal_exception(exc) from None
            except modal.exception.TimeoutError as exc:
                raise _translate_modal_exception(exc) from None
            except (modal.exception.Error, RuntimeError, TypeError, ValueError) as exc:
                raise _translate_modal_exception(exc) from None
        if self._should_retry_logic_verification(triage_input, decision):
            decision = self._retry_logic_verification(
                triage_input,
                messages,
                decision,
            )
        self._completed += 1
        if self._completed == 1 or self._completed % 10 == 0:
            print(
                f"Tiến độ Modal: đã hoàn thành {self._completed} finding.",
                flush=True,
            )
        return decision


@contextmanager
def modal_qwen_provider_session() -> Iterator[ModalQwenProvider]:
    """Mở một Modal App cho cả batch và tự bảo đảm model đã cache."""
    try:
        with modal.enable_output(), app.run():
            download_model.remote()
            yield ModalQwenProvider(Qwen14B())
    except SastTriageError:
        raise
    except modal.exception.ResourceExhaustedError as exc:
        raise _translate_modal_exception(exc) from None
    except modal.exception.AuthError as exc:
        raise _translate_modal_exception(exc) from None
    except modal.exception.TimeoutError as exc:
        raise _translate_modal_exception(exc) from None
    except (modal.exception.Error, RuntimeError, TypeError, ValueError) as exc:
        raise _translate_modal_exception(exc) from None
