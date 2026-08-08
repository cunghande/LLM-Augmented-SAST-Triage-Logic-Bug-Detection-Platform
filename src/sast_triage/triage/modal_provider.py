"""Provider Qwen3-14B-AWQ trên Modal cho CLI ``--provider real``."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import modal

from modal_apps.qwen14b_modal import MODEL_ID, Qwen14B, app, download_model
from sast_triage.errors import SastTriageError
from sast_triage.models import TriageDecision, TriageInput
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt


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
        try:
            response = self._remote_model.chat.remote(
                messages=messages,
                thinking=False,
                max_tokens=512,
                json_schema=_decision_schema(triage_input.prompt_version),
            )
        except modal.exception.ResourceExhaustedError as exc:
            raise _translate_modal_exception(exc) from None
        except modal.exception.AuthError as exc:
            raise _translate_modal_exception(exc) from None
        except modal.exception.TimeoutError as exc:
            raise _translate_modal_exception(exc) from None
        except (modal.exception.Error, RuntimeError, TypeError, ValueError) as exc:
            raise _translate_modal_exception(exc) from None

        decision = parse_triage_decision(
            response,
            prompt_version=triage_input.prompt_version,
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
