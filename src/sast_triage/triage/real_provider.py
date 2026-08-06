"""Minimal OpenAI-compatible HTTP triage provider with safe boundaries."""

import json
import os
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sast_triage.errors import SastTriageError
from sast_triage.models import TriageDecision, TriageInput
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt

Transport = Callable[[str, dict[str, object], dict[str, str], float], bytes]


def _http_transport(url: str, payload: dict[str, object], headers: dict[str, str], timeout_seconds: float) -> bytes:
    """Send one HTTP request without exposing payload or response in errors."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(url, data=body, headers=headers, method="POST")
    with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310: configured endpoint
        return response.read()


class RealTriageProvider:
    """OpenAI-compatible synchronous provider using validated structured output."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 30.0,
        reasoning_effort: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise SastTriageError("Real provider API key is not configured.", "TRIAGE_CONFIGURATION_ERROR")
        if not base_url or not base_url.strip() or not base_url.startswith(("https://", "http://")):
            raise SastTriageError("Real provider base URL is invalid.", "TRIAGE_CONFIGURATION_ERROR")
        if not model or not model.strip() or timeout_seconds <= 0:
            raise SastTriageError("Real provider model or timeout is invalid.", "TRIAGE_CONFIGURATION_ERROR")
        if reasoning_effort not in {None, "none", "low", "medium", "high", "max"}:
            raise SastTriageError("Real provider reasoning effort is invalid.", "TRIAGE_CONFIGURATION_ERROR")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._reasoning_effort = reasoning_effort
        self._transport = transport or _http_transport

    @classmethod
    def from_environment(cls, *, transport: Transport | None = None) -> "RealTriageProvider":
        """Create a provider from documented environment variables."""
        try:
            timeout = float(os.getenv("SAST_TRIAGE_LLM_TIMEOUT_SECONDS", "30"))
        except ValueError:
            timeout = -1
        return cls(
            api_key=os.getenv("SAST_TRIAGE_LLM_API_KEY", ""),
            base_url=os.getenv("SAST_TRIAGE_LLM_BASE_URL", ""),
            model=os.getenv("SAST_TRIAGE_LLM_MODEL", ""),
            timeout_seconds=timeout,
            reasoning_effort=os.getenv("SAST_TRIAGE_LLM_REASONING_EFFORT") or None,
            transport=transport,
        )

    @property
    def provider_name(self) -> str:
        """Return the stable provider identifier."""
        return "real"

    @property
    def model_version(self) -> str:
        """Return configured model identifier."""
        return self._model

    def triage(self, triage_input: TriageInput) -> TriageDecision:
        """Send a safe prompt and validate the structured provider response."""
        if not isinstance(triage_input, TriageInput):
            raise SastTriageError("triage() requires a TriageInput instance.", "TRIAGE_INVALID_INPUT")
        prompt = build_triage_prompt(triage_input, model_version=self._model)
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": prompt.system_message},
                {"role": "user", "content": prompt.user_message},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        if self._reasoning_effort is not None:
            payload["reasoning_effort"] = self._reasoning_effort
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        try:
            response_bytes = self._transport(
                f"{self._base_url}/chat/completions", payload, headers, self._timeout_seconds
            )
        except HTTPError as exc:
            raise SastTriageError(
                "Real provider returned an HTTP error.",
                "TRIAGE_PROVIDER_HTTP_ERROR",
                retryable=exc.code >= 500,
            ) from None
        except (URLError, TimeoutError, OSError):
            raise SastTriageError(
                "Real provider request failed or timed out.",
                "TRIAGE_PROVIDER_NETWORK_ERROR",
                retryable=True,
            ) from None
        try:
            envelope = json.loads(response_bytes)
            content = envelope["choices"][0]["message"]["content"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError):
            raise SastTriageError(
                "Real provider response has an invalid envelope.",
                "TRIAGE_PROVIDER_RESPONSE_INVALID",
            ) from None
        return parse_triage_decision(content, prompt_version=triage_input.prompt_version)
