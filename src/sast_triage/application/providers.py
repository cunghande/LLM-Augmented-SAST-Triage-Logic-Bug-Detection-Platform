"""Khởi tạo provider theo lựa chọn của CLI."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sast_triage.errors import SastTriageError
from sast_triage.triage.fake_provider import FakeTriageProvider
from sast_triage.triage.real_provider import RealTriageProvider


class _LazyModalProvider:
    """Start the Modal app only on the first cache miss/provider call."""

    provider_name = "real-modal-qwen"
    model_version = "Qwen/Qwen3-14B-AWQ"

    def __init__(self, session_factory: object) -> None:
        self._session_factory = session_factory
        self._session: Any = None
        self._provider: object | None = None

    def triage(self, triage_input: object) -> object:
        """Delegate after lazily entering the real provider session."""
        if self._provider is None:
            self._session = self._session_factory()
            self._provider = self._session.__enter__()
        return self._provider.triage(triage_input)  # type: ignore[attr-defined, no-any-return]

    def close(self) -> None:
        """Close Modal resources only when they were actually started."""
        if self._session is not None:
            session = self._session
            self._session = None
            self._provider = None
            session.__exit__(None, None, None)


@contextmanager
def provider_session(provider_name: str) -> Iterator[object]:
    """Giữ một provider cho toàn bộ batch tuần tự."""
    if provider_name == "fake":
        yield FakeTriageProvider()
        return
    if provider_name == "ollama":
        yield RealTriageProvider.for_ollama()
        return

    # Chỉ import Modal khi người dùng chọn provider real.
    try:
        from sast_triage.triage.modal_provider import modal_qwen_provider_session
    except ModuleNotFoundError as exc:
        if exc.name != "modal":
            raise
        raise SastTriageError(
            "Modal provider dependency is not installed in this Python environment.",
            "TRIAGE_PROVIDER_DEPENDENCY_MISSING",
            retryable=False,
        ) from None

    provider = _LazyModalProvider(modal_qwen_provider_session)
    try:
        yield provider
    finally:
        provider.close()


def provider_identity(provider_name: str) -> tuple[str, str | None]:
    """Trả về tên provider và model để lưu checkpoint."""
    if provider_name == "fake":
        return "fake", "fake-triage-v1"
    if provider_name == "ollama":
        return "ollama", os.getenv("SAST_TRIAGE_LLM_MODEL", "qwen3:8b")
    return "real-modal-qwen", "Qwen/Qwen3-14B-AWQ"
