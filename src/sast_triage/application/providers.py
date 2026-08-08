"""Khởi tạo provider theo lựa chọn của CLI."""

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sast_triage.triage.fake_provider import FakeTriageProvider
from sast_triage.triage.real_provider import RealTriageProvider


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
    from sast_triage.triage.modal_provider import modal_qwen_provider_session

    with modal_qwen_provider_session() as provider:
        yield provider


def provider_identity(provider_name: str) -> tuple[str, str | None]:
    """Trả về tên provider và model để lưu checkpoint."""
    if provider_name == "fake":
        return "fake", "fake-triage-v1"
    if provider_name == "ollama":
        return "ollama", os.getenv("SAST_TRIAGE_LLM_MODEL", "qwen3:8b")
    return "real-modal-qwen", "Qwen/Qwen3-14B-AWQ"

