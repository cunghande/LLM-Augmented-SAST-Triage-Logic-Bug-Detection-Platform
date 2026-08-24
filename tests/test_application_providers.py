import sys

import pytest

from sast_triage.application.providers import _LazyModalProvider, provider_session
from sast_triage.errors import SastTriageError


def test_real_provider_reports_missing_modal_dependency_safely(monkeypatch) -> None:
    monkeypatch.delitem(sys.modules, "sast_triage.triage.modal_provider", raising=False)
    monkeypatch.setitem(sys.modules, "modal", None)

    with pytest.raises(SastTriageError) as raised, provider_session("real"):
        pass

    assert raised.value.error_code == "TRIAGE_PROVIDER_DEPENDENCY_MISSING"
    assert "modal" not in raised.value.safe_message.lower() or "dependency" in raised.value.safe_message.lower()


def test_lazy_modal_provider_does_not_start_unused_session() -> None:
    entered = 0

    class Session:
        def __enter__(self) -> object:
            nonlocal entered
            entered += 1
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    provider = _LazyModalProvider(Session)
    provider.close()

    assert entered == 0
