import sys

import pytest

from sast_triage.application.providers import provider_session
from sast_triage.errors import SastTriageError


def test_real_provider_reports_missing_modal_dependency_safely(monkeypatch) -> None:
    monkeypatch.delitem(sys.modules, "sast_triage.triage.modal_provider", raising=False)
    monkeypatch.setitem(sys.modules, "modal", None)

    with pytest.raises(SastTriageError) as raised, provider_session("real"):
        pass

    assert raised.value.error_code == "TRIAGE_PROVIDER_DEPENDENCY_MISSING"
    assert "modal" not in raised.value.safe_message.lower() or "dependency" in raised.value.safe_message.lower()
