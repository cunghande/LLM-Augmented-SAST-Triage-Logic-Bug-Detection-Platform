"""Checkpoint persistence regression tests."""

from pathlib import Path

import pytest

from sast_triage import checkpoint
from sast_triage.checkpoint import TriageCheckpointStore
from sast_triage.errors import SastTriageError


def test_checkpoint_replace_retries_temporary_windows_lock(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "checkpoint.tmp"
    destination = tmp_path / "triage-checkpoint.json"
    source.write_text("new", encoding="utf-8")
    destination.write_text("old", encoding="utf-8")
    real_replace = checkpoint.os.replace
    attempts = 0
    delays: list[float] = []

    def flaky_replace(source_path: Path, destination_path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("simulated Windows sharing violation")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(checkpoint.os, "replace", flaky_replace)
    monkeypatch.setattr(checkpoint.time, "sleep", delays.append)

    checkpoint._replace_with_retry(source, destination)

    assert attempts == 3
    assert delays == [0.05, 0.1]
    assert destination.read_text(encoding="utf-8") == "new"
    assert not source.exists()


def test_checkpoint_rejects_resume_with_different_analysis_backend(
    tmp_path: Path,
) -> None:
    path = tmp_path / "triage-checkpoint.json"
    joern = TriageCheckpointStore(
        path,
        repository_identifier="example/repo",
        artifact_hashes={"semgrep": "abc"},
        finding_ids=(),
        prompt_version="triage-prompt-v8",
        output_schema_version="triage-decision-v1",
        analysis_backend="joern",
        analysis_backend_version="4.0.600",
        analysis_config_id="joern-config",
    )
    joern.save((), provider_history=(("fake", None),))
    native = TriageCheckpointStore(
        path,
        repository_identifier="example/repo",
        artifact_hashes={"semgrep": "abc"},
        finding_ids=(),
        prompt_version="triage-prompt-v8",
        output_schema_version="triage-decision-v1",
        analysis_backend="native",
        analysis_backend_version="0.1.0",
        analysis_config_id="native-config",
    )

    with pytest.raises(SastTriageError) as captured:
        native.load(())
    assert captured.value.error_code == "CHECKPOINT_BINDING_MISMATCH"
