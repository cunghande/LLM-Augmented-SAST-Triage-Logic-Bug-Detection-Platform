"""Tests for benchmark schema and evaluation semantics."""

import json
from pathlib import Path

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.evaluation.benchmark import load_benchmark
from sast_triage.evaluation.metrics import evaluate_batch
from sast_triage.models import BatchResult


def _record(identifier: str = "f-1") -> dict[str, str]:
    return {
        "benchmark_id": "b-1", "repository_identifier": "repo", "scanner": "SEMGREP",
        "artifact_reference": "semgrep.json", "finding_instance_id": identifier,
        "expected_label": "TP", "reviewer_rationale": "confirmed",
        "evidence_reference": "fixture-1", "split": "development", "benchmark_version": "v1",
    }


def test_benchmark_loader_validates_schema_and_forbidden_values(tmp_path: Path) -> None:
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps({"version": "v1", "records": [_record()]}), encoding="utf-8")
    dataset = load_benchmark(path)
    assert dataset.records[0].expected_label == "TP"
    path.write_text(json.dumps({"version": "v1", "records": [{**_record(), "expected_label": "bad"}]}), encoding="utf-8")
    with pytest.raises(SastTriageError):
        load_benchmark(path)


def test_evaluation_does_not_claim_fake_provider_quality() -> None:
    dataset = load_benchmark_from_dict({"version": "v1", "records": [_record()]})
    result = BatchResult.model_construct(run_metadata=type("Meta", (), {"triage_provider": "fake"})(), results=[], scanner_errors=[])
    metrics = evaluate_batch(dataset, result)
    assert metrics["quality_claim_supported"] is False
    assert "No model-quality claim" in metrics["quality_claim_note"]


def load_benchmark_from_dict(raw: dict[str, object]):
    """Create a temporary benchmark for a focused test."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(raw, handle)
        path = Path(handle.name)
    return load_benchmark(path)
