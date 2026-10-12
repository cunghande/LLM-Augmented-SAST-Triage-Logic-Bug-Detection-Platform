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


@pytest.mark.parametrize(
    ("record_update", "error_code"),
    [
        ({"split": "test"}, "BENCHMARK_SPLIT_INVALID"),
        ({"benchmark_version": "v2"}, "BENCHMARK_VERSION_MISMATCH"),
    ],
)
def test_benchmark_loader_enforces_split_and_version(
    tmp_path: Path,
    record_update: dict[str, str],
    error_code: str,
) -> None:
    path = tmp_path / "benchmark.json"
    path.write_text(
        json.dumps({"version": "v1", "records": [{**_record(), **record_update}]}),
        encoding="utf-8",
    )
    with pytest.raises(SastTriageError) as exc_info:
        load_benchmark(path)
    assert exc_info.value.error_code == error_code


def test_benchmark_loader_rejects_duplicate_finding_ids(tmp_path: Path) -> None:
    path = tmp_path / "benchmark.json"
    path.write_text(
        json.dumps({"version": "v1", "records": [_record(), {**_record(), "benchmark_id": "b-2"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SastTriageError) as exc_info:
        load_benchmark(path)
    assert exc_info.value.error_code == "BENCHMARK_DUPLICATE_FINDING"


def test_evaluation_does_not_claim_fake_provider_quality() -> None:
    dataset = load_benchmark_from_dict({"version": "v1", "records": [_record()]})
    result = BatchResult.model_construct(run_metadata=type("Meta", (), {"triage_provider": "fake"})(), results=[], scanner_errors=[])
    metrics = evaluate_batch(dataset, result)
    assert metrics["quality_claim_supported"] is False
    assert "No model-quality claim" in metrics["quality_claim_note"]
    assert set(metrics["metrics_by_split"]) == {"development", "calibration", "held_out"}
    assert "no held-out record" in metrics["quality_claim_note"]


def load_benchmark_from_dict(raw: dict[str, object]):
    """Create a temporary benchmark for a focused test."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(raw, handle)
        path = Path(handle.name)
    return load_benchmark(path)


def test_compute_binary_metric_ci() -> None:
    from sast_triage.evaluation.metrics import compute_binary_metric_ci

    # 10 samples: 8 TP actual, 8 predicted positive, 7 true positives
    data = [(True, True)] * 7 + [(False, True)] * 1 + [(True, False)] * 1 + [(False, False)] * 1
    low, high = compute_binary_metric_ci(data, metric_name="precision", n_bootstraps=200, ci=0.95)
    assert 0.0 <= low <= high <= 1.0
    assert high >= 0.7  # expected around 7/8 = 0.875

    # Empty data
    assert compute_binary_metric_ci([]) == (0.0, 0.0)


def test_compute_calibration_ece() -> None:
    from sast_triage.evaluation.metrics import compute_calibration_ece

    # Perfect calibration: high confidence -> always 1, low confidence -> always 0
    confidences = [0.9, 0.9, 0.9, 0.1, 0.1]
    accuracies = [1, 1, 1, 0, 0]
    res = compute_calibration_ece(confidences, accuracies, n_bins=5)
    assert "ece" in res
    assert res["ece"] >= 0.0
    assert len(res["bins"]) == 5
    assert res["total_samples"] == 5

    # Empty data
    assert compute_calibration_ece([], []) == {"ece": 0.0, "bins": []}

