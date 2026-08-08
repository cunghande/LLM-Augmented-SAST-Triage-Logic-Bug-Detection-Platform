"""Schema benchmark nhỏ, an toàn và JSON loader."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError

_LABELS = frozenset({"TP", "FP", "DISPUTED", "INSUFFICIENT_CONTEXT"})


@dataclass(frozen=True)
class BenchmarkRecord:
    """Một record benchmark ground-truth không chứa nội dung scanner thô."""

    benchmark_id: str
    repository_identifier: str
    scanner: str
    artifact_reference: str
    finding_instance_id: str
    expected_label: str
    reviewer_rationale: str
    evidence_reference: str
    split: str
    benchmark_version: str


@dataclass(frozen=True)
class BenchmarkDataset:
    """Dataset benchmark bất biến."""

    version: str
    records: tuple[BenchmarkRecord, ...]
    dataset_kind: str = "curated"


def _record(raw: Any, index: int, forbidden_values: tuple[str, ...]) -> BenchmarkRecord:
    """Validate và tạo một benchmark record."""
    if not isinstance(raw, dict):
        raise SastTriageError("Benchmark record is not an object.", "BENCHMARK_RECORD_INVALID")
    required = (
        "benchmark_id", "repository_identifier", "scanner", "artifact_reference",
        "finding_instance_id", "expected_label", "reviewer_rationale",
        "evidence_reference", "split", "benchmark_version",
    )
    if any(not isinstance(raw.get(key), str) or not raw[key].strip() for key in required):
        raise SastTriageError(
            "Benchmark record is missing a required field.",
            f"BENCHMARK_RECORD_INVALID_{index}",
        )
    for value in raw.values():
        if isinstance(value, str) and any(forbidden in value for forbidden in forbidden_values):
            raise SastTriageError("Benchmark contains a forbidden value.", "BENCHMARK_FORBIDDEN_VALUE")
    if raw["expected_label"] not in _LABELS:
        raise SastTriageError("Benchmark label is invalid.", "BENCHMARK_LABEL_INVALID")
    return BenchmarkRecord(**{key: raw[key] for key in required})


def load_benchmark(file_path: Path, *, forbidden_values: tuple[str, ...] = ()) -> BenchmarkDataset:
    """Nạp benchmark JSON có phiên bản hoặc chặn an toàn."""
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SastTriageError("Benchmark file does not exist.", "BENCHMARK_FILE_NOT_FOUND") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SastTriageError("Benchmark file could not be read.", "BENCHMARK_FILE_INVALID") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), str) or not isinstance(raw.get("records"), list):
        raise SastTriageError("Benchmark root has an invalid schema.", "BENCHMARK_SCHEMA_INVALID")
    records = tuple(_record(item, index, forbidden_values) for index, item in enumerate(raw["records"]))
    dataset_kind = raw.get("dataset_kind", "curated")
    if not isinstance(dataset_kind, str) or not dataset_kind.strip():
        raise SastTriageError("Benchmark dataset_kind is invalid.", "BENCHMARK_SCHEMA_INVALID")
    return BenchmarkDataset(version=raw["version"], records=records, dataset_kind=dataset_kind)
