"""Schema benchmark nhỏ, an toàn và JSON loader."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError

_LABELS = frozenset({"TP", "FP", "DISPUTED", "INSUFFICIENT_CONTEXT"})
_SPLITS = frozenset({"development", "calibration", "held_out"})
_ADJUDICATION_STATUSES = frozenset(
    {"UNREVIEWED", "AGREED", "ADJUDICATED", "DISPUTED"}
)
_REVIEWER_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


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
    reviewer_ids: tuple[str, ...] = ()
    adjudication_status: str = "UNREVIEWED"


@dataclass(frozen=True)
class BenchmarkDataset:
    """Dataset benchmark bất biến."""

    version: str
    records: tuple[BenchmarkRecord, ...]
    dataset_kind: str = "curated"
    review_protocol_version: str = "unverified"
    held_out_frozen: bool = False


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
    if raw["split"] not in _SPLITS:
        raise SastTriageError("Benchmark split is invalid.", "BENCHMARK_SPLIT_INVALID")
    reviewer_ids_raw = raw.get("reviewer_ids", [])
    if not isinstance(reviewer_ids_raw, list) or any(
        not isinstance(reviewer_id, str) or not _REVIEWER_ID.fullmatch(reviewer_id)
        for reviewer_id in reviewer_ids_raw
    ):
        raise SastTriageError(
            "Benchmark reviewer IDs are invalid.",
            "BENCHMARK_REVIEWER_INVALID",
        )
    reviewer_ids = tuple(reviewer_ids_raw)
    if len(reviewer_ids) != len(set(reviewer_ids)):
        raise SastTriageError(
            "Benchmark reviewer IDs must be unique per record.",
            "BENCHMARK_REVIEWER_DUPLICATE",
        )
    adjudication_status = raw.get("adjudication_status", "UNREVIEWED")
    if adjudication_status not in _ADJUDICATION_STATUSES:
        raise SastTriageError(
            "Benchmark adjudication status is invalid.",
            "BENCHMARK_ADJUDICATION_INVALID",
        )
    return BenchmarkRecord(
        **{key: raw[key] for key in required},
        reviewer_ids=reviewer_ids,
        adjudication_status=adjudication_status,
    )


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
    finding_ids = [record.finding_instance_id for record in records]
    if len(finding_ids) != len(set(finding_ids)):
        raise SastTriageError("Benchmark finding IDs must be unique.", "BENCHMARK_DUPLICATE_FINDING")
    benchmark_ids = [record.benchmark_id for record in records]
    if len(benchmark_ids) != len(set(benchmark_ids)):
        raise SastTriageError("Benchmark IDs must be unique.", "BENCHMARK_DUPLICATE_ID")
    if any(record.benchmark_version != raw["version"] for record in records):
        raise SastTriageError("Benchmark record version mismatch.", "BENCHMARK_VERSION_MISMATCH")
    dataset_kind = raw.get("dataset_kind", "curated")
    if not isinstance(dataset_kind, str) or not dataset_kind.strip():
        raise SastTriageError("Benchmark dataset_kind is invalid.", "BENCHMARK_SCHEMA_INVALID")
    review_protocol_version = raw.get("review_protocol_version", "unverified")
    held_out_frozen = raw.get("held_out_frozen", False)
    if not isinstance(review_protocol_version, str) or not review_protocol_version.strip():
        raise SastTriageError("Benchmark review protocol is invalid.", "BENCHMARK_SCHEMA_INVALID")
    if not isinstance(held_out_frozen, bool):
        raise SastTriageError("Benchmark held-out freeze flag is invalid.", "BENCHMARK_SCHEMA_INVALID")
    return BenchmarkDataset(
        version=raw["version"],
        records=records,
        dataset_kind=dataset_kind,
        review_protocol_version=review_protocol_version,
        held_out_frozen=held_out_frozen,
    )
