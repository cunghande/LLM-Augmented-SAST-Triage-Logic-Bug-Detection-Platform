"""Semgrep JSON artifact parser.

Parses a Semgrep JSON report file into a ``ScannerParseResult``
containing ``NormalizedFinding`` instances and per-record
``ProcessingError`` records.

Security notes:
- Raw artifact content is never stored in the returned models.
- Metadata is filtered through a strict allowlist.
- ``safe_message`` fields never contain raw JSON fragments or
  tracebacks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    ProcessingError,
    ProcessingStage,
    ScannerParseResult,
    ScannerType,
    Severity,
)

logger = logging.getLogger(__name__)

# --- Constants ---

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_METADATA_ALLOWLIST: frozenset[str] = frozenset(
    {
        "cwe",
        "owasp",
        "technology",
        "category",
        "confidence",
        "references",
    }
)


# --- Helpers ---


def _generate_finding_id(
    rule_id: str,
    file_path: str,
    start_line: int,
    end_line: int | None,
) -> str:
    """Generate a deterministic finding instance ID.

    Uses the contract from docs/domain-models.md:
    ``sha256(f"{scanner}:{rule_id}:{file_path}:{start_line}:{end_line}")[:16]``
    """
    end_str = str(end_line) if end_line is not None else "None"
    hash_input = f"SEMGREP:{rule_id}:{file_path}:{start_line}:{end_str}"
    return hashlib.sha256(hash_input.encode()).hexdigest()[:16]


def _map_severity(raw_severity: Any) -> Severity:
    """Map Semgrep severity string to domain Severity enum (case-insensitive)."""
    if not isinstance(raw_severity, str):
        return Severity.UNKNOWN
    return _SEVERITY_MAP.get(raw_severity.upper(), Severity.UNKNOWN)


def _filter_metadata(raw_metadata: Any) -> dict[str, Any]:
    """Extract only allowlisted keys from Semgrep extra.metadata."""
    if not isinstance(raw_metadata, dict):
        return {}
    return {k: v for k, v in raw_metadata.items() if k in _METADATA_ALLOWLIST}


def _make_artifact_error(
    error_code: str,
    safe_message: str,
    retryable: bool = False,
) -> ProcessingError:
    """Create an artifact-level ProcessingError for the Semgrep scanner."""
    return ProcessingError(
        finding_id=None,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code=error_code,
        safe_message=safe_message,
        retryable=retryable,
    )


def _make_record_error(
    error_code: str,
    safe_message: str,
    record_index: int,
) -> ProcessingError:
    """Create a per-record ProcessingError for the Semgrep scanner."""
    return ProcessingError(
        finding_id=None,
        scanner=ScannerType.SEMGREP,
        stage=ProcessingStage.PARSE,
        error_code=error_code,
        safe_message=f"Semgrep result[{record_index}]: {safe_message}",
        retryable=False,
    )


# --- Public API ---


def parse_semgrep_json(file_path: Path) -> ScannerParseResult:
    """Parse a Semgrep JSON artifact file into normalized findings.

    Args:
        file_path: Path to the Semgrep JSON report file.

    Returns:
        A frozen ``ScannerParseResult`` with parsed findings and
        any per-record or artifact-level errors.
    """
    # --- Artifact-level validation ---

    if not file_path.exists():
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_FILE_NOT_FOUND",
                    "Semgrep artifact file does not exist.",
                ),
            ),
        )

    try:
        raw_bytes = file_path.read_bytes()
    except PermissionError:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_FILE_READ_ERROR",
                    "Permission denied when reading Semgrep artifact file.",
                ),
            ),
        )
    except OSError:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_FILE_NOT_FOUND",
                    "Semgrep artifact file could not be read.",
                ),
            ),
        )

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_UNSUPPORTED_ENCODING",
                    "Semgrep artifact file is not valid UTF-8.",
                ),
            ),
        )

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_INVALID_JSON",
                    "Semgrep artifact file contains invalid JSON.",
                ),
            ),
        )

    if not isinstance(data, dict):
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_INVALID_ROOT",
                    "Semgrep artifact root must be a JSON object.",
                ),
            ),
        )

    if "results" not in data:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_RESULTS_MISSING",
                    "Semgrep artifact is missing the 'results' field.",
                ),
            ),
        )

    results = data["results"]
    if not isinstance(results, list):
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_RESULTS_INVALID",
                    "Semgrep artifact 'results' field is not an array.",
                ),
            ),
        )

    if len(results) == 0:
        return ScannerParseResult()

    # --- Per-record parsing ---

    findings: list[NormalizedFinding] = []
    errors: list[ProcessingError] = []

    for idx, record in enumerate(results):
        if not isinstance(record, dict):
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_INVALID_FIELD",
                    "record is not a JSON object.",
                    idx,
                )
            )
            continue

        # Required: check_id
        check_id = record.get("check_id")
        if not isinstance(check_id, str) or not check_id.strip():
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_MISSING_FIELD",
                    "missing or invalid 'check_id'.",
                    idx,
                )
            )
            continue

        # Required: path
        path = record.get("path")
        if not isinstance(path, str) or not path.strip():
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_MISSING_FIELD",
                    "missing or invalid 'path'.",
                    idx,
                )
            )
            continue

        # Required: start.line
        start_obj = record.get("start")
        if not isinstance(start_obj, dict):
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_MISSING_FIELD",
                    "missing or invalid 'start' object.",
                    idx,
                )
            )
            continue

        start_line = start_obj.get("line")
        if not isinstance(start_line, int) or start_line <= 0:
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_INVALID_FIELD",
                    "'start.line' must be a positive integer.",
                    idx,
                )
            )
            continue

        # Required: extra.message
        extra = record.get("extra")
        if not isinstance(extra, dict):
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_MISSING_FIELD",
                    "missing or invalid 'extra' object.",
                    idx,
                )
            )
            continue

        message = extra.get("message")
        if not isinstance(message, str) or not message.strip():
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_MISSING_FIELD",
                    "missing or invalid 'extra.message'.",
                    idx,
                )
            )
            continue

        # Optional: end.line
        end_obj = record.get("end")
        end_line: int | None = None
        if isinstance(end_obj, dict):
            raw_end_line = end_obj.get("line")
            if isinstance(raw_end_line, int) and raw_end_line >= start_line:
                end_line = raw_end_line

        # Optional: extra.severity
        severity = _map_severity(extra.get("severity"))

        # Optional: extra.lines → snippet
        raw_lines = extra.get("lines")
        snippet = raw_lines if isinstance(raw_lines, str) else ""

        # Optional: extra.metadata → allowlisted metadata
        metadata = _filter_metadata(extra.get("metadata"))

        # Generate deterministic finding instance ID
        finding_id = _generate_finding_id(check_id, path, start_line, end_line)

        try:
            finding = NormalizedFinding(
                finding_instance_id=finding_id,
                scanner=ScannerType.SEMGREP,
                finding_type=FindingType.SAST,
                rule_id=check_id,
                rule_name=None,
                file_path=path,
                start_line=start_line,
                end_line=end_line,
                severity=severity,
                message=message,
                snippet=snippet,
                metadata=metadata,
            )
            findings.append(finding)
        except ValueError:
            errors.append(
                _make_record_error(
                    "PARSE_RECORD_INVALID_FIELD",
                    "record produced an invalid NormalizedFinding.",
                    idx,
                )
            )

    return ScannerParseResult(
        findings=tuple(findings),
        errors=tuple(errors),
    )
