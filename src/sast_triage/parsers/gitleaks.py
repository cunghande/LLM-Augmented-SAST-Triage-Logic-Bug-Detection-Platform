"""Parser Gitleaks JSON artifact an toàn.

Parses a Gitleaks JSON report file into a ``ScannerParseResult``
containing ``NormalizedFinding`` instances and per-record
``ProcessingError`` records.

Security notes:
- Raw Secret and Match values only exist in narrow local scope of record parsing.
- Raw Secret is NEVER stored in NormalizedFinding, metadata, or errors.
- Raw Match is checked locally for redaction consistency, then discarded.
- Author, email, commit, date, message, symlink, and fingerprint fields are DROPPED.
- No logging of artifacts, secrets, or records.
"""

from __future__ import annotations

import hashlib
import json
import math
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
from sast_triage.redaction import redact_exact_secret


def _generate_finding_id(
    rule_id: str,
    file_path: str,
    start_line: int,
    end_line: int | None,
) -> str:
    """Sinh finding instance ID xác định cho finding Gitleaks.

    Uses contract: sha256(f"GITLEAKS:{rule_id}:{file_path}:{start_line}:{end_line}")[:16]
    Does NOT contain secrets, match strings, or entropy.
    """
    end_str = str(end_line) if end_line is not None else "None"
    hash_input = f"GITLEAKS:{rule_id}:{file_path}:{start_line}:{end_str}"
    return hashlib.sha256(hash_input.encode()).hexdigest()[:16]


def _make_artifact_error(
    error_code: str,
    safe_message: str,
    retryable: bool = False,
) -> ProcessingError:
    """Tạo ProcessingError cấp artifact cho scanner Gitleaks."""
    return ProcessingError(
        finding_id=None,
        scanner=ScannerType.GITLEAKS,
        stage=ProcessingStage.PARSE,
        error_code=error_code,
        safe_message=safe_message,
        retryable=retryable,
    )


def parse_gitleaks_json(file_path: Path) -> ScannerParseResult:
    """Parse file Gitleaks JSON artifact thành finding đã normalize an toàn.

    Args:
        file_path: Path to the Gitleaks JSON report file.

    Returns:
        A frozen ``ScannerParseResult`` containing normalized findings and errors.
    """
    # --- Validate cấp artifact ---

    if not file_path.exists():
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_FILE_NOT_FOUND",
                    "Gitleaks artifact file does not exist.",
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
                    "Permission denied when reading Gitleaks artifact file.",
                ),
            ),
        )
    except OSError:
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_FILE_NOT_FOUND",
                    "Gitleaks artifact file could not be read.",
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
                    "Gitleaks artifact file is not valid UTF-8.",
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
                    "Gitleaks artifact file contains invalid JSON.",
                ),
            ),
        )

    if not isinstance(data, list):
        return ScannerParseResult(
            errors=(
                _make_artifact_error(
                    "PARSE_INVALID_ROOT",
                    "Gitleaks artifact root must be a JSON array.",
                ),
            ),
        )

    if len(data) == 0:
        return ScannerParseResult()

    # --- Parse theo từng record ---

    findings: list[NormalizedFinding] = []
    errors: list[ProcessingError] = []

    for idx, record in enumerate(data):
        if not isinstance(record, dict):
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_INVALID_FIELD",
                    safe_message=f"Gitleaks record[{idx}] is not a JSON object.",
                    retryable=False,
                )
            )
            continue

        # Trường bắt buộc: RuleID
        rule_id = record.get("RuleID")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_MISSING_FIELD",
                    safe_message=f"Gitleaks record[{idx}] missing or invalid 'RuleID'.",
                    retryable=False,
                )
            )
            continue

        # Trường bắt buộc: File
        file_path_str = record.get("File")
        if not isinstance(file_path_str, str) or not file_path_str.strip():
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_MISSING_FIELD",
                    safe_message=f"Gitleaks record[{idx}] missing or invalid 'File'.",
                    retryable=False,
                )
            )
            continue

        # Trường bắt buộc: StartLine
        start_line = record.get("StartLine")
        if not isinstance(start_line, int) or start_line <= 0 or isinstance(start_line, bool):
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_INVALID_FIELD"
                    if isinstance(start_line, int)
                    else "PARSE_RECORD_MISSING_FIELD",
                    safe_message=f"Gitleaks record[{idx}] missing or invalid 'StartLine'.",
                    retryable=False,
                )
            )
            continue

        # Trường tùy chọn: EndLine
        end_line_raw = record.get("EndLine")
        if end_line_raw is None:
            end_line = start_line
        elif isinstance(end_line_raw, int) and not isinstance(end_line_raw, bool) and end_line_raw >= start_line:
            end_line = end_line_raw
        else:
            end_line = start_line
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_INVALID_FIELD",
                    safe_message=f"Gitleaks record[{idx}] invalid 'EndLine', defaulted to StartLine.",
                    retryable=False,
                )
            )

        # Trường tùy chọn: Description
        desc = record.get("Description")
        if isinstance(desc, str) and desc.strip():
            rule_name: str | None = desc.strip()
            message = desc.strip()
        else:
            rule_name = None
            message = f"Gitleaks finding for rule {rule_id}"

        # Metadata allowlist: entropy, rule_description
        metadata: dict[str, Any] = {}
        if rule_name is not None:
            metadata["rule_description"] = rule_name

        entropy_raw = record.get("Entropy")
        if (
            isinstance(entropy_raw, (int, float))
            and not isinstance(entropy_raw, bool)
            and math.isfinite(entropy_raw)
        ):
            metadata["entropy"] = float(entropy_raw)

        # Finding ID xác định
        finding_id = _generate_finding_id(rule_id, file_path_str, start_line, end_line)

        # --- Ranh giới redact sớm cho Secret và Match ---
        raw_secret = record.get("Secret")
        raw_match = record.get("Match")

        if isinstance(raw_secret, str) and raw_secret.strip():
            if isinstance(raw_match, str):
                redaction_res = redact_exact_secret(raw_match, raw_secret)
                if redaction_res.replacements == 0:
                    errors.append(
                        ProcessingError(
                            finding_id=finding_id,
                            scanner=ScannerType.GITLEAKS,
                            stage=ProcessingStage.SANITIZE,
                            error_code="SANITIZE_SECRET_REDACTION_NO_MATCH",
                            safe_message=f"Gitleaks record[{idx}] secret value was not found in Match string; raw preview was discarded.",
                            retryable=False,
                        )
                    )
            else:
                errors.append(
                    ProcessingError(
                        finding_id=finding_id,
                        scanner=ScannerType.GITLEAKS,
                        stage=ProcessingStage.SANITIZE,
                        error_code="SANITIZE_SECRET_MATCH_MISSING",
                        safe_message=f"Gitleaks record[{idx}] Match string missing or invalid; raw preview was discarded.",
                        retryable=False,
                    )
                )
        else:
            errors.append(
                ProcessingError(
                    finding_id=finding_id,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.SANITIZE,
                    error_code="SANITIZE_SECRET_VALUE_MISSING",
                    safe_message=f"Gitleaks record[{idx}] Secret value missing or empty; raw preview was discarded.",
                    retryable=False,
                )
            )

        try:
            finding = NormalizedFinding(
                finding_instance_id=finding_id,
                scanner=ScannerType.GITLEAKS,
                finding_type=FindingType.SECRET,
                rule_id=rule_id,
                rule_name=rule_name,
                file_path=file_path_str,
                start_line=start_line,
                end_line=end_line,
                severity=Severity.UNKNOWN,
                message=message,
                metadata=metadata,
            )
            findings.append(finding)
        except ValueError:
            errors.append(
                ProcessingError(
                    finding_id=None,
                    scanner=ScannerType.GITLEAKS,
                    stage=ProcessingStage.PARSE,
                    error_code="PARSE_RECORD_INVALID_FIELD",
                    safe_message=f"Gitleaks record[{idx}] produced an invalid NormalizedFinding.",
                    retryable=False,
                )
            )

    return ScannerParseResult(
        findings=tuple(findings),
        errors=tuple(errors),
    )
