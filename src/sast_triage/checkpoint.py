"""Checkpoint tiến độ triage an toàn để resume bằng provider khác."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from pydantic import ValidationError

from sast_triage.errors import SastTriageError
from sast_triage.models import NormalizedFinding, TriageResult

CHECKPOINT_VERSION = "triage-checkpoint-v1"
CHECKPOINT_FILENAME = "triage-checkpoint.json"
_REPLACE_ATTEMPTS = 8
_REPLACE_INITIAL_DELAY_SECONDS = 0.05


def _replace_with_retry(source: Path, destination: Path) -> None:
    """Replace a checkpoint despite short-lived Windows file-sharing locks."""
    delay = _REPLACE_INITIAL_DELAY_SECONDS
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.4)


@dataclass(frozen=True, slots=True)
class CheckpointLoadResult:
    """Kết quả checkpoint nội bộ đã được bind với artifact hiện tại."""

    results: tuple[TriageResult, ...]
    provider_history: tuple[tuple[str, str | None], ...]
    status: str
    failure_code: str | None


def _safe_result_projection(result: TriageResult) -> dict[str, Any]:
    """Chiếu TriageResult mà không lưu snippet, source, prompt hay response thô."""
    return {
        "finding_id": result.finding.finding_instance_id,
        "context_summary": result.context_summary,
        "triage_decision": (
            result.triage_decision.model_dump(mode="json")
            if result.triage_decision is not None
            else None
        ),
        "policy_decision": result.policy_decision.model_dump(mode="json"),
        "processing_errors": [
            error.model_dump(mode="json") for error in result.processing_errors
        ],
        "processed_at": result.processed_at.isoformat(),
        "processing_duration_ms": result.processing_duration_ms,
    }


class TriageCheckpointStore:
    """Ghi và đọc checkpoint atomic, fail-closed theo artifact và finding manifest."""

    def __init__(
        self,
        path: Path,
        *,
        repository_identifier: str,
        artifact_hashes: dict[str, str | None],
        finding_ids: tuple[str, ...],
        prompt_version: str,
        output_schema_version: str,
        analysis_backend: str = "native",
        analysis_backend_version: str | None = None,
        analysis_config_id: str | None = None,
    ) -> None:
        self.path = path
        self.repository_identifier = repository_identifier
        self.artifact_hashes = dict(sorted(artifact_hashes.items()))
        self.finding_ids = finding_ids
        self.prompt_version = prompt_version
        self.output_schema_version = output_schema_version
        self.analysis_backend = analysis_backend
        self.analysis_backend_version = analysis_backend_version
        self.analysis_config_id = analysis_config_id

    def load(self, findings: tuple[NormalizedFinding, ...]) -> CheckpointLoadResult:
        """Khôi phục các result đã xong bằng finding hiện tại từ parser."""
        if not self.path.is_file():
            raise SastTriageError(
                "Resume checkpoint does not exist.",
                "CHECKPOINT_NOT_FOUND",
            )
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise SastTriageError(
                "Resume checkpoint could not be read safely.",
                "CHECKPOINT_INVALID",
            ) from None
        if not isinstance(payload, dict):
            raise SastTriageError(
                "Resume checkpoint root is invalid.",
                "CHECKPOINT_INVALID",
            )
        expected_binding = {
            "version": CHECKPOINT_VERSION,
            "repository_identifier": self.repository_identifier,
            "artifact_hashes": self.artifact_hashes,
            "finding_ids": list(self.finding_ids),
            "prompt_version": self.prompt_version,
            "output_schema_version": self.output_schema_version,
            "analysis_backend": self.analysis_backend,
            "analysis_backend_version": self.analysis_backend_version,
            "analysis_config_id": self.analysis_config_id,
        }
        for key, expected in expected_binding.items():
            if payload.get(key) != expected:
                raise SastTriageError(
                    "Resume checkpoint does not match the current repository artifacts or prompt contract.",
                    "CHECKPOINT_BINDING_MISMATCH",
                )

        finding_by_id = {finding.finding_instance_id: finding for finding in findings}
        raw_results = payload.get("completed_results", [])
        raw_history = payload.get("provider_history", [])
        if not isinstance(raw_results, list) or not isinstance(raw_history, list):
            raise SastTriageError(
                "Resume checkpoint collections are invalid.",
                "CHECKPOINT_INVALID",
            )

        restored: list[TriageResult] = []
        seen: set[str] = set()
        try:
            for raw in raw_results:
                if not isinstance(raw, dict):
                    raise TypeError
                finding_id = raw.get("finding_id")
                if not isinstance(finding_id, str) or finding_id in seen:
                    raise ValueError
                finding = finding_by_id.get(finding_id)
                if finding is None:
                    raise ValueError
                seen.add(finding_id)
                restored.append(
                    TriageResult.model_validate(
                        {
                            "finding": finding,
                            "context_summary": raw.get("context_summary"),
                            "triage_decision": raw.get("triage_decision"),
                            "policy_decision": raw.get("policy_decision"),
                            "processing_errors": raw.get("processing_errors", []),
                            "processed_at": raw.get("processed_at"),
                            "processing_duration_ms": raw.get("processing_duration_ms"),
                        }
                    )
                )
        except (ValidationError, ValueError, TypeError):
            raise SastTriageError(
                "Resume checkpoint contains an invalid completed result.",
                "CHECKPOINT_INVALID",
            ) from None

        history: list[tuple[str, str | None]] = []
        for item in raw_history:
            if not isinstance(item, dict):
                raise SastTriageError(
                    "Resume checkpoint provider history is invalid.",
                    "CHECKPOINT_INVALID",
                )
            name = item.get("provider")
            model = item.get("model")
            if not isinstance(name, str) or not name.strip() or (
                model is not None and not isinstance(model, str)
            ):
                raise SastTriageError(
                    "Resume checkpoint provider history is invalid.",
                    "CHECKPOINT_INVALID",
                )
            history.append((name, model))

        status = payload.get("status", "in_progress")
        failure_code = payload.get("failure_code")
        if status not in {"in_progress", "resource_exhausted", "complete"} or (
            failure_code is not None and not isinstance(failure_code, str)
        ):
            raise SastTriageError(
                "Resume checkpoint status is invalid.",
                "CHECKPOINT_INVALID",
            )
        return CheckpointLoadResult(
            results=tuple(restored),
            provider_history=tuple(history),
            status=status,
            failure_code=failure_code,
        )

    def save(
        self,
        results: tuple[TriageResult, ...],
        *,
        provider_history: tuple[tuple[str, str | None], ...],
        status: str = "in_progress",
        failure_code: str | None = None,
    ) -> None:
        """Ghi snapshot tiến độ hiện tại theo cơ chế atomic."""
        if status not in {"in_progress", "resource_exhausted", "complete"}:
            raise SastTriageError("Checkpoint status is invalid.", "CHECKPOINT_INVALID")
        payload = {
            "version": CHECKPOINT_VERSION,
            "repository_identifier": self.repository_identifier,
            "artifact_hashes": self.artifact_hashes,
            "finding_ids": list(self.finding_ids),
            "prompt_version": self.prompt_version,
            "output_schema_version": self.output_schema_version,
            "analysis_backend": self.analysis_backend,
            "analysis_backend_version": self.analysis_backend_version,
            "analysis_config_id": self.analysis_config_id,
            "status": status,
            "failure_code": failure_code,
            "completed_count": len(results),
            "total_count": len(self.finding_ids),
            "provider_history": [
                {"provider": name, "model": model}
                for name, model in provider_history
            ],
            "completed_results": [_safe_result_projection(result) for result in results],
        }
        temporary: Path | None = None
        try:
            with NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            _replace_with_retry(temporary, self.path)
            temporary = None
        except OSError:
            raise SastTriageError(
                "Triage checkpoint could not be written.",
                "CHECKPOINT_WRITE_ERROR",
            ) from None
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def clear(self) -> None:
        """Xóa checkpoint sau khi tất cả report đã ghi thành công."""
        if not self.path.exists():
            return
        try:
            self.path.unlink()
        except OSError:
            raise SastTriageError(
                "Completed triage checkpoint could not be removed.",
                "CHECKPOINT_WRITE_ERROR",
            ) from None


def read_checkpoint_summary(path: Path) -> dict[str, object] | None:
    """Đọc allowlist trạng thái checkpoint để entrypoint hiển thị an toàn."""
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return {
        "status": payload.get("status"),
        "failure_code": payload.get("failure_code"),
        "completed_count": payload.get("completed_count"),
        "total_count": payload.get("total_count"),
    }
