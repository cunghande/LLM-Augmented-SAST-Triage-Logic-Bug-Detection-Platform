"""SQLite-backed cache containing validated ``TriageDecision`` objects only."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from sast_triage.errors import SastTriageError
from sast_triage.models import TriageDecision

CACHE_VERSION = "triage-decision-cache-v1"
CACHE_FILENAME = "decisions.sqlite3"
_MAX_DECISION_BYTES = 64_000


@dataclass(frozen=True, slots=True)
class DecisionCacheKey:
    """Versioned safe facts that invalidate a cached LLM decision."""

    triage_input_digest: str
    provider_name: str
    model_version: str
    prompt_version: str
    output_schema_version: str
    policy_version: str
    risk_scoring_version: str

    def digest(self) -> str:
        """Return a stable SHA-256 key without storing the sanitized input."""
        payload = {
            "cache_version": CACHE_VERSION,
            "triage_input_digest": self.triage_input_digest,
            "provider_name": self.provider_name,
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "output_schema_version": self.output_schema_version,
            "policy_version": self.policy_version,
            "risk_scoring_version": self.risk_scoring_version,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class DecisionCache:
    """Persist validated decisions with TTL and source-free cache metadata."""

    def __init__(self, directory: Path, *, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise SastTriageError(
                "Decision cache TTL must be positive.",
                "DECISION_CACHE_INVALID_CONFIGURATION",
            )
        raw_directory = directory
        if raw_directory.exists() and raw_directory.is_symlink():
            raise SastTriageError(
                "Decision cache directory must not be a symlink.",
                "DECISION_CACHE_INVALID_CONFIGURATION",
            )
        try:
            raw_directory.mkdir(parents=True, exist_ok=True)
            resolved = raw_directory.resolve(strict=True)
        except OSError:
            raise SastTriageError(
                "Decision cache directory could not be created.",
                "DECISION_CACHE_WRITE_ERROR",
            ) from None
        if not resolved.is_dir():
            raise SastTriageError(
                "Decision cache path must be a directory.",
                "DECISION_CACHE_INVALID_CONFIGURATION",
            )
        self.directory = resolved
        self.path = resolved / CACHE_FILENAME
        if self.path.exists() and self.path.is_symlink():
            raise SastTriageError(
                "Decision cache database must not be a symlink.",
                "DECISION_CACHE_INVALID_CONFIGURATION",
            )
        self.ttl_seconds = ttl_seconds
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS decisions (
                        cache_key TEXT PRIMARY KEY,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        provider_name TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        prompt_version TEXT NOT NULL,
                        output_schema_version TEXT NOT NULL,
                        decision_json TEXT NOT NULL
                    )
                    """
                )
        except sqlite3.Error:
            raise SastTriageError(
                "Decision cache database could not be initialized.",
                "DECISION_CACHE_WRITE_ERROR",
            ) from None

    def get(
        self,
        identity: DecisionCacheKey,
        *,
        now: int | None = None,
    ) -> TriageDecision | None:
        """Return one unexpired schema-valid decision, otherwise a cache miss."""
        current = int(time.time()) if now is None else now
        key = identity.digest()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT expires_at, provider_name, model_version,
                           prompt_version, output_schema_version, decision_json
                    FROM decisions WHERE cache_key = ?
                    """,
                    (key,),
                ).fetchone()
                if row is None:
                    return None
                expires_at, provider, model, prompt, schema, raw_decision = row
                if expires_at <= current:
                    connection.execute(
                        "DELETE FROM decisions WHERE cache_key = ?", (key,)
                    )
                    return None
                if (
                    provider != identity.provider_name
                    or model != identity.model_version
                    or prompt != identity.prompt_version
                    or schema != identity.output_schema_version
                ):
                    return None
                try:
                    decision = TriageDecision.model_validate_json(raw_decision)
                except ValidationError:
                    connection.execute(
                        "DELETE FROM decisions WHERE cache_key = ?", (key,)
                    )
                    return None
        except sqlite3.Error:
            raise SastTriageError(
                "Decision cache database could not be read.",
                "DECISION_CACHE_READ_ERROR",
            ) from None
        if (
            decision.model_version != identity.model_version
            or decision.prompt_version != identity.prompt_version
        ):
            return None
        return decision

    def put(
        self,
        identity: DecisionCacheKey,
        decision: TriageDecision,
        *,
        forbidden_values: tuple[str, ...] = (),
        now: int | None = None,
    ) -> None:
        """Store a validated decision only after bounded leak checks."""
        if (
            decision.model_version != identity.model_version
            or decision.prompt_version != identity.prompt_version
        ):
            raise SastTriageError(
                "Decision cache identity does not match the validated decision.",
                "DECISION_CACHE_IDENTITY_MISMATCH",
            )
        decision_json = decision.model_dump_json()
        if len(decision_json.encode("utf-8")) > _MAX_DECISION_BYTES:
            raise SastTriageError(
                "Validated decision exceeds the cache size limit.",
                "DECISION_CACHE_ENTRY_TOO_LARGE",
            )
        if any(value and value in decision_json for value in forbidden_values):
            raise SastTriageError(
                "Validated decision contains a forbidden value and was not cached.",
                "DECISION_CACHE_LEAK_CHECK_FAILED",
            )
        created_at = int(time.time()) if now is None else now
        expires_at = created_at + self.ttl_seconds
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO decisions (
                        cache_key, created_at, expires_at, provider_name,
                        model_version, prompt_version, output_schema_version,
                        decision_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identity.digest(),
                        created_at,
                        expires_at,
                        identity.provider_name,
                        identity.model_version,
                        identity.prompt_version,
                        identity.output_schema_version,
                        decision_json,
                    ),
                )
        except sqlite3.Error:
            raise SastTriageError(
                "Decision cache database could not be written.",
                "DECISION_CACHE_WRITE_ERROR",
            ) from None

    def clear(self, *, expired_only: bool = False, now: int | None = None) -> int:
        """Delete rows from this cache database and return the affected count."""
        current = int(time.time()) if now is None else now
        try:
            with self._connect() as connection:
                if expired_only:
                    cursor = connection.execute(
                        "DELETE FROM decisions WHERE expires_at <= ?", (current,)
                    )
                else:
                    cursor = connection.execute("DELETE FROM decisions")
                return max(0, cursor.rowcount)
        except sqlite3.Error:
            raise SastTriageError(
                "Decision cache database could not be cleared.",
                "DECISION_CACHE_WRITE_ERROR",
            ) from None
