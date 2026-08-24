"""Security and integration tests for validated LLM decision caching."""

import time
from pathlib import Path

import pytest

from sast_triage.cache.decision_cache import DecisionCache, DecisionCacheKey
from sast_triage.cli import EXIT_SUCCESS, main
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    ScannerParseResult,
    ScannerType,
    Severity,
    TriageDecision,
    TriageInput,
)
from sast_triage.pipeline.batch import triage_batch


def _identity(**changes: str) -> DecisionCacheKey:
    values = {
        "triage_input_digest": "a" * 64,
        "provider_name": "counting",
        "model_version": "model-v1",
        "prompt_version": "prompt-v1",
        "output_schema_version": "schema-v1",
        "policy_version": "policy-v1",
        "risk_scoring_version": "risk-v1",
    }
    values.update(changes)
    return DecisionCacheKey(**values)


def _decision() -> TriageDecision:
    return TriageDecision(
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Validated safe summary.",
        evidence=["Validated safe evidence."],
        model_version="model-v1",
        prompt_version="prompt-v1",
    )


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="cache-finding",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.sql-injection",
        file_path="app.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        message="Potential SQL injection.",
    )


def test_cache_round_trip_and_version_invalidation(tmp_path: Path) -> None:
    cache = DecisionCache(tmp_path / "cache", ttl_seconds=60)
    identity = _identity()

    cache.put(identity, _decision(), now=100)

    assert cache.get(identity, now=101) == _decision()
    assert cache.get(_identity(prompt_version="prompt-v2"), now=101) is None
    database_text = cache.path.read_bytes()
    assert b"Validated safe summary" in database_text
    assert b"raw_source" not in database_text
    assert b"prompt_raw" not in database_text


def test_expired_entry_becomes_miss_and_can_be_pruned(tmp_path: Path) -> None:
    cache = DecisionCache(tmp_path / "cache", ttl_seconds=10)
    cache.put(_identity(), _decision(), now=100)

    assert cache.get(_identity(), now=110) is None
    assert cache.clear(expired_only=True, now=111) == 0


def test_cache_rejects_forbidden_value(tmp_path: Path) -> None:
    cache = DecisionCache(tmp_path / "cache", ttl_seconds=60)

    with pytest.raises(SastTriageError) as raised:
        cache.put(
            _identity(),
            _decision(),
            forbidden_values=("Validated safe summary",),
        )

    assert raised.value.error_code == "DECISION_CACHE_LEAK_CHECK_FAILED"
    assert cache.get(_identity()) is None


def test_batch_second_run_uses_cache_without_calling_provider(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args.get('q')\n", encoding="utf-8")
    cache = DecisionCache(tmp_path / "cache", ttl_seconds=60)

    class CountingProvider:
        provider_name = "counting"
        model_version = "model-v1"

        def __init__(self) -> None:
            self.calls = 0

        def triage(self, triage_input: TriageInput) -> TriageDecision:
            self.calls += 1
            time.sleep(0.002)
            return TriageDecision(
                model_verdict=ModelVerdict.LIKELY_TP,
                model_confidence=ModelConfidence.HIGH,
                summary="Validated safe summary.",
                evidence=["Validated safe evidence."],
                model_version=self.model_version,
                prompt_version=triage_input.prompt_version,
            )

    provider = CountingProvider()
    scanner_result = ScannerParseResult(findings=(_finding(),))
    common = {
        "semgrep_result": scanner_result,
        "repository_identifier": "repo",
        "prompt_version": "prompt-v1",
        "output_schema_version": "schema-v1",
        "decision_cache": cache,
        "provider_cost_per_hour_usd": 3.6,
    }

    first = triage_batch(repo, provider, **common)
    second = triage_batch(repo, provider, **common)

    assert provider.calls == 1
    assert first.results[0].decision_cache_status == "MISS"
    assert second.results[0].decision_cache_status == "HIT"
    assert second.results[0].cache_hit is True
    assert second.results[0].provider_duration_ms == 0
    assert second.results[0].estimated_cost_usd == 0.0
    assert first.run_metadata.decision_cache_misses == 1
    assert second.run_metadata.decision_cache_hits == 1
    assert second.run_metadata.provider_input_tokens == 0
    assert second.run_metadata.provider_output_tokens == 0


def test_cache_clear_cli_removes_only_cache_rows(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    cache = DecisionCache(directory, ttl_seconds=60)
    cache.put(_identity(), _decision())
    marker = directory / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    exit_code = main(["cache-clear", "--cache-dir", str(directory)])

    assert exit_code == EXIT_SUCCESS
    assert cache.get(_identity()) is None
    assert marker.read_text(encoding="utf-8") == "keep"
