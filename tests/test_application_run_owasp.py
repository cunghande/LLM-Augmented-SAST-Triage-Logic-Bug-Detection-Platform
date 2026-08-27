"""Tests for automatic OWASP Benchmark run scoping."""

from pathlib import Path

from sast_triage.application.run import _resolve_owasp_expected_results


def test_expected_results_is_auto_detected_at_repository_root(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "BenchmarkPython"
    repository.mkdir()
    expected = repository / "expectedresults-0.1.csv"
    expected.write_text("safe fixture\n", encoding="utf-8")

    assert _resolve_owasp_expected_results(repository, None) == expected


def test_ambiguous_expected_results_requires_explicit_path(tmp_path: Path) -> None:
    repository = tmp_path / "BenchmarkPython"
    repository.mkdir()
    (repository / "expectedresults-0.1.csv").write_text("one\n", encoding="utf-8")
    (repository / "expectedresults-0.2.csv").write_text("two\n", encoding="utf-8")

    assert _resolve_owasp_expected_results(repository, None) is None


def test_relative_explicit_path_can_be_resolved_inside_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "BenchmarkPython"
    repository.mkdir()
    expected = repository / "truth.csv"
    expected.write_text("safe fixture\n", encoding="utf-8")

    assert _resolve_owasp_expected_results(repository, "truth.csv") == expected
