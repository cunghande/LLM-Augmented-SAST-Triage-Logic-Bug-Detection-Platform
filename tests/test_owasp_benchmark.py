"""Tests for category-aware OWASP Benchmark scoring."""

from pathlib import Path

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.evaluation.owasp_benchmark import (
    load_owasp_expected_results,
    score_owasp_findings,
    select_owasp_findings,
)
from sast_triage.models import FindingType, NormalizedFinding, ScannerType, Severity


def _finding(identifier: str, rule_id: str) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=identifier,
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        file_path=f"testcode/BenchmarkTest{identifier}.py",
        start_line=1,
        severity=Severity.HIGH,
        message="safe message",
    )


def test_owasp_scorer_requires_matching_test_and_category(tmp_path: Path) -> None:
    expected = tmp_path / "expected.csv"
    expected.write_text(
        "# test name,category,real vulnerability,cwe,Benchmark version: 0.1,2026-01-09\n"
        "BenchmarkTest00001,cmdi,true,78\n"
        "BenchmarkTest00002,cmdi,false,78\n"
        "BenchmarkTest00003,xss,true,79\n",
        encoding="utf-8",
    )
    dataset = load_owasp_expected_results(expected)
    findings = (
        _finding("00001", "python.audit.subprocess-shell-true"),
        _finding("00002", "python.audit.subprocess-shell-true"),
        _finding("00003", "python.security.use-defused-xml-parse"),
    )
    score = score_owasp_findings(dataset, findings)
    assert score.benchmark_version == "0.1"
    assert score.true_positive == 1
    assert score.false_positive == 1
    assert score.false_negative == 1
    assert score.true_negative == 0
    assert score.out_of_scope_findings == 1
    assert score.unique_reported_cases == 2
    assert score.precision == 0.5
    assert score.recall == 0.5
    assert score.f1 == 0.5


def test_owasp_loader_fails_closed_on_invalid_or_duplicate_rows(tmp_path: Path) -> None:
    expected = tmp_path / "expected.csv"
    expected.write_text("not an OWASP header\n", encoding="utf-8")
    with pytest.raises(SastTriageError):
        load_owasp_expected_results(expected)

    expected.write_text(
        "# test name,category,real vulnerability,cwe,Benchmark version: 0.1\n"
        "BenchmarkTest00001,cmdi,true,78\n"
        "BenchmarkTest00001,cmdi,false,78\n",
        encoding="utf-8",
    )
    with pytest.raises(SastTriageError) as exc_info:
        load_owasp_expected_results(expected)
    assert exc_info.value.error_code == "BENCHMARK_DUPLICATE_RECORD"


def test_owasp_selection_deduplicates_and_preserves_label_mix(
    tmp_path: Path,
) -> None:
    expected = tmp_path / "expected.csv"
    rows = [
        f"BenchmarkTest{number:05d},cmdi,{'true' if number <= 4 else 'false'},78"
        for number in range(1, 7)
    ]
    expected.write_text(
        "# test name,category,real vulnerability,cwe,Benchmark version: 0.1\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )
    dataset = load_owasp_expected_results(expected)
    findings = tuple(
        _finding(f"{number:05d}", "python.audit.subprocess-shell-true")
        for number in range(1, 7)
    ) + (
        _finding("00001", "python.lang.security.dangerous-subprocess-use"),
        _finding("99999", "python.audit.subprocess-shell-true"),
    )

    selection = select_owasp_findings(dataset, findings, max_findings=5)

    assert len(selection.findings) == 5
    assert selection.matched_findings == 7
    assert selection.unique_matched_cases == 6
    assert selection.duplicate_findings == 1
    assert selection.out_of_scope_findings == 1
    assert selection.vulnerable_cases == 3
    assert selection.benign_cases == 2
    assert selection.truncated_cases == 1


@pytest.mark.parametrize("limit", [0, 101])
def test_owasp_selection_rejects_limits_outside_safe_range(
    tmp_path: Path,
    limit: int,
) -> None:
    expected = tmp_path / "expected.csv"
    expected.write_text(
        "# test name,category,real vulnerability,cwe,Benchmark version: 0.1\n"
        "BenchmarkTest00001,cmdi,true,78\n",
        encoding="utf-8",
    )
    dataset = load_owasp_expected_results(expected)

    with pytest.raises(SastTriageError) as exc_info:
        select_owasp_findings(
            dataset,
            (_finding("00001", "python.audit.subprocess-shell-true"),),
            max_findings=limit,
        )

    assert exc_info.value.error_code == "BENCHMARK_LIMIT_INVALID"
