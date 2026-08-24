"""Tests for deterministic source-free risk scoring."""

from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
)
from sast_triage.risk.scoring import assess_finding_risk


def _context(path_category: PathCategory) -> SanitizedContext:
    return SanitizedContext(
        finding_id="risk-finding",
        sanitized_snippet="safe context",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=3,
        finding_start_line=2,
        finding_end_line=2,
        path_category=path_category,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )


def _finding(
    *,
    scanner: ScannerType = ScannerType.SEMGREP,
    finding_type: FindingType = FindingType.SAST,
    rule_id: str = "python.sql-injection",
    metadata: dict[str, object] | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="risk-finding",
        scanner=scanner,
        finding_type=finding_type,
        rule_id=rule_id,
        file_path="app/views.py",
        start_line=2,
        end_line=2,
        severity=Severity.HIGH,
        message="Safe scanner message.",
        metadata=metadata or {},
    )


def test_reachable_sql_finding_has_complete_deterministic_assessment() -> None:
    finding = _finding()
    evidence = {
        "source_reaches_sink": True,
        "complete": True,
        "sink": {"symbol": "execute", "file_path": "app/views.py", "line": 2},
    }

    first = assess_finding_risk(finding, _context(PathCategory.PRODUCTION), evidence)
    second = assess_finding_risk(finding, _context(PathCategory.PRODUCTION), evidence)

    assert first == second
    assert first.level in {"HIGH", "CRITICAL"}
    assert first.factors["reachability"] == 5.0
    assert "tham số hóa" in first.remediation
    assert len(first.validation_checklist) == 3


def test_test_secret_gets_lower_exposure_without_losing_sensitivity() -> None:
    finding = _finding(
        scanner=ScannerType.GITLEAKS,
        finding_type=FindingType.SECRET,
        rule_id="jwt",
    )

    assessment = assess_finding_risk(
        finding,
        _context(PathCategory.TEST),
        evidence=None,
    )

    assert assessment.factors["exposure"] == 1.5
    assert assessment.factors["data_sensitivity"] == 5.0
    assert "xoay vòng credential" in assessment.remediation


def test_complete_logic_detector_assessment_is_preserved() -> None:
    metadata: dict[str, object] = {
        "risk_score": 4.2,
        "risk_level": "CRITICAL",
        "risk_factors": {
            "severity": 4.0,
            "reachability": 5.0,
            "exposure": 4.5,
            "data_sensitivity": 4.5,
            "exploitability": 4.0,
        },
        "remediation": "Apply an object-level authorization guard.",
        "validation_checklist": ["Add an unauthorized-object regression test."],
    }
    finding = _finding(
        scanner=ScannerType.MODULE2,
        rule_id="module2.logic.missing-authz-idor",
        metadata=metadata,
    )

    assessment = assess_finding_risk(
        finding,
        _context(PathCategory.PRODUCTION),
        evidence=None,
    )

    assert assessment.score == 4.2
    assert assessment.remediation == metadata["remediation"]
