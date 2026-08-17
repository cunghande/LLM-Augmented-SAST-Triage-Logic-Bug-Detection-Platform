"""Source-free internal contracts for Sprint 2 logic-bug candidates."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sast_triage.models import Severity


class LogicBugClass(str, Enum):
    """The five logic-bug classes required by the archived Sprint 2 plan."""

    MISSING_AUTHZ_IDOR = "missing_authz_idor"
    MASS_ASSIGNMENT = "mass_assignment"
    RACE_CONDITION_TOCTOU = "race_condition_toctou"
    BUSINESS_RULE_BYPASS = "business_rule_bypass"
    INSECURE_WORKFLOW = "insecure_workflow"


@dataclass(frozen=True, slots=True)
class LogicCandidate:
    """A source-free, reviewable AST candidate produced by the native index."""

    bug_class: LogicBugClass
    file_path: str
    component: str
    line: int
    end_line: int
    function: str
    entrypoint: bool
    source_kind: str
    sink_kind: str
    guards: tuple[str, ...]
    trace: tuple[str, ...]
    cwe: str
    severity: Severity
    risk_score: float
    risk_level: str
    risk_factors: tuple[tuple[str, float], ...]
    remediation: str
    validation_checklist: tuple[str, ...]
    analysis_complete: bool = True
