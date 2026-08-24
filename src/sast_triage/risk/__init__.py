"""Deterministic risk assessment for reportable triage results."""

from sast_triage.risk.scoring import RiskAssessment, assess_finding_risk

__all__ = ["RiskAssessment", "assess_finding_risk"]
