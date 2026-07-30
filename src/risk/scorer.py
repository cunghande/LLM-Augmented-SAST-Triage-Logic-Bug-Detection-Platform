"""
Risk Scoring Engine Module
==========================
Calculates normalized 0-100 risk scores based on explicit 1-5 component rubrics.
Guarantees that LLM decision confidence never artificially reduces high-impact risk.
"""

from typing import List
from src.core.schema import (
    UnifiedFinding,
    Severity,
    RiskScoreDetails,
)


SEVERITY_NUMERIC_MAP = {
    Severity.CRITICAL: 5.0,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}


class RiskScorer:
    """
    Calculates risk score on a 0-100 rubric scale.
    Component Weights:
      - Technical Severity: 25%
      - Reachability: 25%
      - Exposure: 20%
      - Data Sensitivity: 20%
      - Exploitability: 10%
    """

    def __init__(
        self,
        weight_severity: float = 0.25,
        weight_reachability: float = 0.25,
        weight_exposure: float = 0.20,
        weight_sensitivity: float = 0.20,
        weight_exploitability: float = 0.10,
    ):
        self.w_sev = weight_severity
        self.w_reach = weight_reachability
        self.w_exp = weight_exposure
        self.w_sens = weight_sensitivity
        self.w_exploit = weight_exploitability

    def calculate_risk_score(self, finding: UnifiedFinding) -> RiskScoreDetails:
        """Calculate Risk Score on a normalized 0-100 scale."""
        # 1. Base Severity Score (1-5)
        sev_score = SEVERITY_NUMERIC_MAP.get(finding.severity, 3.0)

        # 2. Reachability Score (1-5)
        reach_score = 3.0
        if finding.context and finding.context.enclosing_function:
            reach_score = 4.0
        if finding.security_context_graph and not finding.security_context_graph.has_auth_guard:
            reach_score = 5.0

        # 3. Exposure Score (1-5)
        path_lower = finding.file_path.lower()
        if any(k in path_lower for k in ["test", "mock", "fixture", "spec"]):
            exp_score = 1.0
        elif any(k in path_lower for k in ["routes", "controllers", "api", "app", "main"]):
            exp_score = 4.5
        else:
            exp_score = 3.0

        # 4. Data Sensitivity Score (1-5)
        rule_lower = finding.rule_id.lower()
        if any(k in rule_lower for k in ["secret", "jwt", "auth", "password", "sqli", "idor", "authz"]):
            sens_score = 4.5
        else:
            sens_score = 3.0

        # 5. Exploitability Score (1-5)
        # Note: Do NOT let low decision_score penalize exploitability of high severity findings
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            exploit_score = 4.5
        else:
            exploit_score = 3.0

        # Weighted raw score (1.0 - 5.0)
        raw_weighted = (
            self.w_sev * sev_score +
            self.w_reach * reach_score +
            self.w_exp * exp_score +
            self.w_sens * sens_score +
            self.w_exploit * exploit_score
        )

        # Normalize 1-5 raw score onto exact 0 - 100 scale
        normalized_0_100 = round(((raw_weighted - 1.0) / 4.0) * 100.0, 2)

        # Determine risk level
        if normalized_0_100 >= 80.0:
            risk_lvl = Severity.CRITICAL
        elif normalized_0_100 >= 60.0:
            risk_lvl = Severity.HIGH
        elif normalized_0_100 >= 35.0:
            risk_lvl = Severity.MEDIUM
        else:
            risk_lvl = Severity.LOW

        details = RiskScoreDetails(
            overall_score=normalized_0_100,
            severity_score=sev_score,
            reachability_score=reach_score,
            exposure_score=exp_score,
            data_sensitivity_score=sens_score,
            exploitability_score=exploit_score,
            risk_level=risk_lvl
        )

        finding.risk_score = normalized_0_100
        finding.risk_score_details = details
        return details

    def score_finding(self, finding: UnifiedFinding) -> RiskScoreDetails:
        """Alias for calculate_risk_score."""
        return self.calculate_risk_score(finding)

    def score_batch(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Calculate risk scores for a batch of findings."""
        for finding in findings:
            self.calculate_risk_score(finding)
        return findings
