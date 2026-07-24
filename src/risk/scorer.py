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
        self.w_exp = weight_exploitability

    def calculate_risk_score(self, finding: UnifiedFinding) -> RiskScoreDetails:
        """Calculate Risk Score (1.0 to 5.0) using the Sprint 2 formula."""
        # 1. Base Severity Score (1-5)
        sev_score = SEVERITY_NUMERIC_MAP.get(finding.severity, 3.0)

        # 2. Reachability Score (1-5) based on context & guards
        reach_score = 4.0
        if finding.context and finding.context.enclosing_function:
            reach_score = 4.5
        if finding.logic_bug_trace and not finding.logic_bug_trace.has_authz_guard:
            reach_score = 5.0

        # 3. Exposure Score (1-5) based on file path (routes/controllers vs scripts/tests)
        path_lower = finding.file_path.lower()
        if "test" in path_lower or "seed" in path_lower or "script" in path_lower:
            exp_score = 1.5
        elif "routes" in path_lower or "controllers" in path_lower or "main" in path_lower or "api" in path_lower:
            exp_score = 4.5
        else:
            exp_score = 3.0

        # 4. Data Sensitivity Score (1-5)
        rule_lower = finding.rule_id.lower()
        if "secret" in rule_lower or "jwt" in rule_lower or "auth" in rule_lower or "password" in rule_lower or "sqli" in rule_lower:
            sens_score = 4.5
        else:
            sens_score = 3.0

        # 5. Exploitability Score (1-5)
        if finding.verdict == "TP" and (finding.confidence or 0) >= 0.8:
            exploit_score = 4.5
        else:
            exploit_score = 2.5

        # Weighted calculation
        overall = (
            self.w_sev * sev_score +
            self.w_reach * reach_score +
            0.20 * exp_score +
            0.20 * sens_score +
            self.w_exp * exploit_score
        )
        overall_clamped = round(max(1.0, min(5.0, overall)), 2)

        # Determine risk level
        if overall_clamped >= 4.2:
            risk_lvl = Severity.CRITICAL
        elif overall_clamped >= 3.4:
            risk_lvl = Severity.HIGH
        elif overall_clamped >= 2.5:
            risk_lvl = Severity.MEDIUM
        else:
            risk_lvl = Severity.LOW

        details = RiskScoreDetails(
            overall_score=overall_clamped,
            severity_score=sev_score,
            reachability_score=reach_score,
            exposure_score=exp_score,
            data_sensitivity_score=sens_score,
            exploitability_score=exploit_score,
            risk_level=risk_lvl
        )

        finding.risk_score = overall_clamped
        finding.risk_score_details = details
        return details

    def score_batch(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Calculate risk scores for a batch of findings."""
        for finding in findings:
            self.calculate_risk_score(finding)
        return findings
