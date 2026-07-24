import unittest
from src.core.schema import UnifiedFinding, ScannerType, Severity, TriageVerdict
from src.risk.scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):
    def test_risk_scorer_calculation(self):
        finding = UnifiedFinding(
            finding_id="TEST-RISK-01",
            scanner=ScannerType.SEMGREP,
            rule_id="dockerfile.security.missing-user.missing-user",
            repository="CN_WEB",
            file_path="backend/Dockerfile",
            start_line=13,
            end_line=13,
            snippet="CMD ['npm', 'start']",
            severity=Severity.HIGH,
            verdict=TriageVerdict.TRUE_POSITIVE,
            confidence=0.95
        )

        scorer = RiskScorer()
        details = scorer.calculate_risk_score(finding)

        self.assertGreaterEqual(details.overall_score, 1.0)
        self.assertLessEqual(details.overall_score, 5.0)
        self.assertIsNotNone(finding.risk_score)
        print(f"\n[Test] Risk Score calculated: {details.overall_score} (Level: {details.risk_level.value})")


if __name__ == "__main__":
    unittest.main()
