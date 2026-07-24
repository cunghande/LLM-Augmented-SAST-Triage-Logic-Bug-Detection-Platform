import unittest
from src.core.schema import UnifiedFinding, ScannerType, Severity, TriageVerdict
from src.remediation.generator import RemediationGenerator


class TestRemediationGenerator(unittest.TestCase):
    def test_remediation_generator_dockerfile(self):
        finding = UnifiedFinding(
            finding_id="TEST-PATCH-01",
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

        gen = RemediationGenerator()
        patch = gen.generate_patch(finding)

        self.assertIn("USER appuser", patch.code_diff)
        self.assertIsNotNone(finding.remediation_patch)
        print("\n[Test] Remediation Patch Diff generated:\n", patch.code_diff)


if __name__ == "__main__":
    unittest.main()
