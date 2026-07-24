import json
import unittest
from src.parsers.gitleaks import parse_gitleaks_json
from src.parsers.semgrep import parse_semgrep_json
from src.core.schema import ScannerType, Severity


class TestParsers(unittest.TestCase):
    def test_parse_gitleaks_json(self):
        sample_gitleaks = [
            {
                "RuleID": "jwt-secret",
                "Description": "JWT Secret hardcoded",
                "StartLine": 15,
                "EndLine": 15,
                "Match": "const secret = 'dev_secret';",
                "File": "backend/src/config/jwt.js",
                "Commit": "abc1234",
                "Entropy": 3.8
            }
        ]
        findings = parse_gitleaks_json(json.dumps(sample_gitleaks), "CN_WEB")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.scanner, ScannerType.GITLEAKS)
        self.assertEqual(f.rule_id, "jwt-secret")
        self.assertEqual(f.file_path, "backend/src/config/jwt.js")
        self.assertEqual(f.start_line, 15)
        self.assertIsNotNone(f.fingerprint)

    def test_parse_semgrep_json(self):
        sample_semgrep = {
            "results": [
                {
                    "check_id": "javascript.express.security.audit.cors-permissive",
                    "path": "backend/server.js",
                    "start": {"line": 20, "col": 1},
                    "end": {"line": 20, "col": 15},
                    "extra": {
                        "message": "Permissive CORS policy",
                        "lines": "app.use(cors());",
                        "severity": "WARNING"
                    }
                }
            ]
        }
        findings = parse_semgrep_json(json.dumps(sample_semgrep), "CN_WEB")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.scanner, ScannerType.SEMGREP)
        self.assertEqual(f.rule_id, "javascript.express.security.audit.cors-permissive")
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.assertEqual(f.start_line, 20)


if __name__ == "__main__":
    unittest.main()
