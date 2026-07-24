import unittest
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, Severity, TriageVerdict, ActionGroup
from src.triage.engine import TriageEngine
from src.triage.llm_client import LLMClient


class DummyLLMClient(LLMClient):
    def __init__(self, verdict="TP", confidence=0.9):
        super().__init__()
        self.verdict = verdict
        self.confidence = confidence

    def call_chat_completion(self, system_prompt, user_prompt):
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": "Mocked test verdict",
            "evidence": ["Evidence 1"]
        }


class TestTriageEngine(unittest.TestCase):
    def test_triage_engine_routing(self):
        finding = UnifiedFinding(
            finding_id="TEST-001",
            scanner=ScannerType.SEMGREP,
            rule_id="jwt-secret",
            repository="CN_WEB",
            file_path="backend/src/config/jwt.js",
            start_line=15,
            end_line=15,
            snippet="const secret = 'dev_secret';",
            severity=Severity.HIGH
        )

        dummy_client = DummyLLMClient(verdict="TP", confidence=0.95)
        engine = TriageEngine(llm_client=dummy_client)
        
        triaged = engine.triage_finding(finding, Path("."))
        self.assertEqual(triaged.verdict, TriageVerdict.TRUE_POSITIVE)
        self.assertEqual(triaged.confidence, 0.95)
        self.assertEqual(triaged.action_group, ActionGroup.HIGH_CONFIDENCE_TP)


if __name__ == "__main__":
    unittest.main()
