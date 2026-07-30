import unittest
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, BranchType, Severity, TriageVerdict, ContextQuality
from src.pipeline.parallel_pipeline import ParallelAnalysisPipeline


class TestParallelPipeline(unittest.TestCase):
    def test_pipeline_merger(self):
        pipeline = ParallelAnalysisPipeline()

        finding_a = UnifiedFinding(
            finding_id="SG-01",
            scanner=ScannerType.SEMGREP,
            branch_type=BranchType.SAST_TRIAGE_BRANCH,
            rule_id="semgrep.sqli",
            repository="CN_WEB",
            file_path="app.py",
            start_line=10,
            end_line=10,
            snippet="db.execute(query)"
        )

        finding_b = UnifiedFinding(
            finding_id="LB-01",
            scanner=ScannerType.LOGIC_BUG,
            branch_type=BranchType.LOGIC_BUG_BRANCH,
            rule_id="logic-bug.idor",
            repository="CN_WEB",
            file_path="routes/user.py",
            start_line=25,
            end_line=25,
            snippet="User.findById(req.params.id)"
        )

        merged = pipeline.merge_findings([finding_a], [finding_b])
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0].branch_type, BranchType.SAST_TRIAGE_BRANCH)
        self.assertEqual(merged[1].branch_type, BranchType.LOGIC_BUG_BRANCH)


if __name__ == "__main__":
    unittest.main()
