import unittest
import tempfile
import json
from pathlib import Path
from src.core.schema import (
    UnifiedFinding,
    ScannerType,
    ScanState,
    ScanManifest,
    CoverageReport,
    TriageVerdict,
    ActionGroup,
    PatchStatus,
)
from src.context.context_policy import GuardRequirementPolicy
from src.pipeline.stage_compare import CompareStageRunner
from src.pipeline.stage_patch import PatchStageRunner
from src.reporters.storage import ExternalStorageManager


class TestCodexPrinciples(unittest.TestCase):
    def test_guard_requirement_policy_loader(self):
        policy = GuardRequirementPolicy()
        ev = policy.get_guard_evidence_for_route("/api/user/123", "db.query")
        self.assertIsNotNone(ev)
        self.assertIn("system_exposure", ev)
        self.assertGreaterEqual(ev["policy_count"], 0)

    def test_stage_compare_correlation_state_machine(self):
        comparator = CompareStageRunner()

        finding_old = UnifiedFinding(
            finding_id="F-01",
            scanner=ScannerType.SEMGREP,
            rule_id="rule.a",
            repository="CN_WEB",
            file_path="src/main.py",
            start_line=10,
            end_line=10,
            snippet="x = 1"
        )
        finding_old.compute_fingerprint()

        finding_new_same = UnifiedFinding(
            finding_id="F-01",
            scanner=ScannerType.SEMGREP,
            rule_id="rule.a",
            repository="CN_WEB",
            file_path="src/main.py",
            start_line=10,
            end_line=10,
            snippet="x = 1"
        )
        finding_new_same.compute_fingerprint()

        finding_brand_new = UnifiedFinding(
            finding_id="F-02",
            scanner=ScannerType.SEMGREP,
            rule_id="rule.b",
            repository="CN_WEB",
            file_path="src/app.py",
            start_line=20,
            end_line=20,
            snippet="y = 2"
        )
        finding_brand_new.compute_fingerprint()

        correlated, summary = comparator.run_stage_compare(
            [finding_new_same, finding_brand_new],
            [finding_old]
        )

        self.assertEqual(summary["EXISTING"], 1)
        self.assertEqual(summary["NEW"], 1)
        self.assertEqual(summary["FIXED"], 0)

    def test_stage_patch_selected_only(self):
        patcher = PatchStageRunner()
        finding_unvalidated = UnifiedFinding(
            finding_id="F-UNVALIDATED",
            scanner=ScannerType.SEMGREP,
            rule_id="semgrep.rule",
            repository="CN_WEB",
            file_path="app.py",
            start_line=5,
            end_line=5,
            snippet="dummy()",
            verdict=TriageVerdict.NEEDS_REVIEW
        )

        patcher.run_stage_patch([finding_unvalidated], Path("/tmp"))
        self.assertIsNone(finding_unvalidated.remediation_patch)

    def test_external_storage_permissions(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mgr = ExternalStorageManager(storage_root=tmp_dir)
            run_dir = mgr.get_run_dir("TEST_REPO", "run-1")
            self.assertTrue(run_dir.exists())

            manifest = ScanManifest(
                manifest_id="M-01",
                repository="TEST_REPO",
                commit_sha="1234567890123456789012345678901234567890"
            )
            saved_file = mgr.save_scan_manifest(manifest, run_dir)
            self.assertTrue(saved_file.exists())


if __name__ == "__main__":
    unittest.main()
