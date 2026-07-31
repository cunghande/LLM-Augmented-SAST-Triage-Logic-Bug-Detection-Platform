"""
Unit and Integration Tests for Benchmark Evaluation Framework (Metric 2.0 Audit-Ready)
========================================================================================
Tests exact numerical formulas, N/A semantics, null metric JSON serialization,
path validation, fail-closed LLM client, and mathematical report invariants.
"""

import os
import tempfile
import unittest
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, Severity, TriageVerdict, EvaluationOutcome, FailureCategory
from src.benchmark.adapters import AdapterMatchReport, MatchedSample, MatchType, UnmatchedSample
from src.benchmark.evaluator import BenchmarkEvaluator, normalize_verdict_str, LatencyBreakdown, EvaluationRun, StructuredMetric
from src.benchmark.reporter import BenchmarkReportGenerator, validate_artifact_path
from src.triage.llm_client import LLMClient, LLMExecutionException
from src.context.extractor import OWASPPythonBenchmarkIndex, extract_finding_context


class TestBenchmarkEvaluator(unittest.TestCase):

    def _create_finding(self, fid: str, verdict: Optional[TriageVerdict] = None, outcome: Optional[EvaluationOutcome] = None) -> UnifiedFinding:
        return UnifiedFinding(
            finding_id=fid,
            scanner=ScannerType.SEMGREP,
            rule_id="rule-1",
            repository="TEST_REPO",
            file_path="test.py",
            start_line=10,
            end_line=10,
            snippet="test()",
            severity=Severity.HIGH,
            verdict=verdict,
            outcome=outcome
        )

    def test_verdict_normalization(self):
        self.assertEqual(normalize_verdict_str("TRIAGED_TP"), "TP")
        self.assertEqual(normalize_verdict_str("TRIAGED_FP"), "FP")
        self.assertEqual(normalize_verdict_str("TP"), "TP")
        self.assertEqual(normalize_verdict_str("FP"), "FP")
        self.assertEqual(normalize_verdict_str(TriageVerdict.NEEDS_REVIEW), "NEEDS_REVIEW")
        self.assertEqual(normalize_verdict_str(TriageVerdict.NEEDS_MORE_CONTEXT), "NEEDS_MORE_CONTEXT")
        self.assertIsNone(normalize_verdict_str(None))

    def test_needs_review_does_not_increase_accuracy(self):
        """NEEDS_REVIEW must not be counted into accuracy."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t.py",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE, EvaluationOutcome.DECIDED)
            ),
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t.py",
                ground_truth_label="TP", source_ground_truth_id="2",
                finding=self._create_finding("2", TriageVerdict.NEEDS_REVIEW, EvaluationOutcome.ABSTAINED)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=2, matched_count=2, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 2)
        self.assertEqual(metrics.tp, 1)
        self.assertEqual(metrics.tp_abstained, 1)
        self.assertEqual(metrics.selective_accuracy.value, 1.0)
        self.assertEqual(metrics.decision_coverage.value, 0.5)

    def test_null_metric_has_reason(self):
        """Every undefined metric must have status UNDEFINED, value None, and a non-empty reason."""
        evaluator = BenchmarkEvaluator()
        # Report with 0 matched findings
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=0, matched_count=0, unmatched_count=0,
            matched_samples=[], adapter_status="ADAPTER_FAILURE"
        )
        metrics = evaluator.evaluate_matched_samples(report, 0)
        self.assertEqual(metrics.precision.status, "UNDEFINED")
        self.assertIsNone(metrics.precision.value)
        self.assertTrue(len(metrics.precision.reason) > 0)

    def test_java_zero_fp_correct_fp_suppression_is_null(self):
        """When ground_truth_fp is 0 (Java subset), correct_fp_suppression_rate must be null with reason."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="java", repo_id="r1", normalized_file_path="t.java",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE, EvaluationOutcome.DECIDED)
            )
        ]
        report = AdapterMatchReport(
            benchmark_name="java", total_findings=1, matched_count=1, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 1)
        self.assertEqual(metrics.ground_truth_fp, 0)
        self.assertEqual(metrics.correct_fp_suppression_rate.status, "UNDEFINED")
        self.assertIsNone(metrics.correct_fp_suppression_rate.value)
        self.assertIn("no ground-truth FP", metrics.correct_fp_suppression_rate.reason)

    def test_metric_invariants_pass(self):
        """Test mathematical report invariants hold on synthetic dataset."""
        evaluator = BenchmarkEvaluator()
        samples = [
            # 2 GT TP: 1 TP, 1 FN
            MatchedSample(benchmark_name="t", repo_id="r", normalized_file_path="a", ground_truth_label="TP", source_ground_truth_id="1", finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE, EvaluationOutcome.DECIDED)),
            MatchedSample(benchmark_name="t", repo_id="r", normalized_file_path="a", ground_truth_label="TP", source_ground_truth_id="2", finding=self._create_finding("2", TriageVerdict.FALSE_POSITIVE, EvaluationOutcome.DECIDED)),
            # 2 GT FP: 1 TN, 1 FP
            MatchedSample(benchmark_name="t", repo_id="r", normalized_file_path="a", ground_truth_label="FP", source_ground_truth_id="3", finding=self._create_finding("3", TriageVerdict.FALSE_POSITIVE, EvaluationOutcome.DECIDED)),
            MatchedSample(benchmark_name="t", repo_id="r", normalized_file_path="a", ground_truth_label="FP", source_ground_truth_id="4", finding=self._create_finding("4", TriageVerdict.TRUE_POSITIVE, EvaluationOutcome.DECIDED)),
        ]
        report = AdapterMatchReport(
            benchmark_name="t", total_findings=4, matched_count=4, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 4)
        self.assertTrue(metrics.invariants_passed)
        self.assertEqual(metrics.evaluation_status, "OK")

    def test_real_mode_rejects_mock(self):
        """In fail-closed REAL mode, mock mode must be disabled."""
        client = LLMClient(fail_closed=True)
        self.assertFalse(client.mock_mode)
        self.assertTrue(client.fail_closed)

    def test_ollama_unavailable_creates_failure(self):
        """When Ollama endpoint is down in fail-closed REAL mode, call must return EvaluationOutcome.FAILED."""
        client = LLMClient(api_base="http://localhost:9999", fail_closed=True)
        resp = client.call_chat_completion("sys", "user")
        self.assertEqual(resp["outcome"], "FAILED")
        self.assertEqual(resp["failure_category"], "LLM_UNAVAILABLE")

    def test_artifact_path_in_git_root_rejected(self):
        """Path inside Git worktree must be rejected with ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            git_dir = tmp_path / ".git"
            git_dir.mkdir()
            inside_path = tmp_path / "inside_git"
            inside_path.mkdir()

            with self.assertRaises(ValueError):
                validate_artifact_path(inside_path, tmp_path)

    def test_python_template_only_context_rejected(self):
        """Template-only HTML path without python handler must create CONTEXT_RESOLUTION_FAILURE."""
        with tempfile.TemporaryDirectory() as tmp_repo:
            repo_path = Path(tmp_repo)
            finding = UnifiedFinding(
                finding_id="BenchmarkTest00165",
                scanner=ScannerType.SEMGREP,
                rule_id="django-csrf",
                repository="PY",
                file_path="templates/web/cmdi-00/BenchmarkTest00165.html",
                start_line=12,
                end_line=12,
                snippet="<form action='...'>"
            )
            ctx = extract_finding_context(finding, repo_path)
            self.assertEqual(ctx.context_quality, "UNRESOLVED")
            self.assertEqual(finding.outcome, EvaluationOutcome.FAILED)
            self.assertEqual(finding.failure_category, FailureCategory.CONTEXT_RESOLUTION_FAILURE)

    def test_python_handler_context_contains_real_source(self):
        """OWASP Python finding resolved to testcode handler must extract Python code."""
        repo_dir = Path("repos/BenchmarkPython").resolve()
        if repo_dir.exists():
            finding = UnifiedFinding(
                finding_id="BenchmarkTest00165",
                scanner=ScannerType.SEMGREP,
                rule_id="rule",
                repository="PY",
                file_path="templates/web/cmdi-00/BenchmarkTest00165.html",
                start_line=12,
                end_line=12,
                snippet="<form action='...'>"
            )
            ctx = extract_finding_context(finding, repo_dir)
            self.assertNotEqual(ctx.context_quality, "UNRESOLVED")
            self.assertIn("def BenchmarkTest00165_post", ctx.surrounding_code)


if __name__ == "__main__":
    unittest.main()
