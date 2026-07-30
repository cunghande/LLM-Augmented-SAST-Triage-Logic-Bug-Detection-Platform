"""
Unit and Integration Tests for Benchmark Evaluation Framework (Metric 2.0)
========================================================================
Tests exact numerical formulas, N/A semantics, confusion matrix, timer,
and execution mode distinctions.
"""

import time
import unittest
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, Severity, TriageVerdict
from src.benchmark.adapters import AdapterMatchReport, MatchedSample, MatchType, UnmatchedSample
from src.benchmark.evaluator import BenchmarkEvaluator, normalize_verdict, LatencyBreakdown, EvaluationRun
from src.benchmark.reporter import BenchmarkReportGenerator


class TestBenchmarkEvaluator(unittest.TestCase):

    def _create_finding(self, fid: str, verdict: TriageVerdict) -> UnifiedFinding:
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
            verdict=verdict
        )

    def test_verdict_normalization(self):
        self.assertEqual(normalize_verdict("TRIAGED_TP"), "TP")
        self.assertEqual(normalize_verdict("TRIAGED_FP"), "FP")
        self.assertEqual(normalize_verdict("TP"), "TP")
        self.assertEqual(normalize_verdict("FP"), "FP")
        self.assertEqual(normalize_verdict(TriageVerdict.NEEDS_REVIEW), "NEEDS_REVIEW")
        self.assertEqual(normalize_verdict(TriageVerdict.NEEDS_MORE_CONTEXT), "NEEDS_MORE_CONTEXT")
        self.assertEqual(normalize_verdict("PIPELINE_FAILURE"), "PIPELINE_FAILURE")

    def test_needs_review_does_not_increase_accuracy(self):
        """NEEDS_REVIEW must not be counted into accuracy."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t.py",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE)
            ),
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t.py",
                ground_truth_label="TP", source_ground_truth_id="2",
                finding=self._create_finding("2", TriageVerdict.NEEDS_REVIEW)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=2, matched_count=2, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 2)
        # Selective accuracy should be 1/1 = 1.0 (only 1 decided sample), NOT (1+1)/2 = 1.0 based on review
        self.assertEqual(metrics.decided_samples, 1)
        self.assertEqual(metrics.selective_accuracy, 1.0)
        self.assertEqual(metrics.decision_coverage, 0.5)
        self.assertEqual(metrics.abstention_rate, 0.5)

    def test_needs_more_context_not_counted_as_fp_suppression(self):
        """NEEDS_MORE_CONTEXT must be counted as abstention, not FP suppression."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t.py",
                ground_truth_label="FP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.NEEDS_MORE_CONTEXT)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=1, matched_count=1, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 1)
        self.assertEqual(metrics.tn, 0)
        self.assertEqual(metrics.safe_fp_suppression_rate, 0.0)
        self.assertEqual(metrics.abstention_count, 1)
        self.assertEqual(metrics.abstention_rate, 1.0)

    def test_50_50_needs_review_produces_na_and_zero_coverage(self):
        """50/50 NEEDS_REVIEW must yield decision_coverage = 0, abstention = 1, and N/A for precision/recall/F1/accuracy."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="python", repo_id="r1", normalized_file_path=f"t{i}.py",
                ground_truth_label="TP" if i % 2 == 0 else "FP", source_ground_truth_id=str(i),
                finding=self._create_finding(str(i), TriageVerdict.NEEDS_REVIEW)
            ) for i in range(50)
        ]
        report = AdapterMatchReport(
            benchmark_name="OWASP BenchmarkPython", total_findings=50, matched_count=50, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 50)
        self.assertEqual(metrics.decision_coverage, 0.0)
        self.assertEqual(metrics.abstention_rate, 1.0)
        self.assertEqual(metrics.precision, "N/A")
        self.assertEqual(metrics.recall_among_decided, "N/A")
        self.assertEqual(metrics.f1, "N/A")
        self.assertEqual(metrics.selective_accuracy, "N/A")

    def test_matched_findings_zero_produces_all_na(self):
        """When matched_findings = 0, all quality metrics must evaluate to N/A."""
        evaluator = BenchmarkEvaluator()
        report = AdapterMatchReport(
            benchmark_name="CredData", total_findings=7, matched_count=0, unmatched_count=7,
            matched_samples=[], adapter_status="ADAPTER_FAILURE"
        )
        metrics = evaluator.evaluate_matched_samples(report, 7)
        self.assertEqual(metrics.evaluation_status, "ADAPTER_FAILURE")
        self.assertEqual(metrics.precision, "N/A")
        self.assertEqual(metrics.recall_among_decided, "N/A")
        self.assertEqual(metrics.f1, "N/A")
        self.assertEqual(metrics.selective_accuracy, "N/A")
        self.assertEqual(metrics.safe_fp_suppression_rate, "N/A")

    def test_fp_suppression_formula(self):
        """TN / ground_truth_fp must calculate safe FP suppression."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t1.py",
                ground_truth_label="FP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.FALSE_POSITIVE)
            ),
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t2.py",
                ground_truth_label="FP", source_ground_truth_id="2",
                finding=self._create_finding("2", TriageVerdict.TRUE_POSITIVE)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=2, matched_count=2, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 2)
        self.assertEqual(metrics.ground_truth_fp, 2)
        self.assertEqual(metrics.tn, 1)
        self.assertEqual(metrics.fp, 1)
        self.assertEqual(metrics.safe_fp_suppression_rate, 0.5)

    def test_policy_fnr_formula(self):
        """FN / ground_truth_tp must calculate policy FNR."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t1.py",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.FALSE_POSITIVE)  # FN
            ),
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t2.py",
                ground_truth_label="TP", source_ground_truth_id="2",
                finding=self._create_finding("2", TriageVerdict.TRUE_POSITIVE)  # TP
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=2, matched_count=2, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 2)
        self.assertEqual(metrics.ground_truth_tp, 2)
        self.assertEqual(metrics.fn, 1)
        self.assertEqual(metrics.tp, 1)
        self.assertEqual(metrics.policy_false_negative_rate, 0.5)

    def test_pipeline_failure_reported_separately(self):
        """PIPELINE_FAILURE must be tracked as failure, not review or FP."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t1.py",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.PIPELINE_FAILURE)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=1, matched_count=1, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 1)
        self.assertEqual(metrics.tp_failure, 1)
        self.assertEqual(metrics.pipeline_failure_rate, 1.0)
        self.assertEqual(metrics.conservative_miss_rate, 1.0)

    def test_unmatched_sample_not_in_confusion_matrix(self):
        """Unmatched samples must not enter confusion matrix counts."""
        evaluator = BenchmarkEvaluator()
        samples = [
            MatchedSample(
                benchmark_name="test", repo_id="r1", normalized_file_path="t1.py",
                ground_truth_label="TP", source_ground_truth_id="1",
                finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE)
            ),
        ]
        report = AdapterMatchReport(
            benchmark_name="test", total_findings=5, matched_count=1, unmatched_count=4,
            matched_samples=samples, adapter_status="OK",
            unmatched_findings=[
                UnmatchedSample(finding_id=f"unmatched-{i}", repo_id="r1", reason="no match")
                for i in range(4)
            ]
        )
        metrics = evaluator.evaluate_matched_samples(report, 5)
        self.assertEqual(metrics.total_findings, 5)
        self.assertEqual(metrics.matched_findings, 1)
        self.assertEqual(metrics.unmatched_findings, 4)
        self.assertEqual(metrics.ground_truth_tp, 1)
        self.assertEqual(metrics.tp, 1)

    def test_synthetic_dataset_integration(self):
        """
        Part 12 Synthetic Dataset Integration Test:
        Ground truth: 4 TP, 6 FP (10 total matched findings)
        Predictions:
        - 2 TP (correct TP)
        - 1 FP (GT TP predicted FP -> FN)
        - 1 NEEDS_REVIEW (GT TP predicted NEEDS_REVIEW -> TP abstained)
        - 3 FP (GT FP predicted FP -> TN)
        - 1 TP (GT FP predicted TP -> FP)
        - 1 NEEDS_MORE_CONTEXT (GT FP predicted NEEDS_MORE_CONTEXT -> FP abstained)
        - 1 PIPELINE_FAILURE (GT FP predicted PIPELINE_FAILURE -> FP failure)
        """
        evaluator = BenchmarkEvaluator()
        samples = [
            # 4 GT TP
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f1.py", ground_truth_label="TP", source_ground_truth_id="1", finding=self._create_finding("1", TriageVerdict.TRUE_POSITIVE)),
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f2.py", ground_truth_label="TP", source_ground_truth_id="2", finding=self._create_finding("2", TriageVerdict.TRUE_POSITIVE)),
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f3.py", ground_truth_label="TP", source_ground_truth_id="3", finding=self._create_finding("3", TriageVerdict.FALSE_POSITIVE)), # FN
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f4.py", ground_truth_label="TP", source_ground_truth_id="4", finding=self._create_finding("4", TriageVerdict.NEEDS_REVIEW)), # TP abstained
            # 6 GT FP
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f5.py", ground_truth_label="FP", source_ground_truth_id="5", finding=self._create_finding("5", TriageVerdict.FALSE_POSITIVE)), # TN
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f6.py", ground_truth_label="FP", source_ground_truth_id="6", finding=self._create_finding("6", TriageVerdict.FALSE_POSITIVE)), # TN
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f7.py", ground_truth_label="FP", source_ground_truth_id="7", finding=self._create_finding("7", TriageVerdict.FALSE_POSITIVE)), # TN
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f8.py", ground_truth_label="FP", source_ground_truth_id="8", finding=self._create_finding("8", TriageVerdict.TRUE_POSITIVE)), # FP
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f9.py", ground_truth_label="FP", source_ground_truth_id="9", finding=self._create_finding("9", TriageVerdict.NEEDS_MORE_CONTEXT)), # FP abstained
            MatchedSample(benchmark_name="synth", repo_id="r", normalized_file_path="f10.py", ground_truth_label="FP", source_ground_truth_id="10", finding=self._create_finding("10", TriageVerdict.PIPELINE_FAILURE)), # FP failure
        ]

        report = AdapterMatchReport(
            benchmark_name="SyntheticBenchmark", total_findings=10, matched_count=10, unmatched_count=0,
            matched_samples=samples, adapter_status="OK"
        )
        metrics = evaluator.evaluate_matched_samples(report, 10)

        # Assert exact expected values
        self.assertEqual(metrics.tp, 2)
        self.assertEqual(metrics.fn, 1)
        self.assertEqual(metrics.tn, 3)
        self.assertEqual(metrics.fp, 1)
        self.assertEqual(metrics.abstention_count, 2)
        self.assertEqual(metrics.pipeline_failure_rate, 0.1)
        self.assertEqual(metrics.decided_samples, 7)
        self.assertEqual(metrics.decision_coverage, 0.7)
        self.assertEqual(metrics.abstention_rate, 0.2)

        self.assertAlmostEqual(metrics.precision, 2 / 3, places=4)
        self.assertAlmostEqual(metrics.recall_among_decided, 2 / 3, places=4)
        self.assertAlmostEqual(metrics.f1, 2 / 3, places=4)
        self.assertAlmostEqual(metrics.selective_accuracy, 5 / 7, places=4)
        self.assertEqual(metrics.policy_false_negative_rate, 0.25)
        self.assertEqual(metrics.conservative_miss_rate, 0.25)
        self.assertEqual(metrics.safe_fp_suppression_rate, 0.5)
        self.assertEqual(metrics.safe_workload_reduction, 0.5)

    def test_high_resolution_timer(self):
        """Timer must measure elapsed milliseconds > 0 with controlled delay."""
        t_start = time.perf_counter()
        time.sleep(0.010)  # 10ms delay
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        self.assertGreater(elapsed_ms, 5.0)

    def test_mock_vs_real_execution_mode(self):
        """MOCK and REAL execution modes must be distinguished."""
        lb_mock = LatencyBreakdown(execution_mode="MOCK")
        lb_real = LatencyBreakdown(execution_mode="REAL")
        self.assertEqual(lb_mock.execution_mode, "MOCK")
        self.assertEqual(lb_real.execution_mode, "REAL")

    def test_realvuln_adapter_matching_5_samples(self):
        """Verify RealVulnBenchmarkAdapter on 5 representative sample findings."""
        from src.benchmark.adapters import RealVulnBenchmarkAdapter
        gt_5_items = [
            {"finding_id": "rv-1", "repo_id": "damn-vulnerable-flask-app", "file_path": "app.py", "start_line": 120, "function": "evaluate", "vulnerability_class": "code_injection", "primary_cwe": "CWE-94", "ground_truth_verdict": "TP"},
            {"finding_id": "rv-2", "repo_id": "damn-vulnerable-flask-app", "file_path": "app.py", "start_line": 135, "function": "profile", "vulnerability_class": "sqli", "primary_cwe": "CWE-89", "ground_truth_verdict": "TP"},
            {"finding_id": "rv-3", "repo_id": "damn-vulnerable-flask-app", "file_path": "app.py", "start_line": 150, "function": "upload", "vulnerability_class": "unrestricted_file_upload", "primary_cwe": "CWE-434", "ground_truth_verdict": "TP"},
            {"finding_id": "rv-4", "repo_id": "damn-vulnerable-flask-app", "file_path": "app.py", "start_line": 165, "function": "debug", "vulnerability_class": "command_injection", "primary_cwe": "CWE-78", "ground_truth_verdict": "TP"},
            {"finding_id": "rv-5", "repo_id": "juice-shop", "file_path": "routes/login.js", "start_line": 42, "function": "login", "vulnerability_class": "sqli", "primary_cwe": "CWE-89", "ground_truth_verdict": "TP"},
        ]

        test_findings = [
            UnifiedFinding(finding_id="f1", scanner=ScannerType.SEMGREP, rule_id="eval-injection", repository="damn-vulnerable-flask-app", file_path="damn-vulnerable-flask-app/app.py", start_line=120, end_line=120, snippet="eval(expr)", severity=Severity.CRITICAL, verdict=TriageVerdict.TRUE_POSITIVE),
            UnifiedFinding(finding_id="f2", scanner=ScannerType.SEMGREP, rule_id="sqli", repository="damn-vulnerable-flask-app", file_path="damn-vulnerable-flask-app/app.py", start_line=135, end_line=135, snippet="SELECT * FROM users", severity=Severity.HIGH, verdict=TriageVerdict.TRUE_POSITIVE),
            UnifiedFinding(finding_id="f3", scanner=ScannerType.SEMGREP, rule_id="file-upload", repository="damn-vulnerable-flask-app", file_path="damn-vulnerable-flask-app/app.py", start_line=150, end_line=150, snippet="file.save()", severity=Severity.HIGH, verdict=TriageVerdict.TRUE_POSITIVE),
            UnifiedFinding(finding_id="f4", scanner=ScannerType.SEMGREP, rule_id="cmd-injection", repository="damn-vulnerable-flask-app", file_path="damn-vulnerable-flask-app/app.py", start_line=165, end_line=165, snippet="os.system()", severity=Severity.CRITICAL, verdict=TriageVerdict.TRUE_POSITIVE),
            UnifiedFinding(finding_id="f5", scanner=ScannerType.SEMGREP, rule_id="sqli-js", repository="juice-shop", file_path="juice-shop/routes/login.js", start_line=42, end_line=42, snippet="db.query()", severity=Severity.HIGH, verdict=TriageVerdict.TRUE_POSITIVE),
        ]

        adapter = RealVulnBenchmarkAdapter(gt_5_items)
        report = adapter.match(test_findings)
        self.assertEqual(report.total_findings, 5)
        self.assertEqual(report.matched_count, 5)
        self.assertEqual(report.adapter_status, "OK")

    def test_samsung_adapter_matching(self):
        """Verify SamsungCredDataAdapter path and line proximity matching."""
        from src.benchmark.adapters import SamsungCredDataAdapter
        gt_items = [
            {"finding_id": "CRED-a09d9e50-616", "repo_name": "a09d9e50", "file_path": "data/a09d9e50/api/9c72cd5b.ts", "line_start": 100, "category": "API", "ground_truth_verdict": "FP"}
        ]
        test_findings = [
            UnifiedFinding(finding_id="f1", scanner=ScannerType.GITLEAKS, rule_id="api-key", repository="CredData", file_path="repos/CredData/data/a09d9e50/api/9c72cd5b.ts", start_line=102, end_line=102, snippet="key = '123'", severity=Severity.HIGH, verdict=TriageVerdict.FALSE_POSITIVE)
        ]
        adapter = SamsungCredDataAdapter(gt_items)
        report = adapter.match(test_findings)
        self.assertEqual(report.matched_count, 1)
        self.assertEqual(report.adapter_status, "OK")


if __name__ == "__main__":
    unittest.main()

