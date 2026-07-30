"""
Benchmark Artifact Report Generator
====================================
Generates standard audit-ready benchmark artifacts:
1. evaluation_summary.json
2. evaluation_summary.md
3. confusion_matrix.json
4. unmatched_findings.json
5. per_sample_results.jsonl
6. latency_report.json
7. evaluation_manifest.json
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Union
from src.benchmark.evaluator import EvaluationRun, EvaluationMetrics, LatencyBreakdown
from src.benchmark.adapters import AdapterMatchReport, MatchedSample, UnmatchedSample


class BenchmarkReportGenerator:
    def __init__(self, output_dir: Union[str, Path]):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_run_artifacts(self, run: EvaluationRun, match_reports: List[AdapterMatchReport]) -> Dict[str, str]:
        generated_files = {}

        # 1. evaluation_manifest.json
        manifest_path = self.output_dir / "evaluation_manifest.json"
        manifest_path.write_text(json.dumps(run.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["manifest"] = str(manifest_path)

        # 2. evaluation_summary.json
        summary_path = self.output_dir / "evaluation_summary.json"
        summary_data = {
            "evaluation_run_id": run.evaluation_run_id,
            "generated_at_utc": run.generated_at_utc,
            "benchmark_name": run.benchmark_name,
            "execution_mode": run.execution_mode,
            "metric_version": run.metric_version,
            "metrics": run.metrics.model_dump(),
            "latency": run.latency.model_dump(),
        }
        summary_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["summary_json"] = str(summary_path)

        # 3. confusion_matrix.json
        cm_path = self.output_dir / "confusion_matrix.json"
        cm_data = {
            "evaluation_run_id": run.evaluation_run_id,
            "benchmark_name": run.benchmark_name,
            "matrix": {
                "TP": run.metrics.tp,
                "FP": run.metrics.fp,
                "TN": run.metrics.tn,
                "FN": run.metrics.fn,
                "TP_abstained": run.metrics.tp_abstained,
                "FP_abstained": run.metrics.fp_abstained,
                "TP_failure": run.metrics.tp_failure,
                "FP_failure": run.metrics.fp_failure,
            },
            "description": "Ground-truth vs Model predictions matrix. Unmatched samples are excluded."
        }
        cm_path.write_text(json.dumps(cm_data, indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["confusion_matrix"] = str(cm_path)

        # 4. unmatched_findings.json
        unmatched_path = self.output_dir / "unmatched_findings.json"
        all_unmatched = []
        for mr in match_reports:
            for uf in mr.unmatched_findings:
                all_unmatched.append(uf.model_dump())
        unmatched_path.write_text(json.dumps({"unmatched_findings": all_unmatched}, indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["unmatched"] = str(unmatched_path)

        # 5. per_sample_results.jsonl
        jsonl_path = self.output_dir / "per_sample_results.jsonl"
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for mr in match_reports:
                for sample in mr.matched_samples:
                    item = {
                        "evaluation_run_id": run.evaluation_run_id,
                        "benchmark_name": sample.benchmark_name,
                        "finding_id": sample.finding.finding_id,
                        "normalized_file_path": sample.normalized_file_path,
                        "start_line": sample.start_line,
                        "ground_truth_label": sample.ground_truth_label,
                        "predicted_verdict": sample.finding.verdict.value if sample.finding.verdict else "NEEDS_REVIEW",
                        "confidence": sample.finding.confidence,
                        "match_type": sample.match_type.value,
                        "rule_family_or_cwe": sample.rule_family_or_cwe,
                    }
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
        generated_files["per_sample"] = str(jsonl_path)

        # 6. latency_report.json
        latency_path = self.output_dir / "latency_report.json"
        latency_path.write_text(json.dumps(run.latency.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["latency"] = str(latency_path)

        # 7. evaluation_summary.md
        md_path = self.output_dir / "evaluation_summary.md"
        md_content = self.generate_markdown_summary(run, match_reports)
        md_path.write_text(md_content, encoding="utf-8")
        generated_files["summary_md"] = str(md_path)

        return generated_files

    def generate_markdown_summary(self, run: EvaluationRun, match_reports: List[AdapterMatchReport]) -> str:
        m = run.metrics
        l = run.latency

        def fmt(val: Any) -> str:
            if isinstance(val, float):
                return f"{val:.4f}"
            return str(val)

        def pct(val: Any) -> str:
            if isinstance(val, float):
                return f"{val * 100:.2f}%"
            return str(val)

        md = [
            f"# 📊 LLM SAST Triage — Benchmark Evaluation Report (Metric {run.metric_version})",
            "",
            f"> **Run ID**: `{run.evaluation_run_id}` | **Timestamp**: `{run.generated_at_utc}` UTC",
            f"> **Model**: `{run.model_name}` | **Execution Mode**: `{run.execution_mode}` | **Status**: `{m.evaluation_status}`",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"Evaluated platform performance on **{m.total_findings} total findings** across benchmark suite.",
            f"Ground-Truth Matched: **{m.matched_findings}** | Unmatched: **{m.unmatched_findings}**",
            "",
            "### Metric 2.0 Summary Table",
            "",
            "| Metric | Value | Status / Note |",
            "|---|:---:|---|",
            f"| **Decision Coverage** | **{pct(m.decision_coverage)}** | Decided samples / Matched findings |",
            f"| **Abstention Rate** | **{pct(m.abstention_rate)}** | NEEDS_REVIEW + NEEDS_MORE_CONTEXT |",
            f"| **Pipeline Failure Rate** | **{pct(m.pipeline_failure_rate)}** | PIPELINE_FAILURE |",
            f"| **Precision (Decided)** | **{fmt(m.precision)}** | TP / (TP + FP) |",
            f"| **Recall (Decided)** | **{fmt(m.recall_among_decided)}** | TP / (TP + FN) |",
            f"| **F1 Score** | **{fmt(m.f1)}** | Harmonic Mean of Precision & Recall |",
            f"| **Selective Accuracy** | **{pct(m.selective_accuracy)}** | (TP + TN) / Decided Samples |",
            f"| **Policy FNR** | **{pct(m.policy_false_negative_rate)}** | FN / Ground Truth TP |",
            f"| **Conservative Miss Rate** | **{pct(m.conservative_miss_rate)}** | (FN + TP Failure) / Ground Truth TP |",
            f"| **Safe FP Suppression Rate** | **{pct(m.safe_fp_suppression_rate)}** | TN / Ground Truth FP |",
            f"| **Safe Workload Reduction** | **{pct(m.safe_workload_reduction)}** | (TP + TN) / Matched Findings |",
            f"| **Total Latency** | **{l.total_wall_clock_ms:.2f} ms** | ({l.total_wall_clock_ms/1000.0:.3f}s) |",
            "",
            "---",
            "",
            "## Confusion Matrix (Decided vs Abstaining vs Failure)",
            "",
            "| Ground Truth | Predicted TP | Predicted FP | NEEDS_REVIEW / CONTEXT | PIPELINE_FAILURE | Total |",
            "|---|:---:|:---:|:---:|:---:|:---:|",
            f"| **Actual TP** | ✅ {m.tp} | ❌ {m.fn} (FN) | ⚠️ {m.tp_abstained} | 🔴 {m.tp_failure} | {m.ground_truth_tp} |",
            f"| **Actual FP** | ❌ {m.fp} (FP) | ✅ {m.tn} (TN) | ⚠️ {m.fp_abstained} | 🔴 {m.fp_failure} | {m.ground_truth_fp} |",
            "",
            "---",
            "",
            "## Benchmark Results Breakdown",
            "",
        ]

        for mr in match_reports:
            md.extend([
                f"### Benchmark: `{mr.benchmark_name}`",
                "",
                f"- **Strategy**: `{mr.match_strategy}` | **Adapter Status**: `{mr.adapter_status}`",
                f"- **Total Findings**: {mr.total_findings}",
                f"- **Matched**: {mr.matched_count} | **Unmatched**: {mr.unmatched_count}",
                "",
            ])

            if mr.adapter_status == "ADAPTER_FAILURE" or mr.matched_count == 0:
                md.extend([
                    "> [!WARNING]",
                    f"> **ADAPTER_FAILURE**: Ground-truth matching achieved 0/{mr.total_findings} matched findings. All quality metrics are reported as **N/A**.",
                    "",
                ])
            else:
                md.extend([
                    "| Parameter | Count / Value |",
                    "|---|:---:|",
                    f"| Matched Findings | {mr.matched_count} |",
                    f"| Ground Truth TP | {sum(1 for s in mr.matched_samples if s.ground_truth_label == 'TP')} |",
                    f"| Ground Truth FP | {sum(1 for s in mr.matched_samples if s.ground_truth_label == 'FP')} |",
                    "",
                ])

        if m.na_reasons:
            md.extend([
                "---",
                "",
                "## Metric Undefined (N/A) Explanations",
                "",
            ])
            for metric_k, reason_v in m.na_reasons.items():
                md.append(f"- **{metric_k}**: `N/A` — *Reason*: {reason_v}")
            md.append("")

        md.extend([
            "---",
            "",
            "## Recommended Targets Evaluation",
            "",
            "| Metric | Target | Current Value | Status |",
            "|---|:---:|:---:|:---:|",
        ])

        # Selective Accuracy Target
        sel_acc_status = "⚠️ N/A"
        if isinstance(m.selective_accuracy, float):
            sel_acc_status = "✅ PASS" if m.selective_accuracy >= 0.80 else "❌ FAIL"
        md.append(f"| Selective Accuracy | ≥ 80.0% | {pct(m.selective_accuracy)} | {sel_acc_status} |")

        # Decision Coverage Target
        cov_status = "⚠️ N/A"
        if isinstance(m.decision_coverage, float):
            cov_status = "✅ PASS" if m.decision_coverage >= 0.50 else "❌ FAIL"
        md.append(f"| Decision Coverage | ≥ 50.0% | {pct(m.decision_coverage)} | {cov_status} |")

        # Safe FP Suppression Target
        fp_sup_status = "⚠️ N/A"
        if isinstance(m.safe_fp_suppression_rate, float):
            fp_sup_status = "✅ PASS" if m.safe_fp_suppression_rate >= 0.60 else "❌ FAIL"
        md.append(f"| Safe FP Suppression Rate | ≥ 60.0% | {pct(m.safe_fp_suppression_rate)} | {fp_sup_status} |")

        # Policy FNR Target
        fnr_status = "⚠️ N/A"
        if isinstance(m.policy_false_negative_rate, float):
            fnr_status = "✅ PASS" if m.policy_false_negative_rate <= 0.10 else "❌ FAIL"
        md.append(f"| Policy FNR | ≤ 10.0% | {pct(m.policy_false_negative_rate)} | {fnr_status} |")

        md.extend([
            "",
            "---",
            "",
            f"*Report produced by LLM-Augmented SAST Triage Evaluator v2.0 — {run.generated_at_utc} UTC*",
        ])

        return "\n".join(md)
