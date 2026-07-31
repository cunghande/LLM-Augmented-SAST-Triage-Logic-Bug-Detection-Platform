"""
Benchmark Artifact Report Generator
====================================
Generates standard audit-ready benchmark artifacts:
1. evaluation_manifest.json
2. evaluation_summary.json
3. evaluation_summary.md
4. confusion_matrix.json
5. unmatched_findings.json
6. per_sample_results.jsonl
7. latency_report.json
"""

import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
from src.benchmark.evaluator import EvaluationRun, EvaluationMetrics, LatencyBreakdown
from src.benchmark.adapters import AdapterMatchReport, MatchedSample, UnmatchedSample


def get_git_root(path: Path) -> Optional[Path]:
    """Helper to resolve the Git root for a given directory path."""
    try:
        res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=str(path), capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except Exception:
        pass
    return None


def validate_artifact_path(
    output_dir: Path,
    project_root: Path,
    target_roots: Optional[List[Path]] = None
) -> Dict[str, Any]:
    """
    Validates that output_dir is an absolute, canonical directory located OUTSIDE
    all Git worktrees (both platform git root and benchmark target git roots).
    Blocks symlink escapes, path traversal, and run overwrites.
    """
    resolved_output = Path(output_dir).resolve()
    resolved_project = Path(project_root).resolve()
    
    git_roots_checked = []

    # Check project git root
    proj_git = get_git_root(resolved_project) or resolved_project
    git_roots_checked.append(str(proj_git))

    # Check target git roots
    if target_roots:
        for tr in target_roots:
            tr_git = get_git_root(Path(tr).resolve()) or Path(tr).resolve()
            git_roots_checked.append(str(tr_git))

    # Check symlinks
    if os.path.islink(output_dir) or any(os.path.islink(p) for p in resolved_output.parents):
        raise ValueError(f"Symlink escape blocked: artifact path '{output_dir}' contains a symbolic link.")

    # Check containment in Git roots
    for git_root_str in git_roots_checked:
        git_root_path = Path(git_root_str)
        try:
            resolved_output.relative_to(git_root_path)
            raise ValueError(
                f"Path validation failed: Output directory '{resolved_output}' is inside Git worktree '{git_root_path}'. "
                "Artifacts MUST be stored outside all Git worktrees."
            )
        except ValueError as e:
            if "inside Git worktree" in str(e):
                raise

    # Block overwrite of existing non-empty directory
    if resolved_output.exists() and any(resolved_output.iterdir()):
        raise FileExistsError(f"Immutable run directory violation: Output directory '{resolved_output}' already exists and is non-empty.")

    return {
        "artifact_root": str(resolved_output),
        "project_git_root": str(proj_git),
        "target_git_roots_checked": git_roots_checked,
        "path_validation_status": "PASSED"
    }


class BenchmarkReportGenerator:
    def __init__(
        self,
        output_dir: Union[str, Path],
        project_root: Path,
        target_roots: Optional[List[Path]] = None
    ):
        self.raw_output_dir = Path(output_dir)
        self.project_root = Path(project_root)
        self.target_roots = target_roots or []

        self.path_metadata = validate_artifact_path(self.raw_output_dir, self.project_root, self.target_roots)
        self.output_dir = Path(self.path_metadata["artifact_root"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_run_artifacts(self, run: EvaluationRun, match_reports: List[AdapterMatchReport]) -> Dict[str, str]:
        generated_files = {}

        # Merge path validation metadata into run manifest
        run_data = run.model_dump()
        run_data.update(self.path_metadata)

        # 1. evaluation_manifest.json
        manifest_path = self.output_dir / "evaluation_manifest.json"
        manifest_path.write_text(json.dumps(run_data, indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["manifest"] = str(manifest_path)

        # 2. evaluation_summary.json
        summary_path = self.output_dir / "evaluation_summary.json"
        summary_data = {
            "evaluation_run_id": run.evaluation_run_id,
            "generated_at_utc": run.generated_at_utc,
            "benchmark_name": run.benchmark_name,
            "execution_mode": run.execution_mode,
            "metric_version": run.metric_version,
            "preflight_run_id": run.preflight_run_id,
            "pilot_run_id": run.pilot_run_id,
            "quality_gate_status": run.quality_gate_status,
            "metrics": run.metrics.model_dump(),
            "latency": run.latency.model_dump(),
            "path_validation": self.path_metadata
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
            "description": "Ground-truth vs Model predictions matrix."
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
                    diagnostic = (sample.finding.metadata or {}).get("diagnostic", {})
                    item = {
                        "evaluation_run_id": run.evaluation_run_id,
                        "benchmark_name": sample.benchmark_name,
                        "finding_id": sample.finding.finding_id,
                        "normalized_file_path": sample.normalized_file_path,
                        "start_line": sample.start_line,
                        "ground_truth_label": sample.ground_truth_label,
                        "predicted_verdict": sample.finding.verdict.value if sample.finding.verdict else None,
                        "outcome": getattr(sample.finding, "outcome", None),
                        "failure_category": getattr(sample.finding, "failure_category", None),
                        "confidence": sample.finding.confidence,
                        "match_type": sample.match_type.value,
                        "rule_family_or_cwe": sample.rule_family_or_cwe,
                        "transport_success": diagnostic.get("transport_success"),
                        "parse_success": diagnostic.get("parse_success"),
                        "raw_response": diagnostic.get("raw_response"),
                        "parsed_response": diagnostic.get("parsed_response"),
                        "schema_validation_error": diagnostic.get("schema_validation_error"),
                    }
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
        generated_files["per_sample"] = str(jsonl_path)


        # 6. latency_report.json
        latency_path = self.output_dir / "latency_report.json"
        latency_path.write_text(json.dumps(run.latency.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8")
        generated_files["latency"] = str(latency_path)

        # 7. evaluation_summary.md
        md_path = self.output_dir / "evaluation_summary.md"
        md_content = self.generate_markdown_summary(run)
        md_path.write_text(md_content, encoding="utf-8")
        generated_files["summary_md"] = str(md_path)

        return generated_files

    def generate_markdown_summary(self, run: EvaluationRun) -> str:
        m = run.metrics
        l = run.latency
        lines = [
            f"# Benchmark Evaluation Report (Metric 2.0 Audit-Ready)",
            f"",
            f"- **Run ID**: `{run.evaluation_run_id}`",
            f"- **Benchmark Name**: {run.benchmark_name}",
            f"- **Execution Mode**: `{run.execution_mode}`",
            f"- **Model**: `{run.model_name}`",
            f"- **Quality Gate Status**: **{run.quality_gate_status}**",
            f"- **Artifact Storage**: `{self.output_dir}`",
            f"",
            f"## 1. Quality Metrics Summary",
            f"",
            f"| Metric Name | Value | Numerator / Denominator | Status / Reason |",
            f"|---|:---:|:---:|---|",
            f"| **Decision Coverage** | {m.decision_coverage.markdown_render(True)} | {m.decision_coverage.numerator} / {m.decision_coverage.denominator} | {m.decision_coverage.status} |",
            f"| **Abstention Rate** | {m.abstention_rate.markdown_render(True)} | {m.abstention_rate.numerator} / {m.abstention_rate.denominator} | {m.abstention_rate.status} |",
            f"| **Precision (Decided)** | {m.precision.markdown_render()} | {m.precision.numerator} / {m.precision.denominator} | {m.precision.status} |",
            f"| **Selective Recall** | {m.selective_recall.markdown_render()} | {m.selective_recall.numerator} / {m.selective_recall.denominator} | {m.selective_recall.status} |",
            f"| **End-to-End TP Resolution** | {m.end_to_end_tp_resolution_rate.markdown_render(True)} | {m.end_to_end_tp_resolution_rate.numerator} / {m.end_to_end_tp_resolution_rate.denominator} | {m.end_to_end_tp_resolution_rate.status} |",
            f"| **F1 Score** | {m.f1.markdown_render()} | {m.f1.numerator} / {m.f1.denominator} | {m.f1.status} |",
            f"| **Selective Accuracy** | {m.selective_accuracy.markdown_render(True)} | {m.selective_accuracy.numerator} / {m.selective_accuracy.denominator} | {m.selective_accuracy.status} |",
            f"| **Policy FNR** | {m.policy_false_negative_rate.markdown_render(True)} | {m.policy_false_negative_rate.numerator} / {m.policy_false_negative_rate.denominator} | {m.policy_false_negative_rate.status} |",
            f"| **Correct FP Suppression** | {m.correct_fp_suppression_rate.markdown_render(True)} | {m.correct_fp_suppression_rate.numerator} / {m.correct_fp_suppression_rate.denominator} | {m.correct_fp_suppression_rate.status} |",
            f"| **Correctly Decided Rate** | {m.correctly_decided_rate.markdown_render(True)} | {m.correctly_decided_rate.numerator} / {m.correctly_decided_rate.denominator} | {m.correctly_decided_rate.status} |",
            f"",
            f"## 2. Decision Outcome Matrix",
            f"",
            f"| GT Label | Decided TP | Decided FP / FN | Abstained | Failed | Total Ground Truth |",
            f"|---|:---:|:---:|:---:|:---:|:---:|",
            f"| **GT True Positive (TP)** | {m.tp} (TP) | {m.fn} (FN) | {m.tp_abstained} | {m.tp_failure} | {m.ground_truth_tp} |",
            f"| **GT False Positive (FP)** | {m.fp} (FP) | {m.tn} (TN) | {m.fp_abstained} | {m.fp_failure} | {m.ground_truth_fp} |",
            f"",
            f"## 3. Latency & Performance Breakdown",
            f"",
            f"- **Total Wall-Clock**: {l.total_wall_clock_ms:.2f} ms",
            f"- **Inference P50 Latency**: {l.latency_p50_ms:.2f} ms",
            f"- **Inference P95 Latency**: {l.latency_p95_ms:.2f} ms",
            f"- **Min / Max Latency**: {l.latency_min_ms:.2f} ms / {l.latency_max_ms:.2f} ms",
            f"- **Total LLM Requests**: {l.request_count} (Success: {l.success_count}, Failed: {l.failure_count}, Timeout: {l.timeout_count})",
        ]
        return "\n".join(lines)
