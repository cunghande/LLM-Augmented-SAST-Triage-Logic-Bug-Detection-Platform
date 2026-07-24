import json
from pathlib import Path
from typing import List, Dict, Any, Union
from src.core.schema import UnifiedFinding, ActionGroup, TriageVerdict


def generate_json_report(findings: List[UnifiedFinding], output_path: Union[str, Path]) -> str:
    """Save triaged findings to JSON file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = [finding.model_dump() for finding in findings]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return str(output_path)


def generate_markdown_report(findings: List[UnifiedFinding], output_path: Union[str, Path]) -> str:
    """Save clean summary markdown report of triaged findings."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total = len(findings)
    tp_count = sum(1 for f in findings if f.verdict == TriageVerdict.TRUE_POSITIVE)
    fp_count = sum(1 for f in findings if f.verdict == TriageVerdict.FALSE_POSITIVE)
    nr_count = sum(1 for f in findings if f.verdict == TriageVerdict.NEEDS_REVIEW or f.verdict is None)

    auto_suppress = sum(1 for f in findings if f.action_group == ActionGroup.AUTO_SUPPRESS_CANDIDATE)
    high_tp = sum(1 for f in findings if f.action_group == ActionGroup.HIGH_CONFIDENCE_TP)
    manual_rev = sum(1 for f in findings if f.action_group == ActionGroup.MANUAL_REVIEW)

    md = [
        "# LLM SAST Automated Triage Summary Report",
        "",
        f"Total Findings Processed: **{total}**",
        "",
        "## Classification Breakdown",
        f"- **True Positives (TP)**: {tp_count} ({(tp_count/total*100):.1f}%" if total else "0%",
        f"- **False Positives (FP)**: {fp_count} ({(fp_count/total*100):.1f}%" if total else "0%",
        f"- **Needs Review**: {nr_count} ({(nr_count/total*100):.1f}%" if total else "0%",
        "",
        "## Confidence Routing Action Groups",
        f"- Auto-suppress Candidates: {auto_suppress}",
        f"- High Confidence TPs: {high_tp}",
        f"- Manual Review Needed: {manual_rev}",
        "",
        "## Detailed Findings",
        "| ID | Scanner | Rule ID | File:Line | Verdict | Confidence | Action Group |",
        "|---|---|---|---|:---:|:---:|---|",
    ]

    for f in findings:
        verdict_str = f.verdict.value if f.verdict else "N/A"
        conf_str = f"{f.confidence:.2f}" if f.confidence is not None else "N/A"
        action_str = f.action_group.value if f.action_group else "N/A"
        md.append(f"| {f.finding_id} | {f.scanner.value} | `{f.rule_id}` | `{f.file_path}:{f.start_line}` | **{verdict_str}** | {conf_str} | {action_str} |")

    md.append("")
    md_content = "\n".join(md)
    output_path.write_text(md_content, encoding="utf-8")
    return str(output_path)


def evaluate_triage_performance(
    triaged_findings: List[UnifiedFinding],
    ground_truth_map: Dict[str, str]
) -> Dict[str, Any]:
    """Calculate confusion matrix, precision, recall, and F1 score against benchmark ground truth."""
    tp_count = 0  # Ground truth TP, predicted TP
    fp_count = 0  # Ground truth FP, predicted TP
    fn_count = 0  # Ground truth TP, predicted FP
    tn_count = 0  # Ground truth FP, predicted FP
    needs_review_count = 0
    unmatched = 0

    for f in triaged_findings:
        gt = ground_truth_map.get(f.finding_id) or ground_truth_map.get(f.rule_id)
        if not gt:
            unmatched += 1
            continue

        pred = f.verdict.value if f.verdict else "NEEDS_REVIEW"

        if pred == "NEEDS_REVIEW":
            needs_review_count += 1
        elif gt == "TP" and pred == "TP":
            tp_count += 1
        elif gt == "FP" and pred == "TP":
            fp_count += 1
        elif gt == "TP" and pred == "FP":
            fn_count += 1
        elif gt == "FP" and pred == "FP":
            tn_count += 1

    total_evaluated = tp_count + fp_count + fn_count + tn_count + needs_review_count
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    fp_reduction_rate = (tn_count / total_evaluated * 100.0) if total_evaluated > 0 else 0.0

    return {
        "total_evaluated": total_evaluated,
        "needs_review": needs_review_count,
        "unmatched": unmatched,
        "true_positives": tp_count,
        "false_positives": fp_count,
        "false_negatives": fn_count,
        "true_negatives": tn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "fp_reduction_rate_pct": round(fp_reduction_rate, 2),
    }


def generate_priority_report(
    findings: List[UnifiedFinding],
    output_path: Union[str, Path],
    repo_name: str = "CN_WEB",
) -> str:
    """Generate S2-07 Priority Report - sorted by Risk Score with Executive Summary."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    from src.core.schema import Severity

    # Sort by risk_score descending
    sorted_findings = sorted(
        [f for f in findings if f.verdict == TriageVerdict.TRUE_POSITIVE],
        key=lambda f: f.risk_score or 0.0,
        reverse=True
    )

    total = len(findings)
    tp_count = sum(1 for f in findings if f.verdict == TriageVerdict.TRUE_POSITIVE)
    fp_count = sum(1 for f in findings if f.verdict == TriageVerdict.FALSE_POSITIVE)
    nr_count = sum(1 for f in findings if f.verdict == TriageVerdict.NEEDS_REVIEW or f.verdict is None)

    critical_count = sum(1 for f in sorted_findings if f.risk_score and f.risk_score >= 4.2)
    high_count = sum(1 for f in sorted_findings if f.risk_score and 3.4 <= f.risk_score < 4.2)
    medium_count = sum(1 for f in sorted_findings if f.risk_score and f.risk_score < 3.4)

    md = [
        f"# Security Priority Report — {repo_name}",
        "",
        f"> **Generated**: {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d')} | **Repository**: `{repo_name}`",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Platform scanned **{repo_name}** and discovered **{total} findings** from automated SAST scanners.",
        f"After LLM-augmented triage by **Qwen 3:8b**, the results were reduced and prioritized as follows:",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total Findings | **{total}** |",
        f"| True Positives (Confirmed) | **{tp_count}** |",
        f"| False Positives (Suppressed) | **{fp_count}** |",
        f"| Needs Manual Review | **{nr_count}** |",
        f"| Critical Risk Findings | **{critical_count}** |",
        f"| High Risk Findings | **{high_count}** |",
        f"| Medium Risk Findings | **{medium_count}** |",
        "",
        "---",
        "",
        "## Priority Action List (Sorted by Risk Score)",
        "",
        "| Priority | Finding ID | Rule / Bug Type | File:Line | Risk Score | Level | Remediation Summary |",
        "|:---:|---|---|---|:---:|:---:|---|",
    ]

    for idx, f in enumerate(sorted_findings, 1):
        score = f.risk_score or 0.0
        if score >= 4.2:
            level = "🔴 CRITICAL"
        elif score >= 3.4:
            level = "🟠 HIGH"
        elif score >= 2.5:
            level = "🟡 MEDIUM"
        else:
            level = "🟢 LOW"

        remediation_summary = "See remediation_report.json"
        if f.remediation and isinstance(f.remediation, dict):
            remediation_summary = f.remediation.get("summary", remediation_summary)[:60] + "..."

        short_path = f.file_path.replace("\\", "/").split("/repos/")[-1] if "/repos/" in f.file_path.replace("\\", "/") else f.file_path[-50:]
        md.append(f"| **#{idx}** | `{f.finding_id}` | `{f.rule_id}` | `{short_path}:{f.start_line}` | **{score:.2f}** | {level} | {remediation_summary} |")

    md.extend([
        "",
        "---",
        "",
        "## Recommended Next Steps",
        "",
        "1. **Immediate Action (Critical/High)**: Address all Critical and High risk findings within 1 sprint.",
        "2. **Scheduled Remediation (Medium)**: Address Medium risk findings in the next 2 sprints.",
        "3. **Manual Review**: Verify all NEEDS_REVIEW findings with AppSec team.",
        "4. **Re-scan**: After applying fixes, re-run the triage pipeline to confirm remediation.",
        "",
        "---",
        "",
        f"*Full technical details available in `triage_result.json`, `risk_report.json`, and `remediation_report.json`.*",
    ])

    output_path.write_text("\n".join(md), encoding="utf-8")
    return str(output_path)

