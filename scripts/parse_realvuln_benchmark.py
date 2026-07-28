"""
Convert Real-Vuln-Benchmark ground-truth JSON files into
Unified Ground Truth JSON schema for evaluate command.

Source: repos/Real-Vuln-Benchmark/ground-truth/{repo}/ground-truth.json
Output: benchmark/RealVuln_ground_truth.json
"""

import json
from pathlib import Path

GT_DIR = Path("repos/Real-Vuln-Benchmark/ground-truth")
OUTPUT_JSON = Path("benchmark/RealVuln_ground_truth.json")


def convert_realvuln_benchmark_gt():
    if not GT_DIR.exists():
        print(f"[!] Error: {GT_DIR} not found!")
        return

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    gt_list = []
    repo_count = 0

    for gt_file in sorted(GT_DIR.rglob("ground-truth.json")):
        try:
            with open(gt_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to parse {gt_file}: {e}")
            continue

        repo_id = data.get("repo_id", gt_file.parent.name)
        repo_url = data.get("repo_url", "")
        language = data.get("language", "unknown")
        framework = data.get("framework", "unknown")
        findings = data.get("findings", [])
        repo_count += 1

        for finding in findings:
            finding_id = finding.get("id", "")
            is_vulnerable = finding.get("is_vulnerable", False)
            vuln_class = finding.get("vulnerability_class", "")
            primary_cwe = finding.get("primary_cwe", "")
            acceptable_cwes = finding.get("acceptable_cwes", [])
            file_path = finding.get("file", "")
            location = finding.get("location", {})
            start_line = location.get("start_line", 0)
            end_line = location.get("end_line", start_line)
            function = location.get("function", "")
            severity = finding.get("severity", "medium")
            evidence = finding.get("evidence", {})
            description = evidence.get("description", "")

            verdict = "TP" if is_vulnerable else "FP"

            item = {
                "finding_id": finding_id,
                "ground_truth_verdict": verdict,
                "reviewer_notes": f"RealVuln [{repo_id}] {vuln_class}: {description[:120]}",
                "confidence_level": "HIGH",
                # Extended fields for matching
                "repo_id": repo_id,
                "repo_url": repo_url,
                "language": language,
                "framework": framework,
                "vulnerability_class": vuln_class,
                "primary_cwe": primary_cwe,
                "acceptable_cwes": acceptable_cwes,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "function": function,
                "severity": severity,
            }
            gt_list.append(item)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(gt_list, f, indent=2, ensure_ascii=False)

    tp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "TP")
    fp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "FP")
    print(f"[OK] Converted {len(gt_list)} findings from {repo_count} repos into {OUTPUT_JSON}")
    print(f"     TP: {tp_count} | FP: {fp_count}")


if __name__ == "__main__":
    convert_realvuln_benchmark_gt()
