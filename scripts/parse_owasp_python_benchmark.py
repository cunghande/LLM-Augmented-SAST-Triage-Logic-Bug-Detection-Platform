"""
Convert OWASP BenchmarkPython CSV ground truth (expectedresults-0.1.csv)
into Unified Ground Truth JSON schema for evaluate command.
"""

import json
from pathlib import Path

EXPECTED_CSV = Path("repos/BenchmarkPython/expectedresults-0.1.csv")
OUTPUT_JSON = Path("benchmark/BenchmarkPython_ground_truth.json")


def convert_owasp_python_benchmark_gt():
    if not EXPECTED_CSV.exists():
        print(f"[!] Error: {EXPECTED_CSV} not found!")
        return

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    gt_list = []

    with open(EXPECTED_CSV, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                test_name = parts[0].strip()
                category = parts[1].strip()
                is_real_vuln = parts[2].strip().lower() == "true"
                cwe = parts[3].strip() if len(parts) > 3 else ""

                verdict = "TP" if is_real_vuln else "FP"

                item = {
                    "finding_id": test_name,
                    "ground_truth_verdict": verdict,
                    "reviewer_notes": f"OWASP BenchmarkPython 0.1 Category: {category}, CWE: {cwe}",
                    "confidence_level": "HIGH",
                    "category": category,
                    "cwe": cwe
                }
                gt_list.append(item)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(gt_list, f, indent=2, ensure_ascii=False)

    tp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "TP")
    fp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "FP")
    print(f"[OK] Converted {len(gt_list)} OWASP BenchmarkPython testcases into {OUTPUT_JSON}")
    print(f"     TP: {tp_count} | FP: {fp_count}")


if __name__ == "__main__":
    convert_owasp_python_benchmark_gt()
