"""
Convert OWASP Benchmark CSV ground truth (expectedresults-1.2.csv)
into Unified Ground Truth JSON schema for evaluate command.
"""

import csv
import json
from pathlib import Path

EXPECTED_CSV = Path("repos/BenchmarkJava/expectedresults-1.2.csv")
OUTPUT_JSON = Path("benchmark/BenchmarkJava_ground_truth.json")


def convert_owasp_benchmark_gt():
    if not EXPECTED_CSV.exists():
        print(f"[!] Error: {EXPECTED_CSV} not found!")
        return

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    gt_map = {}
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
                    "reviewer_notes": f"OWASP Benchmark 1.2 Category: {category}, CWE: {cwe}",
                    "confidence_level": "HIGH"
                }
                gt_list.append(item)
                gt_map[test_name] = verdict

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(gt_list, f, indent=2, ensure_ascii=False)

    print(f"[OK] Converted {len(gt_list)} OWASP Benchmark testcases into {OUTPUT_JSON}")


if __name__ == "__main__":
    convert_owasp_benchmark_gt()
