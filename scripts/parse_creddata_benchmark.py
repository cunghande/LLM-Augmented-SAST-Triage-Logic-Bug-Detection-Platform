"""
Convert Samsung CredData meta CSVs into Unified Ground Truth JSON schema.
Selects 25 most diverse repos (by credential type) from 335 available.

Source: repos/CredData/meta/{repo_hash}.csv
Output: benchmark/CredData_ground_truth.json
        benchmark/CredData_selected_repos.json (list of selected repos)
"""

import csv
import json
import collections
from pathlib import Path

META_DIR = Path("repos/CredData/meta")
OUTPUT_JSON = Path("benchmark/CredData_ground_truth.json")
SELECTED_REPOS_JSON = Path("benchmark/CredData_selected_repos.json")
MAX_REPOS = 25


def select_diverse_repos(meta_dir: Path, max_repos: int = MAX_REPOS):
    """
    Select repos with maximum diversity across credential categories.
    Strategy:
    1. Count category distribution per repo
    2. Pick repos that cover the most unique categories
    3. Prioritize repos with mix of TP (T) and FP (F) labels
    """
    repo_stats = {}

    for csv_file in sorted(meta_dir.glob("*.csv")):
        repo_name = csv_file.stem
        categories = collections.Counter()
        labels = collections.Counter()
        total_entries = 0

        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cat = row.get("Category", "Unknown")
                    label = row.get("GroundTruth", "")
                    categories[cat] += 1
                    labels[label] += 1
                    total_entries += 1
        except Exception:
            continue

        if total_entries == 0:
            continue

        repo_stats[repo_name] = {
            "categories": dict(categories),
            "labels": dict(labels),
            "total": total_entries,
            "num_categories": len(categories),
            "has_tp": labels.get("T", 0) > 0,
            "has_fp": labels.get("F", 0) > 0,
            "tp_count": labels.get("T", 0),
            "fp_count": labels.get("F", 0),
        }

    # Score repos: prefer those with both TP+FP, multiple categories, reasonable size
    for repo, stats in repo_stats.items():
        score = 0
        score += stats["num_categories"] * 3  # Category diversity
        if stats["has_tp"] and stats["has_fp"]:
            score += 20  # Both labels present
        elif stats["has_tp"]:
            score += 10
        # Prefer repos with 5-200 entries (not too small, not too huge)
        if 5 <= stats["total"] <= 200:
            score += 15
        elif stats["total"] > 200:
            score += 5
        stats["score"] = score

    # Sort by score descending, select top N
    sorted_repos = sorted(repo_stats.items(), key=lambda x: x[1]["score"], reverse=True)
    selected = sorted_repos[:max_repos]

    return {name: stats for name, stats in selected}


def convert_creddata_benchmark_gt():
    if not META_DIR.exists():
        print(f"[!] Error: {META_DIR} not found!")
        return

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    # Step 1: Select diverse repos
    print(f"[*] Analyzing {len(list(META_DIR.glob('*.csv')))} CredData repos for diversity selection...")
    selected_repos = select_diverse_repos(META_DIR)
    print(f"[+] Selected {len(selected_repos)} repos for benchmark evaluation")

    # Save selection info
    with open(SELECTED_REPOS_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {name: {"total": s["total"], "tp": s["tp_count"], "fp": s["fp_count"],
                     "categories": s["categories"]}
             for name, s in selected_repos.items()},
            f, indent=2, ensure_ascii=False
        )

    # Step 2: Convert ground truth for selected repos
    gt_list = []
    for repo_name in selected_repos:
        csv_file = META_DIR / f"{repo_name}.csv"
        if not csv_file.exists():
            continue

        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    label = row.get("GroundTruth", "").strip()
                    if label not in ("T", "F"):
                        continue

                    file_path = row.get("FilePath", "")
                    line_start = int(row.get("LineStart", 0)) if row.get("LineStart", "").strip() else 0
                    line_end = int(row.get("LineEnd", line_start)) if row.get("LineEnd", "").strip() else line_start
                    category = row.get("Category", "Unknown")
                    file_id = row.get("FileID", "")
                    entry_id = row.get("Id", "")

                    verdict = "TP" if label == "T" else "FP"
                    finding_id = f"CRED-{repo_name}-{entry_id}" if entry_id else f"CRED-{repo_name}-{idx}"

                    item = {
                        "finding_id": finding_id,
                        "ground_truth_verdict": verdict,
                        "reviewer_notes": f"CredData [{repo_name}] Category: {category}, File: {file_path}:{line_start}",
                        "confidence_level": "HIGH",
                        # Extended fields for matching
                        "repo_name": repo_name,
                        "file_path": file_path,
                        "line_start": line_start,
                        "line_end": line_end,
                        "category": category,
                        "file_id": file_id,
                    }
                    gt_list.append(item)
        except Exception as e:
            print(f"[!] Warning: Failed to parse {csv_file}: {e}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(gt_list, f, indent=2, ensure_ascii=False)

    tp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "TP")
    fp_count = sum(1 for x in gt_list if x["ground_truth_verdict"] == "FP")
    print(f"[OK] Converted {len(gt_list)} CredData entries from {len(selected_repos)} repos into {OUTPUT_JSON}")
    print(f"     TP: {tp_count} | FP: {fp_count}")

    # Print selected repos summary
    print(f"\n[*] Selected repos summary:")
    for name, stats in sorted(selected_repos.items(), key=lambda x: x[1]["score"], reverse=True):
        cats = list(stats["categories"].keys())[:3]
        print(f"    {name}: {stats['total']} entries (TP:{stats['tp_count']} FP:{stats['fp_count']}) — {', '.join(cats)}")


if __name__ == "__main__":
    convert_creddata_benchmark_gt()
