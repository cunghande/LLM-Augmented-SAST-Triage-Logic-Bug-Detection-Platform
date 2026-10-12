"""Build a verified benchmark dataset from real open-source vulnerable Python repositories."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)

REPO_SPLIT_MAP = {
    "realvuln-pygoat": "development",
    "realvuln-djangoat": "calibration",
    "realvuln-dvpwa": "calibration",
    "realvuln-vulpy": "held_out",
    "realvuln-damn-vulnerable-flask-application": "held_out",
}


def get_cwes(finding: dict[str, Any]) -> set[str]:
    meta = finding.get("metadata") or {}
    raw = meta.get("cwe", [])
    if isinstance(raw, str):
        raw = [raw]
    res = set()
    for c in raw:
        m = CWE_PATTERN.search(str(c))
        if m:
            res.add(m.group(0).upper())
    return res


def build_benchmark(
    runs_dir: Path,
    gt_dir: Path,
    output_path: Path,
    version: str = "curated-realvuln-v1",
) -> dict[str, Any]:
    records: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    for repo_name, split in REPO_SPLIT_MAP.items():
        rep_file = runs_dir / repo_name / "report.json"
        gt_file = gt_dir / repo_name / "ground-truth.json"
        if not rep_file.is_file() or not gt_file.is_file():
            raise FileNotFoundError(f"Missing report or ground-truth for {repo_name}")

        rep_data = json.loads(rep_file.read_text(encoding="utf-8"))
        gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
        results = rep_data.get("results", [])
        gt_list = gt_data.get("findings", [])

        for item in results:
            f = item.get("finding", {})
            f_id = f.get("finding_instance_id")
            if not f_id or f_id in seen_ids:
                continue
            seen_ids.add(f_id)

            f_file = f.get("file_path", "").replace("\\", "/").strip("/")
            f_start = f.get("start_line", 1)
            f_end = f.get("end_line") or f_start
            f_cwes = get_cwes(f)
            scanner = f.get("scanner", "SEMGREP")
            rule_id = f.get("rule_id", "unknown_rule")

            is_tp = False
            matched_gt = None
            matched_desc = ""

            for gt in gt_list:
                gt_file_p = gt.get("file", "").replace("\\", "/").strip("/")
                if f_file != gt_file_p:
                    continue
                acc_cwes = set(gt.get("acceptable_cwes", []))
                if f_cwes and acc_cwes and not (f_cwes & acc_cwes):
                    continue
                loc = gt.get("location", {})
                gt_s = loc.get("start_line")
                gt_e = loc.get("end_line") or gt_s
                tol = 10
                if gt_s is not None:
                    if (f_start <= (gt_e + tol)) and (f_end >= (gt_s - tol)):
                        is_tp = bool(gt.get("is_vulnerable", True))
                        matched_gt = gt.get("id")
                        matched_desc = gt.get("evidence", {}).get("description", "")
                        break

            expected_label = "TP" if is_tp else "FP"
            rationale = (
                f"Matched ground truth vulnerability {matched_gt}: {matched_desc[:120]}"
                if is_tp
                else f"No vulnerable ground truth entry at {f_file}:{f_start}-{f_end} matching rule {rule_id}"
            )

            records.append(
                {
                    "benchmark_id": f"bench-{repo_name}-{f_id[:8]}",
                    "repository_identifier": repo_name,
                    "scanner": scanner,
                    "artifact_reference": "report.json",
                    "finding_instance_id": f_id,
                    "expected_label": expected_label,
                    "reviewer_rationale": rationale,
                    "evidence_reference": f"{f_file}:{f_start}",
                    "split": split,
                    "benchmark_version": version,
                }
            )

    benchmark_json = {
        "version": version,
        "dataset_kind": "curated_realvuln",
        "description": "Curated benchmark dataset from OWASP PyGoat, DjanGoat, DVPWA, VulPy, and DVFA",
        "records": records,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(benchmark_json, indent=2), encoding="utf-8")
    return benchmark_json


if __name__ == "__main__":
    runs = Path("benchmarks/BenchmarkOutput/realvuln-v2-joern/runs")
    gt = Path("benchmarks/Real-Vuln-Benchmark/ground-truth")
    out = Path("benchmarks/curated_benchmark.json")
    data = build_benchmark(runs, gt, out)
    print(f"Built benchmark with {len(data['records'])} records at {out}")
