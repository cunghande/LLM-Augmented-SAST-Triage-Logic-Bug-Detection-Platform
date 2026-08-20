"""Run and score the Joern-backed pipeline on pinned RealVuln repositories."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
_LOGIC_CWES = {
    "missing_authz_idor": "CWE-639",
    "business_rule_bypass": "CWE-840",
}
_SINK_CWES = {
    "eval": "CWE-95",
    "exec": "CWE-95",
    "system": "CWE-78",
    "run": "CWE-78",
    "call": "CWE-78",
    "popen": "CWE-78",
    "execute": "CWE-89",
    "executemany": "CWE-89",
    "open": "CWE-22",
    "load": "CWE-502",
    "loads": "CWE-502",
    "fromstring": "CWE-611",
    "parse": "CWE-611",
    "render_template_string": "CWE-79",
    "mark_safe": "CWE-79",
    "xpath": "CWE-643",
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=Path("benchmarks/Real-Vuln-Benchmark"),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("benchmarks/BenchmarkOutput/realvuln-v2-joern"),
    )
    parser.add_argument("--provider", choices=("fake", "ollama", "real"), default="fake")
    parser.add_argument("--repo-id", action="append", default=[])
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _report_is_current(report: Path, commit_sha: str, provider: str) -> bool:
    if not report.is_file():
        return False
    try:
        metadata = _load_json(report)["run_metadata"]
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        metadata.get("commit_sha") == commit_sha
        and metadata.get("analysis_backend") == "joern"
        and metadata.get("triage_provider")
        == {"fake": "fake", "ollama": "ollama", "real": "modal-qwen-structured"}[provider]
    )


def _cwe_for_finding(finding: dict[str, Any]) -> str | None:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    raw_cwes = metadata.get("cwe", [])
    if isinstance(raw_cwes, str):
        raw_cwes = [raw_cwes]
    if isinstance(raw_cwes, list):
        for raw in raw_cwes:
            match = _CWE_PATTERN.search(str(raw))
            if match:
                return match.group(0).upper()

    logic_class = str(metadata.get("logic_class", ""))
    if logic_class in _LOGIC_CWES:
        return _LOGIC_CWES[logic_class]
    if finding.get("scanner") == "GITLEAKS":
        return "CWE-798"

    rule_id = str(finding.get("rule_id", ""))
    prefix = "module2.joern.cross-file."
    if rule_id.startswith(prefix):
        return _SINK_CWES.get(rule_id.removeprefix(prefix).lower())
    return None


def _semgrep_projection(report: dict[str, Any], *, decisive_only: bool) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for item in report.get("results", []):
        if not isinstance(item, dict):
            continue
        if decisive_only:
            decision = item.get("triage_decision")
            if not isinstance(decision, dict) or decision.get("model_verdict") != "LIKELY_TP":
                continue
        finding = item.get("finding")
        if not isinstance(finding, dict):
            continue
        cwe = _cwe_for_finding(finding)
        if cwe is None:
            continue
        start = int(finding.get("start_line", 1))
        end = int(finding.get("end_line") or start)
        results.append(
            {
                "check_id": str(finding.get("rule_id", "sast-triage.unknown")),
                "path": str(finding.get("file_path", "")),
                "start": {"line": start, "col": 1},
                "end": {"line": end, "col": 1},
                "extra": {
                    "message": str(finding.get("message", "Security finding.")),
                    "severity": str(finding.get("severity", "WARNING")),
                    "metadata": {"cwe": [cwe], "confidence": "MEDIUM"},
                },
            }
        )
    return {"version": "1.0.0", "results": results, "errors": []}


def _score_projection(
    benchmark_root: Path,
    repo_id: str,
    projection_path: Path,
    scanner_name: str,
) -> dict[str, Any]:
    benchmark_text = str(benchmark_root.resolve())
    if benchmark_text not in sys.path:
        sys.path.insert(0, benchmark_text)
    from parsers import get_parser  # type: ignore[import-not-found]
    from scorer.matcher import (  # type: ignore[import-not-found]
        load_ground_truth,
        match_findings,
    )
    from scorer.metrics import compute_scorecard  # type: ignore[import-not-found]

    ground_truth_path = benchmark_root / "ground-truth" / repo_id / "ground-truth.json"
    families = _load_json(benchmark_root / "config" / "cwe-families.json")
    ground_truth = load_ground_truth(str(ground_truth_path))
    findings = get_parser("semgrep").parse(str(projection_path))
    matches = match_findings(findings, ground_truth)
    return compute_scorecard(repo_id, scanner_name, "", matches, families).to_dict()


def _aggregate(cards: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        name: sum(int(card.get(name, 0)) for card in cards)
        for name in ("tp", "fp", "fn", "tn")
    }
    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f2 = 5 * precision * recall / (4 * precision + recall) if 4 * precision + recall else 0.0
    f3 = 10 * precision * recall / (9 * precision + recall) if 9 * precision + recall else 0.0
    return {
        **counts,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "f2_score": round(f2 * 100, 2),
        "f3_score": round(f3 * 100, 2),
    }


def _write_summary(
    output_root: Path,
    provider: str,
    cards: list[dict[str, Any]],
    decisive_cards: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> None:
    summary = {
        "schema_version": "realvuln-sast-triage-joern-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "provider": provider,
        "analysis_backend": "joern",
        "repositories_completed": len(cards),
        "detection": _aggregate(cards),
        "decisive_likely_tp": _aggregate(decisive_cards),
        "repository_scores": cards,
        "decisive_repository_scores": decisive_cards,
        "failures": failures,
    }
    (output_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    """Run selected pinned repositories and update a resumable score summary."""
    args = _arguments()
    benchmark_root = args.benchmark_root.resolve()
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    selected = set(args.repo_id)
    cards: list[dict[str, Any]] = []
    decisive_cards: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    ground_truth_paths = sorted((benchmark_root / "ground-truth").glob("*/ground-truth.json"))
    for position, ground_truth_path in enumerate(ground_truth_paths, start=1):
        ground_truth = _load_json(ground_truth_path)
        repo_id = ground_truth_path.parent.name
        if selected and repo_id not in selected:
            continue
        repository = benchmark_root / "repos" / repo_id
        run_dir = output_root / "runs" / repo_id
        report_path = run_dir / "report.json"
        commit_sha = str(ground_truth.get("commit_sha", ""))
        print(f"[{position}/{len(ground_truth_paths)}] {repo_id}", flush=True)

        if args.overwrite or not _report_is_current(report_path, commit_sha, args.provider):
            command = [
                sys.executable,
                "-m",
                "sast_triage",
                "scan-and-triage",
                "--repository",
                str(repository),
                "--output-dir",
                str(run_dir),
                "--repository-identifier",
                repo_id,
                "--provider",
                args.provider,
                "--semgrep-config",
                "p/python",
                "--semgrep-config",
                "p/security-audit",
                "--module2",
                "--module2-discovery",
                "--logic-detector",
                "python-idor-business-logic",
                "--overwrite",
            ]
            completed = subprocess.run(command, check=False)
            if completed.returncode != 0:
                failures.append({"repository": repo_id, "exit_code": completed.returncode})
                _write_summary(output_root, args.provider, cards, decisive_cards, failures)
                continue

        report = _load_json(report_path)
        projection_dir = output_root / "projections" / repo_id
        projection_dir.mkdir(parents=True, exist_ok=True)
        detection_path = projection_dir / "detection.json"
        decisive_path = projection_dir / "decisive-likely-tp.json"
        detection_path.write_text(
            json.dumps(_semgrep_projection(report, decisive_only=False), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decisive_path.write_text(
            json.dumps(_semgrep_projection(report, decisive_only=True), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        cards.append(_score_projection(benchmark_root, repo_id, detection_path, "sast-triage-joern"))
        decisive_cards.append(
            _score_projection(benchmark_root, repo_id, decisive_path, "sast-triage-joern-decisive")
        )
        # These are transient scanner inputs. Gitleaks JSON contains raw
        # matches, and scanner fingerprints may contain absolute paths.
        shutil.rmtree(run_dir / "scanner-artifacts", ignore_errors=True)
        _write_summary(output_root, args.provider, cards, decisive_cards, failures)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
