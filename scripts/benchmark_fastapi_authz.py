"""Run the offline FastAPI authorization detector benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.context.repository_index import build_repository_index
from sast_triage.evaluation.logic_authz import (
    evaluate_logic_authz_dataset,
    load_logic_authz_dataset,
)


def main() -> int:
    """Evaluate all repository roots referenced by one source-free manifest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--target-files-only",
        action="store_true",
        help="Index only files named by a pinned endpoint-level manifest.",
    )
    args = parser.parse_args()
    dataset = load_logic_authz_dataset(args.manifest)
    roots = {case.repository_identifier: Path(case.repository_root) for case in dataset.cases}
    endpoints = []
    for identifier, root in sorted(roots.items()):
        resolved = root if root.is_absolute() else (Path.cwd() / root).resolve()
        target_files = frozenset(
            case.file_path for case in dataset.cases if case.repository_identifier == identifier
        )
        index = build_repository_index(
            resolved,
            identifier,
            include_file_paths=target_files if args.target_files_only else None,
        )
        endpoints.extend(index.analyze_fastapi_authorization())
    result = evaluate_logic_authz_dataset(dataset, tuple(endpoints))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    held_out = result["metrics_by_split"]["held_out"]
    report_path = args.output.with_suffix(".md")
    report_path.write_text(
        "# FastAPI authorization benchmark\n\n"
        f"- Dataset: `{result['version']}` ({result['dataset_kind']})\n"
        f"- Repositories: {result['repository_count']}\n"
        f"- Held-out cases: {held_out['total_cases']}\n"
        f"- Precision: {held_out['precision']:.3f}\n"
        f"- Recall: {held_out['recall']:.3f}\n"
        f"- F1: {held_out['f1']:.3f}\n"
        f"- Quality claim supported: `{result['quality_claim_supported']}`\n",
        encoding="utf-8",
    )
    print(
        "FastAPI authorization benchmark: "
        f"precision={held_out['precision']:.3f} "
        f"recall={held_out['recall']:.3f} "
        f"f1={held_out['f1']:.3f} "
        f"gate={'PASS' if result['quality_gate']['passed'] else 'FAIL'}"
    )
    return 0 if result["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
