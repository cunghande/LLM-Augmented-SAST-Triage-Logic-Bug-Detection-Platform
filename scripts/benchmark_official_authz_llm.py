"""Run real-LLM triage on candidates from the official authz corpus."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.application.providers import provider_session
from sast_triage.context.repository_index import FASTAPI_AUTHZ_CONFIG_ID, build_repository_index
from sast_triage.evaluation.logic_authz import load_logic_authz_dataset
from sast_triage.errors import SastTriageError
from sast_triage.models import ArtifactRepositoryMatch, ScannerParseResult, TriageResult
from sast_triage.pipeline.batch import triage_batch


def _safe_result(result: TriageResult, case: Any) -> dict[str, Any]:
    """Serialize only public result fields plus source-free ground truth."""
    payload = result.model_dump(mode="json")
    payload["ground_truth"] = {
        "case_id": case.case_id,
        "expected_state": case.expected_state,
        "case_type": case.case_type,
        "advisory_id": case.advisory_id,
        "cwe": case.cwe,
        "commit_sha": case.commit_sha,
        "http_method": case.http_method,
        "route_path": case.route_path,
    }
    return payload


def _summary(records: list[dict[str, Any]], *, elapsed: float, status: str, error_code: str | None) -> dict[str, Any]:
    """Compute selective triage metrics without treating abstentions as correct."""
    verdicts = Counter()
    actions = Counter()
    correct = 0
    auto = 0
    for record in records:
        decision = record.get("triage_decision") or {}
        verdict = decision.get("model_verdict")
        action = (record.get("policy_decision") or {}).get("action")
        verdicts[verdict or "NONE"] += 1
        actions[action or "NONE"] += 1
        if verdict in {"LIKELY_TP", "LIKELY_FP"}:
            auto += 1
            expected = "LIKELY_TP" if record["ground_truth"]["expected_state"] == "MISSING_AUTHZ" else "LIKELY_FP"
            correct += verdict == expected
    total = len(records)
    return {
        "status": status,
        "error_code": error_code,
        "provider": "real-modal-qwen",
        "model": "Qwen/Qwen3-14B-AWQ",
        "prompt_version": "triage-prompt-v11",
        "completed_findings": total,
        "elapsed_seconds": round(elapsed, 3),
        "cost": None,
        "cost_note": "Modal invocation does not expose per-run billing in the provider response.",
        "verdict_counts": dict(sorted(verdicts.items(), key=lambda item: str(item[0]))),
        "policy_action_counts": dict(sorted(actions.items(), key=lambda item: str(item[0]))),
        "auto_decision_coverage": auto / total if total else 0.0,
        "selective_accuracy": correct / auto if auto else None,
        "selective_accuracy_defined": auto > 0,
        "correct_auto_decisions": correct,
        "auto_decisions": auto,
    }


def main() -> int:
    """Triage every emitted official-corpus candidate with one real provider session."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    dataset = load_logic_authz_dataset(args.manifest)
    roots = {case.repository_identifier: Path(case.repository_root) for case in dataset.cases}
    records: list[dict[str, Any]] = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    status = "complete"
    error_code: str | None = None

    def persist() -> None:
        payload = {
            "benchmark": "official-fastapi-authz-real-llm-triage",
            "dataset_version": dataset.version,
            "ground_truth_sha256": dataset.ground_truth_sha256,
            "summary": _summary(
                records,
                elapsed=time.perf_counter() - started,
                status=status,
                error_code=error_code,
            ),
            "results": records,
        }
        args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    try:
        with provider_session("real") as provider:
            for identifier, root in sorted(roots.items()):
                cases = tuple(case for case in dataset.cases if case.repository_identifier == identifier)
                target_files = frozenset(case.file_path for case in cases)
                index = build_repository_index(root, identifier, include_file_paths=target_files)
                locations = {(case.file_path, case.route_line): case for case in cases}
                findings = tuple(
                    finding
                    for finding in index.discover_fastapi_authorization_findings()
                    if (finding.file_path, finding.start_line) in locations
                )
                if not findings:
                    continue
                before = len(records)

                def save_progress(results: tuple[TriageResult, ...]) -> None:
                    del records[before:]
                    records.extend(
                        _safe_result(result, locations[(result.finding.file_path, result.finding.start_line)])
                        for result in results
                    )
                    persist()

                batch = triage_batch(
                    root,
                    provider,
                    module2_result=ScannerParseResult(findings=findings),
                    repository_index=index,
                    logic_detector="fastapi-missing-authz",
                    logic_detector_version="sprint2-v3",
                    repository_identifier=identifier,
                    commit_sha=cases[0].commit_sha,
                    working_tree_state="pinned_external_revision",
                    artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
                    prompt_version="triage-prompt-v11",
                    output_schema_version="triage-decision-v1",
                    prompt_type="benchmark.official-authz",
                    scanner_config_ids={"MODULE2": FASTAPI_AUTHZ_CONFIG_ID},
                    cli_mode="official-authz-real-llm-benchmark",
                    progress_callback=save_progress,
                    triage_provider_name="real-modal-qwen",
                    model_version="Qwen/Qwen3-14B-AWQ",
                )
                save_progress(tuple(batch.results))
    except SastTriageError as exc:
        status = "resource_exhausted" if exc.error_code == "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED" else "provider_error"
        error_code = exc.error_code
        persist()
        print(f"Real LLM stopped: status={status} error_code={error_code} completed={len(records)}")
        return 2

    persist()
    report = _summary(records, elapsed=time.perf_counter() - started, status=status, error_code=error_code)
    args.output.with_suffix(".md").write_text(
        "# Official FastAPI authorization real-LLM benchmark\n\n"
        f"- Status: `{report['status']}`\n"
        f"- Completed findings: {report['completed_findings']}\n"
        f"- Selective accuracy: "
        f"{report['selective_accuracy'] if report['selective_accuracy'] is not None else 'N/A (no auto decisions)'}\n"
        f"- Auto-decision coverage: {report['auto_decision_coverage']:.3f}\n"
        f"- Runtime: {report['elapsed_seconds']:.3f} seconds\n"
        f"- Cost: unavailable from provider response\n",
        encoding="utf-8",
    )
    print(
        f"Real LLM complete: findings={report['completed_findings']} "
        f"selective_accuracy={report['selective_accuracy'] if report['selective_accuracy'] is not None else 'N/A'} "
        f"coverage={report['auto_decision_coverage']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
