"""Chạy tập con OWASP đã gán nhãn qua Qwen3-14B-AWQ trên Modal."""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import modal

from modal_apps.qwen14b_modal import MODEL_ID, Qwen14B, app
from sast_triage.errors import SastTriageError
from sast_triage.evaluation.owasp_benchmark import (
    DEFAULT_SEMGREP_RULE_CATEGORY_MAP,
    OWASP_RULE_MAPPING_VERSION,
    load_owasp_expected_results,
)
from sast_triage.models import (
    ArtifactRepositoryMatch,
    ModelVerdict,
    ScannerParseResult,
    TriageDecision,
    TriageInput,
)
from sast_triage.parsers.semgrep import parse_semgrep_json
from sast_triage.pipeline.batch import triage_batch
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = PROJECT_ROOT / "benchmarks" / "BenchmarkPython"
SEMGREP_ARTIFACT = PROJECT_ROOT / "benchmarks" / "BenchmarkRun" / "semgrep.json"
EXPECTED_RESULTS = BENCHMARK_ROOT / "expectedresults-0.1.csv"
OUTPUT_JSON = (
    PROJECT_ROOT
    / "benchmarks"
    / "BenchmarkOutput"
    / "qwen3-14b-awq-triage-benchmark.json"
)
OUTPUT_MARKDOWN = OUTPUT_JSON.with_suffix(".md")
PROMPT_VERSION = "triage-prompt-v4"
OUTPUT_SCHEMA_VERSION = "triage-decision-v1"
_TEST_NAME = re.compile(r"BenchmarkTest\d{5}")


def _decision_schema() -> dict[str, object]:
    """Trả về schema output có ràng buộc chính xác mà pipeline yêu cầu."""
    properties: dict[str, object] = {
        "model_verdict": {
            "type": "string",
            "enum": ["LIKELY_TP", "LIKELY_FP", "NEEDS_REVIEW"],
        },
        "model_confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"],
        },
        "summary": {"type": "string", "minLength": 1},
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "missing_information": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "assumptions": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 20,
        },
        "model_version": {"type": "string", "enum": [MODEL_ID]},
        "prompt_version": {"type": "string", "enum": [PROMPT_VERSION]},
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


class ModalQwenProvider:
    """Adapter pipeline đồng bộ cho lớp Qwen Modal độc lập."""

    provider_name = "modal-qwen-structured"
    model_version = MODEL_ID

    def __init__(self, remote_model: Qwen14B) -> None:
        self._remote_model = remote_model
        self._schema = _decision_schema()
        self._completed = 0

    def triage(self, triage_input: TriageInput) -> TriageDecision:
        """Tạo prompt an toàn, yêu cầu JSON có ràng buộc và validate kết quả."""
        if not isinstance(triage_input, TriageInput):
            raise SastTriageError(
                "Modal Qwen provider requires TriageInput.",
                "TRIAGE_INVALID_INPUT",
            )
        prompt = build_triage_prompt(triage_input, model_version=self.model_version)
        messages = [
            {"role": "system", "content": prompt.system_message},
            {"role": "user", "content": prompt.user_message},
        ]
        try:
            response = self._remote_model.chat.remote(
                messages=messages,
                thinking=False,
                max_tokens=512,
                json_schema=self._schema,
            )
        except (modal.exception.Error, RuntimeError, TypeError, ValueError):
            raise SastTriageError(
                "Modal Qwen request failed or timed out.",
                "TRIAGE_PROVIDER_MODAL_ERROR",
                retryable=True,
            ) from None
        decision = parse_triage_decision(
            response,
            prompt_version=triage_input.prompt_version,
        )
        self._completed += 1
        if self._completed == 1 or self._completed % 10 == 0:
            print(f"PROGRESS {self._completed}", flush=True)
        return decision


def _mapped_category(rule_id: str) -> str | None:
    """Ánh xạ chính xác một rule Semgrep đã biết sang danh mục OWASP."""
    matches = {
        category
        for token, category in DEFAULT_SEMGREP_RULE_CATEGORY_MAP.items()
        if token in rule_id
    }
    return matches.pop() if len(matches) == 1 else None


def _scoreable_findings() -> tuple[ScannerParseResult, dict[str, bool], dict[str, str], int, int]:
    """Chọn finding có định danh test và danh mục lỗ hổng đã biết."""
    parsed = parse_semgrep_json(SEMGREP_ARTIFACT)
    if parsed.errors:
        raise RuntimeError("The committed Semgrep benchmark artifact did not parse cleanly.")
    dataset = load_owasp_expected_results(EXPECTED_RESULTS)
    cases = {case.test_name: case for case in dataset.cases}
    selected = []
    expected: dict[str, bool] = {}
    categories: dict[str, str] = {}
    unique_cases: set[str] = set()

    for finding in parsed.findings:
        name_match = _TEST_NAME.search(finding.file_path)
        category = _mapped_category(finding.rule_id)
        case = cases.get(name_match.group(0)) if name_match else None
        if case is None or category is None or category != case.category:
            continue
        selected.append(finding)
        expected[finding.finding_instance_id] = case.vulnerable
        categories[finding.finding_instance_id] = case.category
        unique_cases.add(case.test_name)

    if not selected:
        raise RuntimeError("No scoreable OWASP findings were found.")
    return (
        ScannerParseResult(findings=tuple(selected)),
        expected,
        categories,
        len(parsed.findings),
        len(unique_cases),
    )


def _metrics(
    batch_result: Any,
    expected: dict[str, bool],
    categories: dict[str, str],
    *,
    parsed_findings: int,
    unique_cases: int,
    elapsed_seconds: float,
) -> dict[str, object]:
    """Tính metric triage fail-closed mà không serialize nội dung mã nguồn."""
    total = len(batch_result.results)
    vulnerable_total = sum(expected.values())
    benign_total = total - vulnerable_total
    verdicts: Counter[str] = Counter()
    policy_actions: Counter[str] = Counter()
    error_codes: Counter[str] = Counter()
    confusion: Counter[str] = Counter()
    category_stats: dict[str, Counter[str]] = defaultdict(Counter)
    decisive = correct = vulnerable_correct = benign_correct = 0
    schema_success = 0

    for result in batch_result.results:
        finding_id = result.finding.finding_instance_id
        is_vulnerable = expected[finding_id]
        category = categories[finding_id]
        category_stats[category]["total"] += 1
        policy_actions[result.policy_decision.action.value] += 1
        error_codes.update(error.error_code for error in result.processing_errors)

        decision = result.triage_decision
        if decision is None:
            confusion["vulnerable_error" if is_vulnerable else "benign_error"] += 1
            category_stats[category]["error"] += 1
            continue

        schema_success += 1
        verdicts[decision.model_verdict.value] += 1
        if decision.model_verdict == ModelVerdict.NEEDS_REVIEW:
            confusion[
                "vulnerable_needs_review" if is_vulnerable else "benign_needs_review"
            ] += 1
            category_stats[category]["abstain"] += 1
            continue

        decisive += 1
        predicts_vulnerable = decision.model_verdict == ModelVerdict.LIKELY_TP
        is_correct = predicts_vulnerable == is_vulnerable
        confusion[
            ("vulnerable_" if is_vulnerable else "benign_")
            + ("likely_tp" if predicts_vulnerable else "likely_fp")
        ] += 1
        if is_correct:
            correct += 1
            category_stats[category]["correct"] += 1
            if is_vulnerable:
                vulnerable_correct += 1
            else:
                benign_correct += 1
        else:
            category_stats[category]["incorrect"] += 1

    coverage = decisive / total if total else 0.0
    selective_accuracy = correct / decisive if decisive else 0.0
    vulnerable_recognition = (
        vulnerable_correct / vulnerable_total if vulnerable_total else 0.0
    )
    benign_recognition = benign_correct / benign_total if benign_total else 0.0
    return {
        "model": MODEL_ID,
        "benchmark_version": "0.1",
        "mapping_version": OWASP_RULE_MAPPING_VERSION,
        "artifact": "benchmarks/BenchmarkRun/semgrep.json",
        "dataset_scope": "OWASP findings with matching test identity and category",
        "parsed_findings": parsed_findings,
        "scoreable_findings": total,
        "unique_scoreable_cases": unique_cases,
        "ground_truth": {"vulnerable": vulnerable_total, "benign": benign_total},
        "schema_success": schema_success,
        "schema_success_rate": schema_success / total if total else 0.0,
        "errors": total - schema_success,
        "error_codes": dict(sorted(error_codes.items())),
        "verdicts": dict(sorted(verdicts.items())),
        "policy_actions": dict(sorted(policy_actions.items())),
        "decisive": decisive,
        "correct_decisive": correct,
        "coverage": coverage,
        "selective_accuracy": selective_accuracy,
        "accuracy_with_abstentions_unresolved": correct / total if total else 0.0,
        "vulnerable_recognition_rate": vulnerable_recognition,
        "benign_recognition_rate": benign_recognition,
        "balanced_accuracy_with_abstentions_unresolved": (
            vulnerable_recognition + benign_recognition
        )
        / 2,
        "confusion": dict(sorted(confusion.items())),
        "elapsed_seconds_including_cold_start": round(elapsed_seconds, 2),
        "categories": {
            category: dict(sorted(counts.items()))
            for category, counts in sorted(category_stats.items())
        },
        "run_metadata": batch_result.run_metadata.model_dump(mode="json"),
        "limitations": [
            "Single run; no confidence interval or repeated seeds.",
            "This measures LLM triage on scoreable scanner findings, not scanner recall.",
            "OWASP ground truth supplies vulnerable/benign labels only for this run.",
            "NEEDS_REVIEW and provider errors are counted as unresolved.",
        ],
    }


def _write_report(metrics: dict[str, object]) -> None:
    """Ghi artifact benchmark JSON và Markdown không chứa mã nguồn."""
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    truth = metrics["ground_truth"]
    assert isinstance(truth, dict)
    lines = [
        "# Qwen3-14B-AWQ triage benchmark",
        "",
        f"- Model: `{metrics['model']}`",
        f"- Scoreable findings: {metrics['scoreable_findings']}",
        f"- Ground truth: {truth['vulnerable']} vulnerable, {truth['benign']} benign",
        f"- Schema success: {metrics['schema_success_rate']:.2%}",
        f"- Decisive coverage: {metrics['coverage']:.2%}",
        f"- Selective accuracy: {metrics['selective_accuracy']:.2%}",
        (
            "- Accuracy with abstentions/errors unresolved: "
            f"{metrics['accuracy_with_abstentions_unresolved']:.2%}"
        ),
        (
            "- Balanced accuracy with abstentions/errors unresolved: "
            f"{metrics['balanced_accuracy_with_abstentions_unresolved']:.2%}"
        ),
        f"- Elapsed including cold start: {metrics['elapsed_seconds_including_cold_start']} s",
        "",
        "`NEEDS_REVIEW` and provider errors are abstentions/unresolved. This is a single",
        "triage run on scoreable scanner findings, not a scanner precision/recall claim.",
        "",
    ]
    OUTPUT_MARKDOWN.write_text("\n".join(lines), encoding="utf-8")


def run_benchmark(*, limit: int | None, write_report: bool) -> dict[str, object]:
    """Chạy benchmark đầy đủ hoặc giới hạn bằng một ứng dụng Modal tạm thời."""
    scanner_result, expected, categories, parsed_count, unique_cases = (
        _scoreable_findings()
    )
    if limit is not None:
        selected = scanner_result.findings[:limit]
        scanner_result = ScannerParseResult(findings=selected)
        selected_ids = {finding.finding_instance_id for finding in selected}
        expected = {key: value for key, value in expected.items() if key in selected_ids}
        categories = {
            key: value for key, value in categories.items() if key in selected_ids
        }
        unique_cases = len(selected)

    started = time.perf_counter()
    with modal.enable_output(), app.run():
        provider = ModalQwenProvider(Qwen14B())
        batch_result = triage_batch(
            BENCHMARK_ROOT,
            provider,
            semgrep_result=scanner_result,
            repository_identifier="BenchmarkPython-Qwen3-14B-AWQ-scoreable",
            artifact_repository_match=ArtifactRepositoryMatch.VERIFIED,
            prompt_version=PROMPT_VERSION,
            output_schema_version=OUTPUT_SCHEMA_VERSION,
            prompt_type="modal-qwen.structured",
            cli_mode="benchmark-modal-qwen-structured",
        )
    elapsed = time.perf_counter() - started
    metrics = _metrics(
        batch_result,
        expected,
        categories,
        parsed_findings=parsed_count,
        unique_cases=unique_cases,
        elapsed_seconds=elapsed,
    )
    if write_report:
        _write_report(metrics)
    return metrics


def main() -> int:
    """Parse tham số benchmark cục bộ, chạy Modal và in metric an toàn."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be greater than zero")
    metrics = run_benchmark(limit=args.limit, write_report=not args.no_write)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
