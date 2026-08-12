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

from modal_apps.qwen14b_modal import GPU, MODEL_ID, Qwen14B, app
from sast_triage.analysis.factory import analysis_backend_session
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
from sast_triage.triage.modal_provider import (
    minimal_recovery_schema,
    parse_minimal_recovery_decision,
)
from sast_triage.triage.output_validator import parse_triage_decision
from sast_triage.triage.prompt_builder import build_triage_prompt

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = PROJECT_ROOT / "benchmarks" / "BenchmarkPython"
SEMGREP_ARTIFACT = PROJECT_ROOT / "benchmarks" / "BenchmarkRun" / "semgrep-p-python.json"
EXPECTED_RESULTS = BENCHMARK_ROOT / "expectedresults-0.1.csv"
OUTPUT_JSON = (
    PROJECT_ROOT
    / "benchmarks"
    / "BenchmarkOutput"
    / "qwen3-14b-awq-triage-benchmark-v8-b200.json"
)
JOERN_OUTPUT_JSON = OUTPUT_JSON.with_name(
    "qwen3-14b-awq-triage-benchmark-v9-joern-b200.json"
)
BASELINE_JSON = (
    PROJECT_ROOT
    / "benchmarks"
    / "BenchmarkOutput"
    / "qwen3-14b-awq-triage-benchmark-v8-b200.json"
)
PROMPT_VERSION = "triage-prompt-v9"
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
        "summary": {"type": "string", "minLength": 1, "maxLength": 240},
        "evidence": {
            "type": "array",
            "items": {"type": "string", "maxLength": 160},
            "maxItems": 6,
        },
        "missing_information": {
            "type": "array",
            "items": {"type": "string", "maxLength": 120},
            "maxItems": 4,
        },
        "assumptions": {
            "type": "array",
            "items": {"type": "string", "maxLength": 120},
            "maxItems": 4,
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
        self._context_status: dict[str, str] = {}
        self._path_types: dict[str, str] = {}
        self._request_durations: list[float] = []
        self.minimal_schema_recoveries = 0

    def triage(self, triage_input: TriageInput) -> TriageDecision:
        """Tạo prompt an toàn, yêu cầu JSON có ràng buộc và validate kết quả."""
        if not isinstance(triage_input, TriageInput):
            raise SastTriageError(
                "Modal Qwen provider requires TriageInput.",
                "TRIAGE_INVALID_INPUT",
            )
        prompt = build_triage_prompt(triage_input, model_version=self.model_version)
        try:
            evidence = json.loads(triage_input.context.sanitized_snippet or "{}")
        except json.JSONDecodeError:
            evidence = {}
        completeness = evidence.get("context_completeness", {}) if isinstance(evidence, dict) else {}
        taint_path = evidence.get("taint_path", {}) if isinstance(evidence, dict) else {}
        self._context_status[triage_input.finding.finding_instance_id] = (
            str(completeness.get("status", "unavailable"))
            if isinstance(completeness, dict)
            else "unavailable"
        )
        self._path_types[triage_input.finding.finding_instance_id] = (
            str(taint_path.get("path_type", "unknown"))
            if isinstance(taint_path, dict)
            else "unknown"
        )
        messages = [
            {"role": "system", "content": prompt.system_message},
            {"role": "user", "content": prompt.user_message},
        ]
        request_started = time.perf_counter()
        decision: TriageDecision | None = None
        for max_tokens in (512, 1536):
            request_messages = messages
            if max_tokens == 1536:
                request_messages = [
                    {
                        "role": "system",
                        "content": (
                            prompt.system_message
                            + "\n\nOUTPUT RECOVERY: The previous serialization was invalid. "
                            "Return a shorter schema-valid JSON object. Do not quote or copy "
                            "source expressions, string literals, backslashes, or nested quotes. "
                            "Use at most 3 short summary sentences and 4 short evidence items."
                        ),
                    },
                    messages[1],
                ]
            try:
                response = self._remote_model.chat.remote(
                    messages=request_messages,
                    thinking=False,
                    max_tokens=max_tokens,
                    json_schema=self._schema,
                    temperature=0.0,
                    seed=42,
                )
            except (modal.exception.Error, RuntimeError, TypeError, ValueError):
                raise SastTriageError(
                    "Modal Qwen request failed or timed out.",
                    "TRIAGE_PROVIDER_MODAL_ERROR",
                    retryable=True,
                ) from None
            try:
                decision = parse_triage_decision(
                    response,
                    prompt_version=triage_input.prompt_version,
                )
                break
            except SastTriageError as exc:
                recoverable = {
                    "TRIAGE_OUTPUT_INVALID_JSON",
                    "TRIAGE_OUTPUT_SCHEMA_INVALID",
                }
                if max_tokens == 1536 and exc.error_code in recoverable:
                    try:
                        json.loads(response)
                    except json.JSONDecodeError as decode_error:
                        print(
                            "SAFE_OUTPUT_DIAGNOSTIC "
                            f"finding={triage_input.finding.finding_instance_id} "
                            f"file={triage_input.finding.file_path} "
                            f"line={triage_input.finding.start_line} "
                            f"length={len(response)} "
                            f"json_error={decode_error.msg} "
                            f"position={decode_error.pos} "
                            f"code_fence={'```' in response} "
                            f"control_char={any(ord(char) < 32 and char not in chr(9)+chr(10)+chr(13) for char in response)}",
                            flush=True,
                        )
                if exc.error_code not in recoverable:
                    raise
                if max_tokens == 1536:
                    break
        if decision is None:  # pragma: no cover - defensive invariant
            recovery_messages = [
                {
                    "role": "system",
                    "content": (
                        prompt.system_message
                        + "\n\nMINIMAL OUTPUT RECOVERY: Return only model_verdict and "
                        "model_confidence using the supplied strict schema."
                    ),
                },
                messages[1],
            ]
            try:
                response = self._remote_model.chat.remote(
                    messages=recovery_messages,
                    thinking=False,
                    max_tokens=128,
                    json_schema=minimal_recovery_schema(),
                    temperature=0.0,
                    seed=42,
                )
                decision = parse_minimal_recovery_decision(
                    response,
                    prompt_version=triage_input.prompt_version,
                )
                self.minimal_schema_recoveries += 1
            except (modal.exception.Error, RuntimeError, TypeError, ValueError):
                raise SastTriageError(
                    "Modal Qwen minimal recovery failed.",
                    "TRIAGE_PROVIDER_MODAL_ERROR",
                    retryable=True,
                ) from None
        self._request_durations.append(time.perf_counter() - request_started)
        self._completed += 1
        if self._completed == 1 or self._completed % 10 == 0:
            print(f"PROGRESS {self._completed}", flush=True)
        return decision

    def safe_stats(self) -> tuple[dict[str, str], dict[str, str], tuple[float, ...]]:
        """Return safe per-finding evidence classifications without prompt content."""
        return (
            dict(self._context_status),
            dict(self._path_types),
            tuple(self._request_durations),
        )


def _mapped_category(rule_id: str) -> str | None:
    """Ánh xạ chính xác một rule Semgrep đã biết sang danh mục OWASP."""
    matches = {
        category
        for token, category in DEFAULT_SEMGREP_RULE_CATEGORY_MAP.items()
        if token in rule_id
    }
    return matches.pop() if len(matches) == 1 else None


def _scoreable_findings() -> tuple[
    ScannerParseResult,
    dict[str, bool],
    dict[str, str],
    dict[str, str],
    int,
    int,
]:
    """Chọn finding có định danh test và danh mục lỗ hổng đã biết."""
    parsed = parse_semgrep_json(SEMGREP_ARTIFACT)
    if parsed.errors:
        raise RuntimeError("The committed Semgrep benchmark artifact did not parse cleanly.")
    dataset = load_owasp_expected_results(EXPECTED_RESULTS)
    cases = {case.test_name: case for case in dataset.cases}
    selected = []
    expected: dict[str, bool] = {}
    categories: dict[str, str] = {}
    case_names: dict[str, str] = {}
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
        case_names[finding.finding_instance_id] = case.test_name
        unique_cases.add(case.test_name)

    if not selected:
        raise RuntimeError("No scoreable OWASP findings were found.")
    return (
        ScannerParseResult(findings=tuple(selected)),
        expected,
        categories,
        case_names,
        len(parsed.findings),
        len(unique_cases),
    )


def _metrics(
    batch_result: Any,
    expected: dict[str, bool],
    categories: dict[str, str],
    case_names: dict[str, str],
    context_status: dict[str, str],
    path_types: dict[str, str],
    request_durations: tuple[float, ...],
    *,
    parsed_findings: int,
    unique_cases: int,
    elapsed_seconds: float,
    analysis_stats: dict[str, object],
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
    context_counts: Counter[str] = Counter()
    path_type_counts: Counter[str] = Counter()
    context_outcomes: dict[str, Counter[str]] = defaultdict(Counter)
    unsafe_fp_candidate = benign_fp_candidate = 0
    automatic_policy_decisions = 0
    case_predictions: dict[str, list[bool | None]] = defaultdict(list)
    case_truth: dict[str, bool] = {}

    for result in batch_result.results:
        finding_id = result.finding.finding_instance_id
        is_vulnerable = expected[finding_id]
        category = categories[finding_id]
        category_stats[category]["total"] += 1
        action = result.policy_decision.action.value
        policy_actions[action] += 1
        if action in {"LIKELY_TP", "FP_CANDIDATE"}:
            automatic_policy_decisions += 1
        if action == "FP_CANDIDATE":
            if is_vulnerable:
                unsafe_fp_candidate += 1
            else:
                benign_fp_candidate += 1
        error_codes.update(error.error_code for error in result.processing_errors)
        status = context_status.get(finding_id, "unavailable")
        context_counts[status] += 1
        path_type_counts[path_types.get(finding_id, "unknown")] += 1
        case_name = case_names[finding_id]
        case_truth[case_name] = is_vulnerable

        decision = result.triage_decision
        if decision is None:
            confusion["vulnerable_error" if is_vulnerable else "benign_error"] += 1
            category_stats[category]["error"] += 1
            context_outcomes[status]["unresolved"] += 1
            case_predictions[case_name].append(None)
            continue

        schema_success += 1
        verdicts[decision.model_verdict.value] += 1
        if decision.model_verdict == ModelVerdict.NEEDS_REVIEW:
            confusion[
                "vulnerable_needs_review" if is_vulnerable else "benign_needs_review"
            ] += 1
            category_stats[category]["abstain"] += 1
            context_outcomes[status]["unresolved"] += 1
            case_predictions[case_name].append(None)
            continue

        decisive += 1
        predicts_vulnerable = decision.model_verdict == ModelVerdict.LIKELY_TP
        is_correct = predicts_vulnerable == is_vulnerable
        case_predictions[case_name].append(predicts_vulnerable)
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
            context_outcomes[status]["correct"] += 1
        else:
            category_stats[category]["incorrect"] += 1
            context_outcomes[status]["incorrect"] += 1

    coverage = decisive / total if total else 0.0
    selective_accuracy = correct / decisive if decisive else 0.0
    vulnerable_recognition = (
        vulnerable_correct / vulnerable_total if vulnerable_total else 0.0
    )
    benign_recognition = benign_correct / benign_total if benign_total else 0.0
    steady_state = request_durations[1:]
    case_decisive = case_correct = 0
    for case_name, predictions in case_predictions.items():
        decisive_predictions = [item for item in predictions if item is not None]
        if not decisive_predictions:
            continue
        case_decisive += 1
        predicts_vulnerable = any(decisive_predictions)
        case_correct += predicts_vulnerable == case_truth[case_name]
    return {
        "model": MODEL_ID,
        "gpu_requested": GPU,
        "temperature": 0.0,
        "seed": 42,
        "benchmark_version": "0.1",
        "mapping_version": OWASP_RULE_MAPPING_VERSION,
        "analysis": analysis_stats,
        "artifact": "benchmarks/BenchmarkRun/semgrep-p-python.json",
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
        "case_level": {
            "total": len(case_truth),
            "decisive": case_decisive,
            "coverage": case_decisive / len(case_truth) if case_truth else 0.0,
            "selective_accuracy": case_correct / case_decisive if case_decisive else 0.0,
            "accuracy_with_abstentions_unresolved": case_correct / len(case_truth) if case_truth else 0.0,
        },
        "policy_safety": {
            "unsafe_vulnerable_fp_candidate": unsafe_fp_candidate,
            "benign_fp_candidate": benign_fp_candidate,
            "tp_retention_rate": 1 - (unsafe_fp_candidate / vulnerable_total if vulnerable_total else 0.0),
            "automatic_resolution_rate": automatic_policy_decisions / total if total else 0.0,
        },
        "context": {
            "status_counts": dict(sorted(context_counts.items())),
            "path_type_counts": dict(sorted(path_type_counts.items())),
            "outcomes": {
                key: dict(sorted(value.items()))
                for key, value in sorted(context_outcomes.items())
            },
        },
        "confusion": dict(sorted(confusion.items())),
        "elapsed_seconds_including_cold_start": round(elapsed_seconds, 2),
        "latency": {
            "first_request_seconds_including_cold_start": (
                round(request_durations[0], 2) if request_durations else None
            ),
            "steady_state_mean_seconds": (
                round(sum(steady_state) / len(steady_state), 2)
                if steady_state
                else None
            ),
            "steady_state_requests": len(steady_state),
        },
        "categories": {
            category: dict(sorted(counts.items()))
            for category, counts in sorted(category_stats.items())
        },
        "run_metadata": batch_result.run_metadata.model_dump(mode="json"),
        "limitations": [
            "Single deterministic run; no confidence interval.",
            "This measures LLM triage on scoreable scanner findings, not scanner recall.",
            "OWASP ground truth supplies vulnerable/benign labels only for this run.",
            "NEEDS_REVIEW and provider errors are counted as unresolved.",
        ],
    }


def _write_report(
    metrics: dict[str, object],
    output_json: Path,
) -> None:
    """Ghi artifact benchmark JSON và Markdown không chứa mã nguồn."""
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    truth = metrics["ground_truth"]
    policy_safety = metrics["policy_safety"]
    latency = metrics["latency"]
    run_metadata = metrics["run_metadata"]
    assert isinstance(truth, dict)
    assert isinstance(policy_safety, dict)
    assert isinstance(latency, dict)
    assert isinstance(run_metadata, dict)
    analysis = metrics["analysis"]
    quality = metrics["quality_evaluation"]
    assert isinstance(analysis, dict)
    assert isinstance(quality, dict)
    lines = [
        "# Qwen3-14B-AWQ triage benchmark — prompt v9 / B200",
        "",
        f"- Model: `{metrics['model']}`",
        f"- GPU requested: `{metrics['gpu_requested']}`",
        f"- Prompt: `{run_metadata['prompt_version']}`",
        f"- Analysis backend: `{run_metadata['analysis_backend']}`",
        f"- CPG status/build time: `{run_metadata['cpg_build_status']}` / {run_metadata['cpg_build_seconds']} s",
        f"- Query count: {analysis.get('query_count', 0)}",
        f"- Query latency mean: {analysis.get('query_latency_seconds_mean', 0)} s",
        f"- Tool calls: `{analysis.get('tool_call_distribution', {})}`",
        f"- Kết luận quality win: `{quality.get('quality_win')}`",
        f"- Scanner artifact/config: `{metrics['artifact']}` / `p/python`",
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
        f"- Unsafe vulnerable FP candidates: {policy_safety['unsafe_vulnerable_fp_candidate']}",
        f"- Automatic policy resolution: {policy_safety['automatic_resolution_rate']:.2%}",
        f"- Elapsed including cold start: {metrics['elapsed_seconds_including_cold_start']} s",
        (
            "- First request including cold start: "
            f"{latency['first_request_seconds_including_cold_start']} s"
        ),
        f"- Steady-state mean: {latency['steady_state_mean_seconds']} s/finding",
        "",
        "## So sánh với artifact cũ",
        "",
    ]
    if BASELINE_JSON.is_file():
        baseline = json.loads(BASELINE_JSON.read_text(encoding="utf-8"))
        accuracy_improved = (
            metrics["accuracy_with_abstentions_unresolved"]
            > baseline["accuracy_with_abstentions_unresolved"]
        )
        comparison_summary = (
            "Coverage, selective accuracy, overall accuracy và tốc độ đều tăng; policy không "
            "đưa finding mang nhãn vulnerable nào vào FP_CANDIDATE trong lần chạy này."
            if accuracy_improved
            else (
                "Coverage và tốc độ tăng, nhưng accuracy model giảm; đây không phải một "
                "quality win tổng thể."
            )
        )
        lines.extend(
            [
                f"- Coverage: {baseline['coverage']:.2%} → {metrics['coverage']:.2%}",
                (
                    "- Selective accuracy: "
                    f"{baseline['selective_accuracy']:.2%} → {metrics['selective_accuracy']:.2%}"
                ),
                (
                    "- Accuracy khi review/error là unresolved: "
                    f"{baseline['accuracy_with_abstentions_unresolved']:.2%} → "
                    f"{metrics['accuracy_with_abstentions_unresolved']:.2%}"
                ),
                (
                    "- Tổng thời gian: "
                    f"{baseline['elapsed_seconds_including_cold_start']} s → "
                    f"{metrics['elapsed_seconds_including_cold_start']} s"
                ),
                "",
                comparison_summary,
                "",
            ]
        )
    lines.extend(
        [
            "## Giới hạn",
            "",
            "`NEEDS_REVIEW` and provider errors are abstentions/unresolved. This is a single",
            "triage run on scoreable scanner findings, not a scanner precision/recall claim.",
            "OWASP label được map ở cấp test case; một case có nhiều finding có thể làm metric",
            "unsafe-FP bảo thủ hơn độ đúng ở cấp finding.",
            "",
        ]
    )
    output_json.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def _write_report_vi(metrics: dict[str, object], output_json: Path) -> None:
    """Ghi báo cáo A/B tiếng Việt từ các metric an toàn, không chứa mã nguồn."""
    output_json.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    truth = metrics["ground_truth"]
    policy = metrics["policy_safety"]
    context = metrics["context"]
    analysis = metrics["analysis"]
    metadata = metrics["run_metadata"]
    quality = metrics["quality_evaluation"]
    categories = metrics["categories"]
    latency = metrics["latency"]
    assert isinstance(truth, dict)
    assert isinstance(policy, dict)
    assert isinstance(context, dict)
    assert isinstance(analysis, dict)
    assert isinstance(metadata, dict)
    assert isinstance(quality, dict)
    assert isinstance(categories, dict)
    assert isinstance(latency, dict)
    status_counts = context.get("status_counts", {})
    path_counts = context.get("path_type_counts", {})
    required = quality.get("required", {})
    quality_gates = quality.get("quality", {})
    targets = quality.get("targets", {})
    assert isinstance(status_counts, dict)
    assert isinstance(required, dict)
    assert isinstance(quality_gates, dict)
    assert isinstance(targets, dict)
    lines = [
        "# Benchmark Joern CPG với Qwen3-14B-AWQ — prompt v9 / B200",
        "",
        "## 1. Cấu hình cố định",
        "",
        f"- Model/GPU: `{metrics['model']}` / `{metrics['gpu_requested']}`.",
        f"- Prompt/schema: `{metadata['prompt_version']}` / `{OUTPUT_SCHEMA_VERSION}`.",
        (
            f"- Backend: `{metadata['analysis_backend']}` "
            f"`{metadata['analysis_backend_version']}`; "
            f"config `{metadata['analysis_config_id']}`."
        ),
        f"- Artifact/config: `{metrics['artifact']}` / `p/python`.",
        (
            f"- Ground truth: {truth['vulnerable']} vulnerable, "
            f"{truth['benign']} benign; temperature `0`, seed `42`."
        ),
        "",
        "## 2. Kết quả chính",
        "",
        "| Chỉ số | Kết quả |",
        "|---|---:|",
        f"| Schema success | {metrics['schema_success_rate']:.2%} |",
        f"| Provider errors | {metrics['errors']} |",
        (
            "| Accuracy tổng thể | "
            f"{metrics['accuracy_with_abstentions_unresolved']:.2%} |"
        ),
        f"| Selective accuracy | {metrics['selective_accuracy']:.2%} |",
        f"| Nhận diện vulnerable | {metrics['vulnerable_recognition_rate']:.2%} |",
        f"| Nhận diện benign | {metrics['benign_recognition_rate']:.2%} |",
        f"| Automatic resolution | {policy['automatic_resolution_rate']:.2%} |",
        (
            "| Vulnerable bị đưa nhầm vào FP_CANDIDATE | "
            f"{policy['unsafe_vulnerable_fp_candidate']} |"
        ),
        "",
        f"Confusion matrix: `{metrics['confusion']}`.",
        f"Policy actions: `{metrics['policy_actions']}`.",
        "",
        "## 3. Evidence và hiệu năng Joern",
        "",
        (
            f"- CPG `{metadata['cpg_build_status']}`; build "
            f"{metadata['cpg_build_seconds']} giây."
        ),
        f"- Context: `{status_counts}`; path: `{path_counts}`.",
        (
            f"- {analysis.get('query_count', 0)} query; latency trung bình "
            f"{analysis.get('query_latency_seconds_mean', 0)} giây, lớn nhất "
            f"{analysis.get('query_latency_seconds_max', 0)} giây."
        ),
        f"- Tool calls: `{analysis.get('tool_call_distribution', {})}`.",
        (
            "- Minimal-schema recovery: "
            f"{metrics.get('minimal_schema_recoveries', 0)} finding."
        ),
        (
            f"- Tổng thời gian {metrics['elapsed_seconds_including_cold_start']} giây; "
            f"request đầu {latency['first_request_seconds_including_cold_start']} giây; "
            f"steady-state {latency['steady_state_mean_seconds']} giây/finding."
        ),
        "",
        "## 4. Quality gate",
        "",
    ]
    for name, value in (*required.items(), *quality_gates.items(), *targets.items()):
        label = "ĐẠT" if value else "KHÔNG ĐẠT"
        lines.append(f"- `{name}`: **{label}**")
    lines.extend(
        [
            "",
            (
                f"**Quality win:** `{quality.get('quality_win')}`. "
                f"Đề xuất: `{quality.get('default_recommendation')}`."
            ),
            "",
            "## 5. So sánh với baseline native v8",
            "",
        ]
    )
    if BASELINE_JSON.is_file():
        baseline = json.loads(BASELINE_JSON.read_text(encoding="utf-8"))
        baseline_context = baseline["context"]["status_counts"]
        baseline_policy = baseline["policy_safety"]
        lines.extend(
            [
                "| Chỉ số | Native v8 | Joern v9 |",
                "|---|---:|---:|",
                (
                    "| Accuracy tổng thể | "
                    f"{baseline['accuracy_with_abstentions_unresolved']:.2%} | "
                    f"{metrics['accuracy_with_abstentions_unresolved']:.2%} |"
                ),
                (
                    f"| Selective accuracy | {baseline['selective_accuracy']:.2%} | "
                    f"{metrics['selective_accuracy']:.2%} |"
                ),
                (
                    f"| Nhận diện benign | {baseline['benign_recognition_rate']:.2%} | "
                    f"{metrics['benign_recognition_rate']:.2%} |"
                ),
                (
                    "| Automatic resolution | "
                    f"{baseline_policy['automatic_resolution_rate']:.2%} | "
                    f"{policy['automatic_resolution_rate']:.2%} |"
                ),
                (
                    f"| Context partial | {baseline_context.get('partial', 0)} | "
                    f"{status_counts.get('partial', 0)} |"
                ),
                (
                    f"| Tổng thời gian | {baseline['elapsed_seconds_including_cold_start']} s | "
                    f"{metrics['elapsed_seconds_including_cold_start']} s |"
                ),
                "",
                (
                    "Kết luận mặc định được quyết định bởi quality gate ở trên; "
                    "không suy diễn từ một metric đơn lẻ."
                ),
                "",
            ]
        )
    category_errors = {
        name: values.get("incorrect", 0)
        for name, values in categories.items()
        if isinstance(values, dict)
    }
    confusion = metrics["confusion"]
    assert isinstance(confusion, dict)
    benign_manual_review = max(
        0,
        int(confusion.get("benign_likely_fp", 0))
        - int(policy.get("benign_fp_candidate", 0)),
    )
    lines.extend(
        [
            "## 6. Nhóm lỗi và giới hạn",
            "",
            f"- Số dự đoán sai theo category: `{category_errors}`.",
            (
                f"- Benign nhận đúng: {metrics['confusion'].get('benign_likely_fp', 0)}/"
                f"{truth['benign']}; xem category errors để ưu tiên vòng tiếp theo."
            ),
            (
                f"- {status_counts.get('partial', 0)}/93 evidence partial nên policy "
                "giữ MANUAL_REVIEW khi thiếu bằng chứng quan trọng."
            ),
            (
                f"- {benign_manual_review} benign finding được LLM nhận đúng là LIKELY_FP "
                "nhưng policy bảo thủ vẫn giữ MANUAL_REVIEW; chỉ evidence có hỗ trợ "
                "deterministic phù hợp mới thành FP_CANDIDATE."
            ),
            "- Đây là một run deterministic, chưa có confidence interval.",
            "- Metric đo triage trên finding đã có, không đo recall của scanner.",
            "- Ground truth map ở cấp test case; một case có thể sinh nhiều finding.",
            "",
        ]
    )
    output_json.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def _quality_evaluation(metrics: dict[str, object]) -> dict[str, object]:
    """Evaluate the pinned Joern acceptance gates without changing metrics."""
    context = metrics["context"]
    policy = metrics["policy_safety"]
    assert isinstance(context, dict)
    assert isinstance(policy, dict)
    statuses = context.get("status_counts", {})
    assert isinstance(statuses, dict)
    required = {
        "schema_success_100_percent": metrics["schema_success_rate"] == 1.0,
        "provider_errors_zero": metrics["errors"] == 0,
        "unsafe_vulnerable_fp_zero": policy["unsafe_vulnerable_fp_candidate"] == 0,
    }
    quality = {
        "overall_accuracy_above_86_02_percent": (
            metrics["accuracy_with_abstentions_unresolved"] > 0.8602
        ),
        "selective_accuracy_at_least_90_91_percent": (
            metrics["selective_accuracy"] >= 0.9091
        ),
        "partial_context_below_14": int(statuses.get("partial", 0)) < 14,
    }
    targets = {
        "benign_recognition_above_62_5_percent": (
            metrics["benign_recognition_rate"] > 0.625
        ),
        "automatic_resolution_above_72_04_percent": (
            policy["automatic_resolution_rate"] > 0.7204
        ),
    }
    return {
        "required": required,
        "quality": quality,
        "targets": targets,
        "quality_win": all(required.values()) and all(quality.values()),
        "default_recommendation": (
            "consider_sprint_2_default" if all(required.values()) and all(quality.values())
            else "keep_native_default_joern_experimental"
        ),
    }


def run_benchmark(
    *,
    limit: int | None,
    write_report: bool,
    analysis_backend: str = "native",
    category_filter: str | None = None,
) -> dict[str, object]:
    """Chạy benchmark đầy đủ hoặc giới hạn bằng một ứng dụng Modal tạm thời."""
    scanner_result, expected, categories, case_names, parsed_count, unique_cases = (
        _scoreable_findings()
    )
    if category_filter is not None:
        selected = tuple(
            finding
            for finding in scanner_result.findings
            if categories[finding.finding_instance_id] == category_filter
        )
        if not selected:
            raise ValueError(f"Unknown or empty benchmark category: {category_filter}.")
        scanner_result = ScannerParseResult(findings=selected)
        selected_ids = {finding.finding_instance_id for finding in selected}
        expected = {key: value for key, value in expected.items() if key in selected_ids}
        categories = {
            key: value for key, value in categories.items() if key in selected_ids
        }
        case_names = {
            key: value for key, value in case_names.items() if key in selected_ids
        }
        unique_cases = len(set(case_names.values()))
    if limit is not None:
        buckets: dict[tuple[str, bool], list[Any]] = defaultdict(list)
        for finding in scanner_result.findings:
            finding_id = finding.finding_instance_id
            buckets[(categories[finding_id], expected[finding_id])].append(finding)
        selected_list = []
        ordered_keys = sorted(buckets)
        while len(selected_list) < limit and ordered_keys:
            remaining_keys = []
            for key in ordered_keys:
                if buckets[key] and len(selected_list) < limit:
                    selected_list.append(buckets[key].pop(0))
                if buckets[key]:
                    remaining_keys.append(key)
            ordered_keys = remaining_keys
        selected = tuple(selected_list)
        scanner_result = ScannerParseResult(findings=selected)
        selected_ids = {finding.finding_instance_id for finding in selected}
        expected = {key: value for key, value in expected.items() if key in selected_ids}
        categories = {
            key: value for key, value in categories.items() if key in selected_ids
        }
        case_names = {
            key: value for key, value in case_names.items() if key in selected_ids
        }
        unique_cases = len(set(case_names.values()))

    started = time.perf_counter()
    with analysis_backend_session(
        analysis_backend,
        BENCHMARK_ROOT,
        "BenchmarkPython-Qwen3-14B-AWQ-scoreable",
        # Build cross-file evidence but do not add Module 2 findings to the
        # fixed 93-finding comparison set.
        module2_enabled=True,
    ) as backend:
        with app.run():
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
                cli_mode=f"benchmark-modal-qwen-{analysis_backend}",
                repository_index=backend.repository_index,
                analysis_backend=backend,
                analysis_identity=backend.identity,
                scanner_versions={"SEMGREP": "1.170.0"},
                scanner_config_ids={"SEMGREP": "p/python"},
            )
        analysis_stats = (
            backend.safe_stats() if hasattr(backend, "safe_stats") else {}
        )
    elapsed = time.perf_counter() - started
    metrics = _metrics(
        batch_result,
        expected,
        categories,
        case_names,
        *provider.safe_stats(),
        parsed_findings=parsed_count,
        unique_cases=unique_cases,
        elapsed_seconds=elapsed,
        analysis_stats=analysis_stats,
    )
    metrics["quality_evaluation"] = _quality_evaluation(metrics)
    metrics["minimal_schema_recoveries"] = provider.minimal_schema_recoveries
    if write_report:
        output_json = JOERN_OUTPUT_JSON if analysis_backend == "joern" else OUTPUT_JSON
        _write_report_vi(metrics, output_json)
    return metrics


def main() -> int:
    """Parse tham số benchmark cục bộ, chạy Modal và in metric an toàn."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--category", default=None)
    parser.add_argument(
        "--analysis-backend",
        choices=("native", "joern"),
        default="native",
    )
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be greater than zero")
    metrics = run_benchmark(
        limit=args.limit,
        write_report=not args.no_write,
        analysis_backend=args.analysis_backend,
        category_filter=args.category,
    )
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
