# 📊 LLM SAST Triage — Benchmark Evaluation Report (Metric 2.0)

> **Run ID**: `eval-20260730-135052-2e3f1d` | **Timestamp**: `2026-07-30 13:50:52` UTC
> **Model**: `qwen3:8b` | **Execution Mode**: `REAL` | **Status**: `OK`

---

## Executive Summary

Evaluated platform performance on **141 total findings** across benchmark suite.
Ground-Truth Matched: **100** | Unmatched: **41**

### Metric 2.0 Summary Table

| Metric | Value | Status / Note |
|---|:---:|---|
| **Decision Coverage** | **11.00%** | Decided samples / Matched findings |
| **Abstention Rate** | **89.00%** | NEEDS_REVIEW + NEEDS_MORE_CONTEXT |
| **Pipeline Failure Rate** | **0.00%** | PIPELINE_FAILURE |
| **Precision (Decided)** | **1.0000** | TP / (TP + FP) |
| **Recall (Decided)** | **0.5455** | TP / (TP + FN) |
| **F1 Score** | **0.7059** | Harmonic Mean of Precision & Recall |
| **Selective Accuracy** | **54.55%** | (TP + TN) / Decided Samples |
| **Policy FNR** | **6.85%** | FN / Ground Truth TP |
| **Conservative Miss Rate** | **6.85%** | (FN + TP Failure) / Ground Truth TP |
| **Safe FP Suppression Rate** | **0.00%** | TN / Ground Truth FP |
| **Safe Workload Reduction** | **6.00%** | (TP + TN) / Matched Findings |
| **Total Latency** | **354.05 ms** | (0.354s) |

---

## Confusion Matrix (Decided vs Abstaining vs Failure)

| Ground Truth | Predicted TP | Predicted FP | NEEDS_REVIEW / CONTEXT | PIPELINE_FAILURE | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **Actual TP** | ✅ 6 | ❌ 5 (FN) | ⚠️ 62 | 🔴 0 | 73 |
| **Actual FP** | ❌ 0 (FP) | ✅ 0 (TN) | ⚠️ 27 | 🔴 0 | 27 |

---

## Benchmark Results Breakdown

### Benchmark: `OWASP BenchmarkJava`

- **Strategy**: `EXACT_OR_FILE_STEM_MATCH` | **Adapter Status**: `OK`
- **Total Findings**: 50
- **Matched**: 50 | **Unmatched**: 0

| Parameter | Count / Value |
|---|:---:|
| Matched Findings | 50 |
| Ground Truth TP | 50 |
| Ground Truth FP | 0 |

### Benchmark: `OWASP BenchmarkPython`

- **Strategy**: `EXACT_OR_FILE_STEM_MATCH` | **Adapter Status**: `OK`
- **Total Findings**: 50
- **Matched**: 50 | **Unmatched**: 0

| Parameter | Count / Value |
|---|:---:|
| Matched Findings | 50 |
| Ground Truth TP | 23 |
| Ground Truth FP | 27 |

### Benchmark: `Samsung CredData`

- **Strategy**: `PATH_AND_LINE_PROXIMITY_MATCH` | **Adapter Status**: `ADAPTER_FAILURE`
- **Total Findings**: 7
- **Matched**: 0 | **Unmatched**: 7

> [!WARNING]
> **ADAPTER_FAILURE**: Ground-truth matching achieved 0/7 matched findings. All quality metrics are reported as **N/A**.

### Benchmark: `Real-Vuln-Benchmark`

- **Strategy**: `REPO_FILE_LINE_SYMBOL_MATCH` | **Adapter Status**: `ADAPTER_FAILURE`
- **Total Findings**: 34
- **Matched**: 0 | **Unmatched**: 34

> [!WARNING]
> **ADAPTER_FAILURE**: Ground-truth matching achieved 0/34 matched findings. All quality metrics are reported as **N/A**.

---

## Recommended Targets Evaluation

| Metric | Target | Current Value | Status |
|---|:---:|:---:|:---:|
| Selective Accuracy | ≥ 80.0% | 54.55% | ❌ FAIL |
| Decision Coverage | ≥ 50.0% | 11.00% | ❌ FAIL |
| Safe FP Suppression Rate | ≥ 60.0% | 0.00% | ❌ FAIL |
| Policy FNR | ≤ 10.0% | 6.85% | ✅ PASS |

---

*Report produced by LLM-Augmented SAST Triage Evaluator v2.0 — 2026-07-30 13:50:52 UTC*