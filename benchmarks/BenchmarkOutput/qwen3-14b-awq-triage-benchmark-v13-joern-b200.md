# Benchmark joern với Qwen3-14B-AWQ — triage-prompt-v13 / B200

## 1. Cấu hình cố định

- Model/GPU: `Qwen/Qwen3-14B-AWQ` / `B200`.
- Prompt/schema: `triage-prompt-v13` / `triage-decision-v1`.
- Backend: `joern` `4.0.600`; config `joern-pysrc2cpg-v4.0.600-evidence-v2`.
- Artifact/config: `benchmarks/BenchmarkRun/semgrep-p-python.json` / `p/python`.
- Ground truth: 77 vulnerable, 16 benign; temperature `0`, seed `42`.

## 2. Kết quả chính

| Chỉ số | Kết quả |
|---|---:|
| Schema success | 86.02% |
| Provider errors | 13 |
| Accuracy tổng thể | 22.58% |
| Selective accuracy | 72.41% |
| Nhận diện vulnerable | 27.27% |
| Nhận diện benign | 0.00% |
| Automatic resolution | 23.66% |
| Vulnerable bị đưa nhầm vào FP_CANDIDATE | 0 |

Confusion matrix: `{'benign_error': 6, 'benign_likely_tp': 8, 'benign_needs_review': 2, 'vulnerable_error': 7, 'vulnerable_likely_tp': 21, 'vulnerable_needs_review': 49}`.
Policy actions: `{'LIKELY_TP': 22, 'MANUAL_REVIEW': 58, 'TRIAGE_ERROR': 13}`.

## 3. Evidence và hiệu năng joern

- Analysis build `complete`; 73.394533 giây.
- Context: `{'complete': 88, 'partial': 5}`; path: `{'intrinsic_usage': 54, 'same_file': 34, 'unknown': 5}`.
- 205 query; latency trung bình 0.236648 giây, lớn nhất 1.641739 giây.
- Tool calls: `{'find_reachability': 34, 'inspect_security_control': 34, 'trace_dataflow': 5}`.
- Minimal-schema recovery: 13 finding.
- Tổng thời gian 316.23 giây; request đầu 5.58 giây; steady-state 2.2 giây/finding.

## 4. Quality gate tham chiếu (không phải acceptance Sprint 1)

- `schema_success_100_percent`: **KHÔNG ĐẠT**
- `provider_errors_zero`: **KHÔNG ĐẠT**
- `unsafe_vulnerable_fp_zero`: **ĐẠT**
- `overall_accuracy_above_86_02_percent`: **KHÔNG ĐẠT**
- `selective_accuracy_at_least_90_91_percent`: **KHÔNG ĐẠT**
- `partial_context_below_14`: **ĐẠT**
- `benign_recognition_above_62_5_percent`: **KHÔNG ĐẠT**
- `automatic_resolution_above_72_04_percent`: **KHÔNG ĐẠT**

**Quality win:** `False`. Đề xuất: `review_joern_quality_gates`.

## 5. Nhóm lỗi và giới hạn

- Số dự đoán sai theo category: `{'cmdi': 2, 'deserialization': 4, 'hash': 0, 'pathtraver': 2, 'sqli': 0}`.
- Benign nhận đúng: 0/16; xem category errors để ưu tiên vòng tiếp theo.
- 5/93 evidence partial nên policy giữ MANUAL_REVIEW khi thiếu bằng chứng quan trọng.
- 0 benign finding được LLM nhận đúng là LIKELY_FP nhưng policy bảo thủ vẫn giữ MANUAL_REVIEW; chỉ evidence có hỗ trợ deterministic phù hợp mới thành FP_CANDIDATE.
- Đây là một run deterministic, chưa có confidence interval.
- Metric đo triage trên finding đã có, không đo recall của scanner.
- Ground truth map ở cấp test case; một case có thể sinh nhiều finding.
- OWASP Python là benchmark tổng hợp công khai, không phải held-out repository đã review độc lập.
- Manual review: 58/93 finding (62.37%).
