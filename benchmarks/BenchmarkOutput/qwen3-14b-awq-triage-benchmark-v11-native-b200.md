# Benchmark native với Qwen3-14B-AWQ — triage-prompt-v11 / B200

## 1. Cấu hình cố định

- Model/GPU: `Qwen/Qwen3-14B-AWQ` / `B200`.
- Prompt/schema: `triage-prompt-v11` / `triage-decision-v1`.
- Backend: `native` `0.1.0`; config `python-cross-file-evidence-v2-python-web-frameworks-v1`.
- Artifact/config: `benchmarks/BenchmarkRun/semgrep-p-python.json` / `p/python`.
- Ground truth: 77 vulnerable, 16 benign; temperature `0`, seed `42`.

## 2. Kết quả chính

| Chỉ số | Kết quả |
|---|---:|
| Schema success | 100.00% |
| Provider errors | 0 |
| Accuracy tổng thể | 64.52% |
| Selective accuracy | 98.36% |
| Nhận diện vulnerable | 63.64% |
| Nhận diện benign | 68.75% |
| Automatic resolution | 73.12% |
| Vulnerable bị đưa nhầm vào FP_CANDIDATE | 0 |

Confusion matrix: `{'benign_likely_fp': 11, 'benign_likely_tp': 1, 'benign_needs_review': 4, 'vulnerable_likely_tp': 49, 'vulnerable_needs_review': 28}`.
Policy actions: `{'FP_CANDIDATE': 1, 'LIKELY_TP': 67, 'MANUAL_REVIEW': 25}`.

## 3. Evidence và hiệu năng native

- Analysis build `complete`; 11.954266 giây.
- Context: `{'complete': 91, 'partial': 2}`; path: `{'local': 93}`.
- 0 query; latency trung bình 0 giây, lớn nhất 0 giây.
- Tool calls: `{}`.
- Minimal-schema recovery: 0 finding.
- Tổng thời gian 319.74 giây; request đầu 127.45 giây; steady-state 1.89 giây/finding.

## 4. Quality gate tham chiếu (không phải acceptance Sprint 1)

- `schema_success_100_percent`: **ĐẠT**
- `provider_errors_zero`: **ĐẠT**
- `unsafe_vulnerable_fp_zero`: **ĐẠT**
- `overall_accuracy_above_86_02_percent`: **KHÔNG ĐẠT**
- `selective_accuracy_at_least_90_91_percent`: **ĐẠT**
- `partial_context_below_14`: **ĐẠT**
- `benign_recognition_above_62_5_percent`: **ĐẠT**
- `automatic_resolution_above_72_04_percent`: **ĐẠT**

**Quality win:** `False`. Đề xuất: `keep_native_default_joern_experimental`.

## 5. Nhóm lỗi và giới hạn

- Số dự đoán sai theo category: `{'cmdi': 0, 'deserialization': 0, 'hash': 0, 'pathtraver': 1, 'sqli': 0}`.
- Benign nhận đúng: 11/16; xem category errors để ưu tiên vòng tiếp theo.
- 2/93 evidence partial nên policy giữ MANUAL_REVIEW khi thiếu bằng chứng quan trọng.
- 10 benign finding được LLM nhận đúng là LIKELY_FP nhưng policy bảo thủ vẫn giữ MANUAL_REVIEW; chỉ evidence có hỗ trợ deterministic phù hợp mới thành FP_CANDIDATE.
- Đây là một run deterministic, chưa có confidence interval.
- Metric đo triage trên finding đã có, không đo recall của scanner.
- Ground truth map ở cấp test case; một case có thể sinh nhiều finding.
- OWASP Python là benchmark tổng hợp công khai, không phải held-out repository đã review độc lập.
- Manual review: 25/93 finding (26.88%).
