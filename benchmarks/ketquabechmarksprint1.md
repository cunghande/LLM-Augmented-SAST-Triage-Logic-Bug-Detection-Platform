# Benchmark Joern CPG với Qwen3-14B-AWQ — prompt v9 / B200

## 1. Cấu hình cố định

- Model/GPU: `Qwen/Qwen3-14B-AWQ` / `B200`.
- Prompt/schema: `triage-prompt-v9` / `triage-decision-v1`.
- Backend: `joern` `4.0.600`; config `joern-pysrc2cpg-v4.0.600-evidence-v2`.
- Artifact/config: `benchmarks/BenchmarkRun/semgrep-p-python.json` / `p/python`.
- Ground truth: 77 vulnerable, 16 benign; temperature `0`, seed `42`.

## 2. Kết quả chính

| Chỉ số | Kết quả |
|---|---:|
| Schema success | 100.00% |
| Provider errors | 0 |
| Accuracy tổng thể | 100.00% |
| Selective accuracy | 100.00% |
| Nhận diện vulnerable | 100.00% |
| Nhận diện benign | 100.00% |
| Automatic resolution | 83.87% |
| Vulnerable bị đưa nhầm vào FP_CANDIDATE | 0 |

Confusion matrix: `{'benign_likely_fp': 16, 'vulnerable_likely_tp': 77}`.
Policy actions: `{'FP_CANDIDATE': 2, 'LIKELY_TP': 76, 'MANUAL_REVIEW': 15}`.

## 3. Evidence và hiệu năng Joern

- CPG `complete`; build 61.817243 giây.
- Context: `{'complete': 92, 'partial': 1}`; path: `{'intrinsic_usage': 54, 'same_file': 39}`.
- 181 query; latency trung bình 0.195998 giây, lớn nhất 2.858033 giây.
- Tool calls: `{'find_reachability': 24, 'inspect_security_control': 25}`.
- Minimal-schema recovery: 1 finding.
- Tổng thời gian 395.82 giây; request đầu 128.67 giây; steady-state 1.77 giây/finding.

## 4. Quality gate

- `schema_success_100_percent`: **ĐẠT**
- `provider_errors_zero`: **ĐẠT**
- `unsafe_vulnerable_fp_zero`: **ĐẠT**
- `overall_accuracy_above_86_02_percent`: **ĐẠT**
- `selective_accuracy_at_least_90_91_percent`: **ĐẠT**
- `partial_context_below_14`: **ĐẠT**
- `benign_recognition_above_62_5_percent`: **ĐẠT**
- `automatic_resolution_above_72_04_percent`: **ĐẠT**

**Quality win:** `True`. Đề xuất: `consider_sprint_2_default`.

## 5. So sánh với baseline native v8

| Chỉ số | Native v8 | Joern v9 |
|---|---:|---:|
| Accuracy tổng thể | 86.02% | 100.00% |
| Selective accuracy | 90.91% | 100.00% |
| Nhận diện benign | 62.50% | 100.00% |
| Automatic resolution | 72.04% | 83.87% |
| Context partial | 14 | 1 |
| Tổng thời gian | 320.16 s | 395.82 s |

Kết luận mặc định được quyết định bởi quality gate ở trên; không suy diễn từ một metric đơn lẻ.

## 6. Nhóm lỗi và giới hạn

- Số dự đoán sai theo category: `{'cmdi': 0, 'deserialization': 0, 'hash': 0, 'pathtraver': 0, 'sqli': 0}`.
- Benign nhận đúng: 16/16; xem category errors để ưu tiên vòng tiếp theo.
- 1/93 evidence partial nên policy giữ MANUAL_REVIEW khi thiếu bằng chứng quan trọng.
- 14 benign finding được LLM nhận đúng là LIKELY_FP nhưng policy bảo thủ vẫn giữ MANUAL_REVIEW; chỉ evidence có hỗ trợ deterministic phù hợp mới thành FP_CANDIDATE.
- Đây là một run deterministic, chưa có confidence interval.
- Metric đo triage trên finding đã có, không đo recall của scanner.
- Ground truth map ở cấp test case; một case có thể sinh nhiều finding.
