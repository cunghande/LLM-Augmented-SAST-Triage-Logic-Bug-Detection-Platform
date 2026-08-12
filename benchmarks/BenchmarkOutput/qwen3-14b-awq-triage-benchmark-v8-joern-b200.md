# Benchmark Joern CPG với Qwen3-14B-AWQ — prompt v8 / B200

## 1. Cấu hình cố định

- Model/GPU: `Qwen/Qwen3-14B-AWQ` / `B200`.
- Prompt/schema: `triage-prompt-v8` / `triage-decision-v1`.
- Backend: `joern` `4.0.600`; config `joern-pysrc2cpg-v4.0.600-evidence-v1`.
- Artifact/config: `benchmarks/BenchmarkRun/semgrep-p-python.json` / `p/python`.
- Ground truth: 77 vulnerable, 16 benign; temperature `0`, seed `42`.

## 2. Kết quả chính

| Chỉ số | Kết quả |
|---|---:|
| Schema success | 100.00% |
| Provider errors | 0 |
| Accuracy tổng thể | 83.87% |
| Selective accuracy | 83.87% |
| Nhận diện vulnerable | 100.00% |
| Nhận diện benign | 6.25% |
| Automatic resolution | 26.88% |
| Vulnerable bị đưa nhầm vào FP_CANDIDATE | 0 |

Confusion matrix: `{'benign_likely_fp': 1, 'benign_likely_tp': 15, 'vulnerable_likely_tp': 77}`.

## 3. Evidence và hiệu năng Joern

- CPG `complete`; build 98.531312 giây.
- Context: `{'complete': 25, 'partial': 68}`; path: `{'intrinsic_usage': 54, 'same_file': 25, 'unknown': 14}`.
- 304 query; latency trung bình 0.186998 giây, lớn nhất 2.45473 giây.
- Tool calls: `{'find_reachability': 25, 'inspect_security_control': 25, 'trace_dataflow': 68}`.
- Tổng thời gian 720.07 giây; request đầu 383.74 giây; steady-state 1.89 giây/finding.

## 4. Quality gate

- `schema_success_100_percent`: **ĐẠT**
- `provider_errors_zero`: **ĐẠT**
- `unsafe_vulnerable_fp_zero`: **ĐẠT**
- `overall_accuracy_above_86_02_percent`: **KHÔNG ĐẠT**
- `selective_accuracy_at_least_90_91_percent`: **KHÔNG ĐẠT**
- `partial_context_below_14`: **KHÔNG ĐẠT**
- `benign_recognition_above_62_5_percent`: **KHÔNG ĐẠT**
- `automatic_resolution_above_72_04_percent`: **KHÔNG ĐẠT**

**Quality win:** `False`. Đề xuất: `keep_native_default_joern_experimental`.

## 5. So sánh A/B với native v8

| Chỉ số | Native v8 | Joern v8 |
|---|---:|---:|
| Accuracy tổng thể | 86.02% | 83.87% |
| Selective accuracy | 90.91% | 83.87% |
| Nhận diện benign | 62.50% | 6.25% |
| Automatic resolution | 72.04% | 26.88% |
| Context partial | 14 | 68 |
| Tổng thời gian | 320.16 s | 720.07 s |

Joern giữ vulnerable recognition 100%, nhưng accuracy, benign recognition và automatic resolution đều giảm; thời gian chạy tăng. Vì vậy `native` tiếp tục là mặc định.

## 6. Nhóm lỗi và giới hạn

- Số dự đoán sai theo category: `{'cmdi': 7, 'deserialization': 7, 'hash': 0, 'pathtraver': 1, 'sqli': 0}`.
- Điểm yếu chính là benign trap của command injection và deserialization; 15/16 benign bị dự đoán là LIKELY_TP.
- 68/93 evidence partial nên policy giữ MANUAL_REVIEW khi thiếu bằng chứng quan trọng.
- Đây là một run deterministic, chưa có confidence interval.
- Metric đo triage trên finding đã có, không đo recall của scanner.
- Ground truth map ở cấp test case; một case có thể sinh nhiều finding.
