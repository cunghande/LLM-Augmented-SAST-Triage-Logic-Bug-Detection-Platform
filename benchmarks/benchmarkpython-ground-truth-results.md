# Kết quả benchmark OWASP BenchmarkPython — Joern + Qwen3-14B

## 1. Phạm vi và cấu hình

| Thành phần | Giá trị |
|---|---|
| Dataset | `BenchmarkPython` |
| Ground truth | `expectedresults-0.1.csv`, ánh xạ theo `BenchmarkTestNNNNN` và đúng category |
| Commit của repository mục tiêu | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| Cỡ mẫu triage | 100 finding duy nhất, giới hạn cố định trước khi gọi LLM |
| Phân bố ground truth | 79 vulnerable, 21 benign |
| Scanner | Semgrep `1.174.0` |
| Cấu hình scanner | `p/python+p/security-audit` |
| Backend phân tích | Joern `4.0.600`; CPG `complete` |
| Model | `Qwen/Qwen3-14B-AWQ` qua provider `real-modal-qwen` |
| Prompt | `triage-prompt-v15` |
| Policy | `conservative-policy-v4` |
| Run ID | `8302f8b8-968a-4eb0-9fe5-1fe1c87361b3` |
| Thời gian chạy | 2026-08-27 01:28:57Z – 01:38:56Z |
| Lỗi xử lý | 0/100 |

Semgrep tạo 526 finding ban đầu. Bộ chọn benchmark giữ 125 finding có test identity và category khớp ground truth, loại 20 finding trùng test case, còn 105 case duy nhất và chọn tối đa 100 case theo tỷ lệ vulnerable/benign. Có 401 finding ngoài phạm vi ánh xạ và 5 case bị loại bởi giới hạn 100.

## 2. Kết quả chính

| Chỉ số | Kết quả | Cách tính |
|---|---:|---|
| Finding được xử lý thành công | 100/100 | Kết quả có quyết định triage hợp lệ |
| Tự động phân loại | 74/100 (74,00%) | `LIKELY_TP` + `FP_CANDIDATE` |
| Cần review thủ công | 26/100 (26,00%) | `MANUAL_REVIEW` |
| Độ chính xác trên nhóm tự động | 74/74 (100,00%) | Quyết định tự động khớp ground truth |
| Precision của `LIKELY_TP` | 67/67 (100,00%) | Vulnerable trong toàn bộ `LIKELY_TP` |
| Vulnerable được tự động nhận diện | 67/79 (84,81%) | `LIKELY_TP` trên tổng vulnerable |
| Precision của `FP_CANDIDATE` | 7/7 (100,00%) | Benign trong toàn bộ `FP_CANDIDATE` |
| Benign được tự động giảm tải | 7/21 (33,33%) | `FP_CANDIDATE` trên tổng benign |
| Vulnerable bị phân loại nhầm thành FP | 0 | Quality gate an toàn |
| Benign bị phân loại nhầm thành TP | 0 | Quality gate chất lượng |

So với lần ổn định trước đó có 57 finding cần review, policy mới còn 26 finding cần review: giảm 31 finding, tương đương 54,39%, trong khi độ chính xác trên nhóm tự động của mẫu này vẫn là 100%.

## 3. Confusion matrix theo policy action

| Ground truth | `LIKELY_TP` | `FP_CANDIDATE` | `MANUAL_REVIEW` | Tổng |
|---|---:|---:|---:|---:|
| Vulnerable | 67 | 0 | 12 | 79 |
| Benign | 0 | 7 | 14 | 21 |
| **Tổng** | **67** | **7** | **26** | **100** |

## 4. Kết quả theo category

| Category | Tổng | Vulnerable | Benign | `LIKELY_TP` | `FP_CANDIDATE` | Review | Accuracy nhóm tự động |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cmdi` | 14 | 7 | 7 | 2 | 1 | 11 | 100,00% (3/3) |
| `deserialization` | 28 | 17 | 11 | 11 | 6 | 11 | 100,00% (17/17) |
| `hash` | 52 | 52 | 0 | 52 | 0 | 0 | 100,00% (52/52) |
| `pathtraver` | 4 | 2 | 2 | 2 | 0 | 2 | 100,00% (2/2) |
| `redirect` | 1 | 0 | 1 | 0 | 0 | 1 | Không có quyết định tự động |
| `sqli` | 1 | 1 | 0 | 0 | 0 | 1 | Không có quyết định tự động |

## 5. Hiệu năng và bằng chứng chạy

| Chỉ số | Giá trị |
|---|---:|
| Thời gian dựng CPG | 17,03 giây |
| Provider input tokens | 383.498 |
| Provider output tokens | 37.396 |
| Provider latency p50 | 2.685 ms |
| Provider latency p95 | 5.554 ms |
| Chi phí ước tính | 1,0021 USD |
| Cache hit/miss | 0 / 100 |

Báo cáo gốc của lần chạy được giữ tại:

- HTML: `/home/cungdv/code/triage-runs/BenchmarkPython-qwen14b-20260827-012827Z/report.html`
- Markdown: `/home/cungdv/code/triage-runs/BenchmarkPython-qwen14b-20260827-012827Z/report.md`
- JSON: `/home/cungdv/code/triage-runs/BenchmarkPython-qwen14b-20260827-012827Z/report.json`
- Ground truth: `/home/cungdv/code/target-repos/BenchmarkPython/expectedresults-0.1.csv`

## 6. Kết luận và giới hạn

Kết quả đạt quality gate cho mục tiêu triage có chọn lọc: không có vulnerable nào bị đưa nhầm vào `FP_CANDIDATE`, và 74% finding được tự động phân loại đúng trong mẫu 100 finding. Hệ thống giảm được 33,33% benign finding khỏi hàng đợi review, nhưng vẫn giữ 26 finding chưa đủ bằng chứng ở `MANUAL_REVIEW` thay vì ép kết luận.

Các tỷ lệ trên chỉ đánh giá triage đối với 100 finding Semgrep đã được chọn; chúng không đo recall tổng thể của scanner trên toàn bộ dataset. Kết quả 100% là selective accuracy của một lần chạy với mẫu này, không phải cam kết độ chính xác tuyệt đối cho repository khác. `FP_CANDIDATE` là ứng viên cảnh báo giả cần xác nhận, không phải finding bị tự động xóa.
