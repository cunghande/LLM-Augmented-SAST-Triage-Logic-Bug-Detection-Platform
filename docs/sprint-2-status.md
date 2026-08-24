# Trạng thái triển khai Sprint 2

Ngày xác minh: 2026-08-24.

## Phần đã hoàn thành

- Detector chỉ phát ra hai lớp `missing_authz_idor` và
  `business_rule_bypass`.
- Logic finding đi qua pipeline chung: Safe Context, Joern evidence, provider,
  policy và JSON/Markdown/HTML reporter.
- Guard owner/user/tenant/share ACL và exact-object authorization được dùng làm
  counter-evidence cho IDOR.
- Client-controlled price/total, quantity thiếu bound, pagination thiếu cap và
  collection query không giới hạn có regression test.
- Server-side price, quantity bounded và pagination bounded có negative test.
- Prompt-injection variants được giữ trong JSON envelope dưới dạng untrusted
  data; trusted system message không chứa payload từ repository.
- Benchmark runner có runtime Docker để dùng đúng image Semgrep/Gitleaks đã pin.
- Cache benchmark chỉ được tái sử dụng khi Semgrep, Gitleaks, Module 2 và Joern
  đều hoàn thành.

## Focused detector benchmark

Artifact tái lập:
`benchmarks/BenchmarkOutput/sprint2-idor-business/realvuln-focused-v5.json`.

| Phạm vi | Cases | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Tổng | 96 | 65 | 0 | 0 | 31 | 1.0000 | 1.0000 | 1.0000 |
| IDOR/missing authz | 61 | 30 | 0 | 0 | 31 | 1.0000 | 1.0000 | 1.0000 |
| Business-rule bypass | 35 | 35 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

Các metric trên đánh giá deterministic detector trên 96 location đã map. Dataset
này đã được dùng để phân tích false negative và false positive trong quá trình
cải thiện, vì vậy kết quả là development-fit, không phải held-out và không hỗ
trợ tuyên bố chất lượng tổng quát. Business-rule benchmark hiện chưa có negative
case được review; ngoài ra còn 1.050 candidate ngoài vùng ground truth chưa được
adjudicate.

## Kiểm chứng chất lượng code

- Full test suite: 453 passed, 2 skipped.
- Ruff: tất cả check đạt.
- Docker smoke: Semgrep, Gitleaks, Joern và pipeline reporter đều hoàn thành.
- Docker/Joern benchmark hoàn tất 66/66 repository, không có run thiếu scanner
  hoặc CPG.

## Kiểm chứng bằng LLM thật

Ngày 2026-08-24, pipeline được chạy lại bằng `Qwen/Qwen3-14B-AWQ` trên Modal,
không dùng fake provider:

- Pilot logic v2 trên 10 positive case đã review: 10/10 lời gọi hoàn tất, 10
  `LIKELY_TP` đúng, không có abstention hoặc provider error; selective accuracy
  và decision coverage đều là 1,0. Pilot không có negative case vì detector v3
  không phát hiện các reviewed negative location, nên kết quả này chưa đo được
  specificity của LLM.
- Demo end-to-end cuối trên repository DVGA tại commit
  `a961308c02d1fb462b192681c336b0739e432da7`: Semgrep, Gitleaks và Module 2 đều
  thành công; repository-artifact binding là `VERIFIED`; Joern 4.0.600 build CPG
  hoàn tất; Qwen thật triage 30/30 finding, không có lỗi scanner, schema hoặc
  provider.
- Phân bố quyết định cuối: policy giữ 25 `LIKELY_TP` và 5 `MANUAL_REVIEW`.
  Output trực tiếp của model gồm 26 `LIKELY_TP`, 1 `LIKELY_FP` và 3
  `NEEDS_REVIEW`; policy bảo thủ không tự động chấp nhận FP khi structured
  evidence chưa đủ điều kiện.
- Evidence Card v3 dùng function-scoped sanitized code, exact source/sink symbol,
  dòng source/sink, sink argument và retrieval-resolution ở vị trí trực tiếp.
  Hook `before_request` không còn bị nhận nhầm là endpoint; pagination đi qua
  rubric riêng thay vì domain-value chung.
- Context window Modal được nâng từ 4.096 lên 8.192 token sau khi pilot đầu tiên
  phát hiện prompt Evidence Card vượt giới hạn cũ. Regression test provider và
  prompt đều đạt sau thay đổi.
- Lượt kiểm chứng cuối bật `--module2-discovery` trên DVGA và dùng đồng thời
  Joern thật với Qwen thật: 30 finding, 28 evidence card, 28 path được xuất,
  trong đó 4 path cross-file hoàn chỉnh đi qua 3 file (`core/views.py`,
  `core/security.py`, `core/helpers.py`). Cả 28/28 evidence card có trạng thái
  complete và 25/28 xác nhận `source_reaches_sink=true`. Hai nhóm cross-file
  chính là input `filename` tới `open` và input `path` qua sanitizer/call chain
  tới `popen`. JSON, Markdown và HTML đều hiển thị từng bước với kind, symbol,
  file và line. Đây là kiểm chứng tích hợp trên một demo repository, không phải
  held-out benchmark để tuyên bố chất lượng tổng quát của model.

Artifact:

- `benchmarks/BenchmarkOutput/sprint2-idor-business/realvuln-llm-pilot-v2.json`
- `benchmarks/BenchmarkOutput/sprint2-idor-business/demo-real-llm-full-cross-file-final/`

## Còn cần external acceptance

- Đóng băng dataset held-out mới trước khi tiếp tục tuning.
- Hai reviewer và adjudicator cho sample dùng để tuyên bố chất lượng.
- Real-provider run trên held-out mới để đo coverage, failure rate và
  calibration; fake provider không được dùng cho model-quality claim.
- AppSec/service owner review trên service thật.

## Joern pipeline verification

Pipeline đã chạy hoàn tất 66/66 repository bằng Docker với Semgrep, Gitleaks,
Module 2 và CPG đầy đủ. Aggregate summary nhiều CWE không phản ánh phạm vi hai
lớp của Sprint 2 và đã được xóa khỏi tập kết quả công bố. Các report từng
repository được giữ để audit và không được diễn giải thành model-quality metric
vì lượt chạy dùng fake provider.
