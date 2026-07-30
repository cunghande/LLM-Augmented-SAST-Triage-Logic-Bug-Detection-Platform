# BÁO CÁO HOÀN THÀNH NHIỆM VỤ: SỬA BENCHMARK EVALUATION FRAMEWORK & METRIC 2.0 AUDIT

---

### 1. Phân Tích Lỗ Hổng Ban Đầu (Initial Gap Analysis)

| Hạng mục | Trạng thái ban đầu | Nguyên nhân chính |
|---|---|---|
| **Confusion Matrix & Verdict** | Chưa phân định giữa `DECIDED PREDICTION` (`TP`, `FP`), `ABSTENTION` (`NEEDS_REVIEW`, `NEEDS_MORE_CONTEXT`) và `PIPELINE_FAILURE`. | Enum và evaluator cũ gom toàn bộ kết quả không chắc chắn thành 1 nhóm duy nhất. |
| **Tính Sai Accuracy** | OWASP Java báo Accuracy = 90.0%, OWASP Python báo Accuracy = 100%. | Công thức cũ tính `(TP + TN + NEEDS_REVIEW) / Total`, coi `NEEDS_REVIEW` như một dự đoán đúng. |
| **Tính Sai FP Reduction** | OWASP Python báo FP Reduction = 100%, Overall Summary báo 89.0%. | Công thức cũ lấy `NEEDS_REVIEW / Total` hoặc `1 - manual review rate` thay vì `TN / ground_truth_fp`. |
| **Xử lý N/A khi matched = 0** | Samsung CredData (0/7 matched) và RealVuln (0/34 matched) hiển thị `0.0000` cho mọi metric. | Không có kiểm tra điều kiện mẫu số bằng 0; trả về float default `0.0000`. |
| **Ground-Truth Matching Adapters** | 0/7 matched ở CredData và 0/34 matched ở RealVuln. | So sánh chuỗi đơn giản theo `finding_id` hoặc `stem(file_path)` thất bại hoàn toàn do lệch cấu trúc ID và đường dẫn file. |
| **Processing Time & Timer** | Mọi benchmark đều ghi `0.0s`. | Dùng `time.time()` đo quanh hàm triage chính, bị làm tròn số nguyên giây hoặc chỉ đo sub-pipeline ngắn. |
| **Integrity & Hardcoded Report** | Executive summary ghi FP Reduction = 89% trong khi Java = 78% và Python = 100%. | Không dùng `evaluation_run_id` duy nhất; summary bị hardcode hoặc trộn lẫn dữ liệu từ nhiều lần chạy khác nhau. |
| **Test Suite Report** | Báo cáo "all tests passed" dù có test bị skipped. | Test runner không bóc tách chi tiết số lượng test `discovered`, `passed`, `failed`, `errors`, `skipped`. |

---

### 2. Danh Sách File Đã Tạo / Sửa Đổi

1. [src/core/schema.py](file:///d:/Code/AI%20security/src/core/schema.py#L39-L46): Bổ sung `PIPELINE_FAILURE` vào `TriageVerdict` enum và định nghĩa ánh xạ verdict chuẩn.
2. [src/benchmark/__init__.py](file:///d:/Code/AI%20security/src/benchmark/__init__.py): Khởi tạo module `benchmark` export các adapter, evaluator, reporter.
3. [src/benchmark/adapters.py](file:///d:/Code/AI%20security/src/benchmark/adapters.py): Xây dựng 4 adapter chuyên biệt (`OWASPBenchmarkJavaAdapter`, `OWASPBenchmarkPythonAdapter`, `SamsungCredDataAdapter`, `RealVulnBenchmarkAdapter`) hỗ trợ 5 loại match status (`EXACT_LOCATION`, `ACCEPTABLE_LOCATION`, `SYMBOL_MATCH`, `SEMANTIC_MATCH_REQUIRES_REVIEW`, `NO_MATCH`).
4. [src/benchmark/evaluator.py](file:///d:/Code/AI%20security/src/benchmark/evaluator.py): Động cơ tính toán Metric 2.0, xử lý ngữ nghĩa `"N/A"`, phân loại `DECIDED` vs `ABSTENTION` vs `FAILURE`, và đo timer độ phân giải cao (`time.perf_counter()`).
5. [src/benchmark/reporter.py](file:///d:/Code/AI%20security/src/benchmark/reporter.py): Trình xuất báo cáo tự động sinh 7 artifacts chuẩn phục vụ audit.
6. [scripts/run_benchmark_eval.py](file:///d:/Code/AI%20security/scripts/run_benchmark_eval.py): Cập nhật CLI runner kết nối 4 benchmark, xuất các file chẩn đoán diagnostic.
7. [tests/test_benchmark_evaluator.py](file:///d:/Code/AI%20security/tests/test_benchmark_evaluator.py): Bộ unit tests và integration test kiểm tra chính xác các công thức toán học và adapter.

---

### 3. Bảng So Sánh Công Thức Metric Trước Và Sau (Metric 2.0)

| Chỉ số | Công thức cũ (Flawed v1.0) | Công thức mới chuẩn hóa (Metric 2.0) |
|---|---|---|
| **Accuracy** | `(TP + TN + NEEDS_REVIEW) / Total` *(Sai)* | `Selective Accuracy = (TP + TN) / Decided Samples` |
| **FP Reduction** | `NEEDS_REVIEW / Total` hoặc `1 - manual review rate` *(Sai)* | `Safe FP Suppression Rate = TN / Ground Truth FP` |
| **Decision Coverage** | Không có *(Coi 100% mẫu được phân loại)* | `Decided Samples / Matched Findings` |
| **Abstention Rate** | Không báo riêng | `(TP Abstained + FP Abstained) / Matched Findings` |
| **Policy FNR** | `FN / (TP + FN)` | `FN / Ground Truth TP` |
| **Conservative Miss Rate** | Không có | `(FN + TP Failure) / Ground Truth TP` |
| **Manual Review Load** | Không có | `(TP Abstained + FP Abstained) / Matched Findings` |
| **Undefined Metrics** | Trả về `0.0000` hoặc `1.0000` khi mẫu số = 0 | Hiển thị chuỗi `"N/A"` kèm lý do giải thích cụ thể |

---

### 4. Danh Sách Unit & Integration Tests Đã Thêm

Các unit tests trong [test_benchmark_evaluator.py](file:///d:/Code/AI%20security/tests/test_benchmark_evaluator.py):
1. `test_verdict_normalization`: Ánh xạ đúng `TRIAGED_TP` → `TP`, `TRIAGED_FP` → `FP`, giữ nguyên `NEEDS_REVIEW`, `NEEDS_MORE_CONTEXT`, `PIPELINE_FAILURE`.
2. `test_needs_review_does_not_increase_accuracy`: Kiểm định `NEEDS_REVIEW` không làm tăng Selective Accuracy.
3. `test_needs_more_context_not_counted_as_fp_suppression`: Kiểm định `NEEDS_MORE_CONTEXT` không bị tính vào FP suppression rate.
4. `test_50_50_needs_review_produces_na_and_zero_coverage`: Kiểm định bộ dữ liệu 50/50 `NEEDS_REVIEW` tạo Decision Coverage = 0%, Abstention Rate = 100%, Precision/Recall/F1/Accuracy = `"N/A"`.
5. `test_matched_findings_zero_produces_all_na`: Kiểm định khi `matched_findings = 0` tạo tất cả metric bằng `"N/A"`.
6. `test_fp_suppression_formula`: Kiểm định công thức `TN / ground_truth_fp`.
7. `test_policy_fnr_formula`: Kiểm định công thức `FN / ground_truth_tp`.
8. `test_pipeline_failure_reported_separately`: Kiểm định `PIPELINE_FAILURE` được báo cáo riêng biệt dưới dạng failure rate và conservative miss rate.
9. `test_unmatched_sample_not_in_confusion_matrix`: Kiểm định sample chưa match không đi vào confusion matrix.
10. `test_synthetic_dataset_integration`: Integration test với Synthetic Dataset (GT: 4 TP, 6 FP) đối sánh khớp từng số liệu lý thuyết:
    - `TP=2, FN=1, TN=3, FP=1, abstention=2, failure=1, decided=7`
    - `decision_coverage = 0.7`, `abstention_rate = 0.2`, `pipeline_failure_rate = 0.1`
    - `precision = 0.6667`, `recall_among_decided = 0.6667`, `f1 = 0.6667`
    - `selective_accuracy = 0.7143`, `policy_false_negative_rate = 0.25`
    - `safe_fp_suppression_rate = 0.5`, `safe_workload_reduction = 0.5`
11. `test_high_resolution_timer`: Kiểm định timer đo thời gian thực thi > 0 ms.
12. `test_mock_vs_real_execution_mode`: Phân biệt chế độ `REAL` và `MOCK`.
13. `test_realvuln_adapter_matching_5_samples`: Kiểm tra adapter `RealVulnBenchmarkAdapter` trên 5 mẫu thử nghiệm đại diện.
14. `test_samsung_adapter_matching`: Kiểm tra adapter `SamsungCredDataAdapter` đối soát đường dẫn và dòng gần kề.

---

### 5. Kết Quả Chạy Test Suite Chi Tiết

Lệnh thực thi:
```bash
python -m unittest discover tests
```

Kết quả:
```text
30 tests discovered: 28 passed, 0 failed, 0 errors, 2 skipped.
Ran 30 tests in 8.473s (OK, skipped=2)
```

**Danh sách 2 test bị skipped và lý do**:
1. `test_neo4j_connection` ([test_neo4j_exporter.py](file:///d:/Code/AI%20security/tests/test_neo4j_exporter.py#L8)) — *Lý do*: `Neo4j container not available: Failed to connect to bolt://localhost:7687`
2. `test_export_single_trace` ([test_neo4j_exporter.py](file:///d:/Code/AI%20security/tests/test_neo4j_exporter.py#L18)) — *Lý do*: `Neo4j container not available: Failed to connect to bolt://localhost:7687`

---

### 6. Kết Quả Chạy Lại 4 Benchmark Suites (Run ID: `eval-20260730-135052-2e3f1d`)

| Benchmark Suite | Total Findings | Matched | Ground-Truth TP / FP | Decision Coverage | Abstention Rate | Precision (Decided) | Recall (Decided) | Selective Accuracy | Safe FP Suppression | Adapter Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **OWASP BenchmarkJava** | 50 | 50 | 50 TP / 0 FP | 22.00% (11/50) | 78.00% (39/50) | 1.0000 (6/6) | 0.5455 (6/11) | 54.55% (6/11) | 0.00% | `OK` |
| **OWASP BenchmarkPython** | 50 | 50 | 23 TP / 27 FP | 0.00% (0/50) | 100.00% (50/50) | **N/A** | **N/A** | **N/A** | 0.00% | `OK` |
| **Samsung CredData** | 7 | 0 | 0 TP / 0 FP | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** | `ADAPTER_FAILURE` |
| **Real-Vuln-Benchmark** | 34 | 0 | 0 TP / 0 FP | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** | `ADAPTER_FAILURE` |
| **OVERALL SUITE** | **141** | **100** | **73 TP / 27 FP** | **11.00%** | **89.00%** | **1.0000** | **0.5455** | **54.55%** | **0.00%** | `OK` |

*Thời gian thực thi (Wall-clock latency)*: **354.05 ms (0.354s)** cho toàn bộ pipeline bao gồm loading, context extraction, matching và generation.

---

### 7. 5 Diagnostic Samples Của OWASP BenchmarkPython

Các mẫu chẩn đoán chi tiết được ghi nhận tại [python_diagnostic_samples.json](file:///d:/Code/AI%20security/reports/python_diagnostic_samples.json):

1. **SG-1F80888F81C9** (`BenchmarkTest00165`):
   - Ground Truth: `TP` (CWE-78, Command Injection)
   - Code snippet context: `L12 <form action="/benchmark/cmdi-00/BenchmarkTest00165"...>`
   - Raw model output: `verdict: NEEDS_REVIEW`, `confidence: 0.60`
   - Reason: Mode fallback/heuristic kích hoạt do từ khóa không nằm trong bộ rule đơn giản. Ngưỡng tự động duyệt TP (≥ 0.80) không đạt.
2. **SG-3E9885457586** (`BenchmarkTest00166`):
   - Ground Truth: `TP` (CWE-78, Command Injection)
   - Code snippet context: `L12 <form action="/benchmark/cmdi-00/BenchmarkTest00166"...>`
   - Raw model output: `verdict: NEEDS_REVIEW`, `confidence: 0.60`
   - Reason: Ngưỡng tự động duyệt TP (≥ 0.80) không đạt → Trả về `NEEDS_REVIEW` (Abstention).
3. **SG-416CD6D78008** (`BenchmarkTest00167`):
   - Ground Truth: `TP` (CWE-78, Command Injection)
   - Context quality: `FALLBACK` (Line window L1-L23)
   - Raw model output: `verdict: NEEDS_REVIEW`, `confidence: 0.60`
   - Reason: Phân loại vào nhóm `MANUAL_REVIEW`.
4. **SG-346FF0E9F90C** (`BenchmarkTest00168`):
   - Ground Truth: `TP` (CWE-78, Command Injection)
   - Context quality: `FALLBACK`
   - Raw model output: `verdict: NEEDS_REVIEW`, `confidence: 0.60`
   - Reason: Phân loại vào nhóm `MANUAL_REVIEW`.
5. **SG-948FE49BA085** (`BenchmarkTest00169`):
   - Ground Truth: `TP` (CWE-78, Command Injection)
   - Context quality: `FALLBACK`
   - Raw model output: `verdict: NEEDS_REVIEW`, `confidence: 0.60`
   - Reason: Phân loại vào nhóm `MANUAL_REVIEW`.

---

### 8. Danh Sách Unmatched Của Samsung CredData

Báo cáo chẩn đoán tại [samsung_unmatched_report.json](file:///d:/Code/AI%20security/reports/samsung_unmatched_report.json) giải thích nguyên nhân 7/7 phát hiện từ Gitleaks/Semgrep không thể đối soát thành công:

1. `GL-E3A8CAB11A2C`: `repos/CredData/benchmark/scanner/bin/wraith/default.yaml:190`
   - *Lý do*: File cấu hình của công cụ quét nội bộ, không thuộc repository mã nguồn con trong tập 25 repos CredData được chọn.
2. `GL-30C891544B0F`: `repos/CredData/README.md:181`
   - *Lý do*: Credential mẫu nằm trong file README tài liệu root repository.
3. `GL-C6CEA80DEF66`: `repos/CredData/test_obfuscate_creds.py:179`
   - *Lý do*: Script utility mã hóa credential mẫu phục vụ benchmark runner.
4. `GL-078684DC5D89`: `repos/CredData/test_obfuscate_creds.py:189`
   - *Lý do*: Script utility mã hóa.
5. `GL-BFCC8DA90BAF`: `repos/CredData/test_obfuscate_creds.py:173`
   - *Lý do*: Script utility mã hóa.
6. `GL-34C28E21EEE8`: `repos/CredData/test_obfuscate_creds.py:158`
   - *Lý do*: Script utility mã hóa.
7. `SG-79D3B2A101C9`: `repos/CredData/benchmark/scanner/src/wraith/wraith.go:42`
   - *Lý do*: File mã nguồn Go của scanner binary.

*Đánh giá*: Do cả 7 phát hiện của Gitleaks/Semgrep đều quét nhầm vào các file utility/wrapper ở thư mục root thay vì thư mục con `data/{repo_hash}/`, adapter đánh dấu `ADAPTER_FAILURE` và hiển thị tất cả quality metrics là `"N/A"`.

---

### 9. Kết Quả Matching Thử Nghiệm Trên 5 Mẫu Real-Vuln-Benchmark

Khi cho 5 mẫu thử nghiệm có thông tin vị trí mã nguồn đi qua `RealVulnBenchmarkAdapter` (được kiểm định trong unit test `test_realvuln_adapter_matching_5_samples`):

1. Mẫu 1 (`damn-vulnerable-flask-app`, `app.py:120`, `eval(expr)`):
   - Matched ground-truth item: `rv-1` (`CWE-94`, `code_injection`, GT `TP`)
   - Match type: `EXACT_LOCATION` (Line diff = 0, File match)
2. Mẫu 2 (`damn-vulnerable-flask-app`, `app.py:135`, `SELECT * FROM users`):
   - Matched ground-truth item: `rv-2` (`CWE-89`, `sqli`, GT `TP`)
   - Match type: `EXACT_LOCATION`
3. Mẫu 3 (`damn-vulnerable-flask-app`, `app.py:150`, `file.save()`):
   - Matched ground-truth item: `rv-3` (`CWE-434`, `unrestricted_file_upload`, GT `TP`)
   - Match type: `EXACT_LOCATION`
4. Mẫu 4 (`damn-vulnerable-flask-app`, `app.py:165`, `os.system()`):
   - Matched ground-truth item: `rv-4` (`CWE-78`, `command_injection`, GT `TP`)
   - Match type: `EXACT_LOCATION`
5. Mẫu 5 (`juice-shop`, `routes/login.js:42`, `db.query()`):
   - Matched ground-truth item: `rv-5` (`CWE-89`, `sqli`, GT `TP`)
   - Match type: `EXACT_LOCATION`

*Kết quả đối soát trên dữ liệu quét thực tế ở `scans/Real-Vuln-Benchmark`*: 34 phát hiện hiện tại của Semgrep chỉ quét vào `.github/workflows/deploy-dashboard.yml` và các báo cáo HTML tĩnh trong thư mục root, không quét vào mã nguồn ứng dụng con, dẫn tới 0/34 matched (`ADAPTER_FAILURE` & quality metrics = `"N/A"`).

---

### 10. Các Limitation Còn Lại

1. **Abstention Rate Cao (89%)**: Hệ thống hiện có tỷ lệ rút lui/cần con người review cao do phần lớn các pattern phức tạp được chuyển sang `NEEDS_REVIEW` để đảm bảo an toàn.
2. **Scanner Path Mismatch ở CredData & RealVuln**: Công cụ quét tự động Semgrep/Gitleaks hiện tại khi chạy trên thư mục cha CredData và Real-Vuln-Benchmark quét nhầm vào các file tài liệu/workflow root thay vì đi sâu vào các thư mục dự án con. Cần điều chỉnh cấu hình scanner target path trong tương lai.
3. **MOCK LLM Heuristic**: Khi chạy offline không có Ollama, heuristic mặc định sẽ gán `NEEDS_REVIEW` cho các file không chứa từ khóa chỉ định, tạo ra 100% abstention ở OWASP Python.

---

### 11. Các Artifacts Báo Cáo Xuất Ra Để Audit

Tất cả các artifacts đã được ghi lại tại thư mục [reports/](file:///d:/Code/AI%20security/reports):
- [evaluation_summary.md](file:///d:/Code/AI%20security/reports/evaluation_summary.md)
- [evaluation_summary.json](file:///d:/Code/AI%20security/reports/evaluation_summary.json)
- [evaluation_manifest.json](file:///d:/Code/AI%20security/reports/evaluation_manifest.json)
- [confusion_matrix.json](file:///d:/Code/AI%20security/reports/confusion_matrix.json)
- [unmatched_findings.json](file:///d:/Code/AI%20security/reports/unmatched_findings.json)
- [per_sample_results.jsonl](file:///d:/Code/AI%20security/reports/per_sample_results.jsonl)
- [latency_report.json](file:///d:/Code/AI%20security/reports/latency_report.json)
- [python_diagnostic_samples.json](file:///d:/Code/AI%20security/reports/python_diagnostic_samples.json)
- [samsung_unmatched_report.json](file:///d:/Code/AI%20security/reports/samsung_unmatched_report.json)
- [realvuln_unmatched_report.json](file:///d:/Code/AI%20security/reports/realvuln_unmatched_report.json)
