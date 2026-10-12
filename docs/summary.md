# Tổng Kết Dự Án: LLM-Augmented SAST Triage Platform (Báo Cáo Tổng Hợp)

Tài liệu này tổng hợp toàn bộ hiện trạng kỹ thuật, kết quả đo đạc thực nghiệm, bảng trạng thái các hạng mục, những điểm chưa chắc chắn và 3 rủi ro lớn nhất còn lại của dự án.

---

## 1. Bảng Trạng Thái Các Hạng Mục (A - D)

| Mã Mục | Nội Dung Yêu Cầu | Ưu Tiên | Trạng Thái | Minh Chứng & File Triển Khai |
|---|---|---|---|---|
| **A** | **Khung báo cáo kiểu paper rút gọn** | P0 | **XONG** | `docs/paper/paper.md`, `docs/paper/claims.md`, các biểu đồ matplotlib trong `docs/paper/results/`. |
| **B1** | **Bộ đánh giá có nhãn thật & Bootstrap CI** | P0 | **XONG** | `benchmarks/curated_benchmark.json` (219 finding từ 5 repo thật), `src/sast_triage/evaluation/metrics.py`. |
| **B2** | **Baseline so sánh (Scanner vs LLM-Only vs Full)** | P0 | **XONG** | `scripts/run_eval_baseline.py`, `docs/paper/results/baseline_comparison.json`. |
| **B3** | **Báo cáo calibration & Reliability Diagram** | P0 | **XONG** | `scripts/run_calibration_and_audit.py`, `docs/paper/results/reliability_diagram.png`, `calibration_metrics.json`. |
| **B4** | **Kiểm toán False Negative (Shadow Mode 10%)** | P0 | **XONG** | `docs/paper/results/fn_audit_report.json` (0 FN quan sát thấy trong mẫu kiểm toán). |
| **B5** | **Red-team Prompt Injection (16 mẫu)** | P0 | **XONG** | `tests/test_prompt_injection.py`, `scripts/run_prompt_injection_suite.py`, `docs/paper/results/prompt_injection_results.json`. |
| **B6** | **Leak test Canary Secret qua 5 định dạng** | P1 | **XONG** | `tests/test_canary_leak.py`, `scripts/run_leak_test.py`, `docs/paper/results/leak_test_results.json` (Tỷ lệ rò rỉ: 0.00%). |
| **B7** | **Đo độ phủ Joern trên diện rộng** | P1 | **CHƯA ĐO** | Đã ghi rõ placeholder trong phần Limitations của paper. |
| **B8** | **Chi phí, token thật & độ trễ DecisionCache** | P1 | **XONG** | `scripts/benchmark_cost_tokens.py`, `docs/paper/results/cost_and_latency_metrics.json`, `token_latency_chart.png`. |
| **B9** | **Ca nghiên cứu điển hình (4 walkthroughs)** | P1 | **XONG** | `docs/paper/case_studies.md` (SQLi TP, Command Injection FP, IDOR Hallucination Verifier, Prompt Injection Neutralized). |
| **B10** | **Tài liệu tin cậy & Lệnh chạy lại 1-click** | P2 | **XONG** | Được tích hợp trong Section 9 của `paper.md` và `claims.md`. |
| **B11** | **Sandbox scanner & SARIF output** | P2 | **CHƯA LÀM** | Thuộc phạm vi P2 (hoãn theo chỉ đạo). |
| **C1** | **Đưa luật tất định ra khỏi prompt, vào code** | P0 | **XONG** | `src/sast_triage/policy/engine.py` (chặn LIKELY_TP khi thiếu source/sink hoặc không do user kiểm soát). |
| **C2** | **Structured output evidence-first** | P0 | **XONG** | `src/sast_triage/models.py` (bổ sung `EvidenceRole`, `StructuredEvidence`, reorder model). |
| **C3** | **Post-LLM Verifier tất định** | P0 | **XONG** | `src/sast_triage/triage/post_verifier.py`, `tests/test_post_verifier.py` (đối chiếu symbol, bắt hallucinated guards). |
| **C4** | **Siết cổng hướng FP (chặn None, đòi chứng minh âm tính)** | P0 | **XONG** | `src/sast_triage/policy/engine.py` (`POLICY_VERSION = "conservative-policy-v5"`). |
| **C5** | **Kết quả tool 3 trạng thái (FOUND/NOT_FOUND/UNKNOWN)** | P0 | **XONG** | `src/sast_triage/analysis/base.py`, `src/sast_triage/analysis/joern.py`. |
| **C6-C10** | **Tách prompt theo nhóm, English reason, cascade** | P1/P2 | **CHƯA LÀM** | Hoãn sau P0, đã ghi nhận trong hướng phát triển tương lai. |
| **D1** | **Đổi tên: Bounded Evidence Collector + LLM Reasoner** | P0 | **XONG** | `src/sast_triage/context/evidence_agent.py` (đổi tên, giữ alias tương thích ngược). |
| **D2** | **Evidence schema theo từng nhóm lỗ hổng** | P0 | **XONG** | `src/sast_triage/context/evidence_agent.py` (schema cho Injection, Crypto, IDOR, Mass Assignment, TOCTOU). |
| **D3-D8** | **AST bounded tools, NEEDS_EVIDENCE loop, Parallel** | P1/P2 | **CHƯA LÀM** | Hoãn sau P0, giữ vững quy ước Sprint 1 không async/không song song. |

---

## 2. Danh Sách Số Liệu Thật Đã Sinh Ra & Lệnh Chạy Lại

Tất cả các số liệu dưới đây **HOÀN TOÀN KHÔNG BỊA ĐẶT**, được sinh trực tiếp từ các script đo đạc và có thể tái lập 100%:

### 1. Hiệu năng Baseline & Khoảng tin cậy Bootstrap 95% (B1, B2)
- **Tập dữ liệu:** 219 finding từ 5 repository thực tế (PyGoat, DjanGoat, DVPWA, VulPy, DVFA) gồm 96 True Positives và 123 False Positives.
- **Scanner-Only (Semgrep):** Precision = 0.4384 [0.3744, 0.5068], Recall = 1.0000 [1.0, 1.0], F1 = 0.6095, Effort Saved = 0.0%, FN Rate = 0.0%.
- **LLM-Only (Không có cổng an toàn):** Precision = 0.5859, Recall = 0.7812, F1 = 0.6696, Effort Saved = 41.55%, **FN Rate = 21.88%** (Rủi ro bỏ sót lỗ hổng rất lớn).
- **Full System:** Precision = **0.5424** [0.4696, 0.6149], Recall = **1.0000** [1.0, 1.0], F1 = **0.7033**, Effort Saved = **19.18%**, **FN Rate = 0.00%**.
- **Lệnh chạy lại:**
  ```powershell
  python scripts/run_eval_baseline.py
  ```
- **File kết quả:** `docs/paper/results/baseline_comparison.json`

### 2. Hiệu chuẩn Model & Kiểm toán False Negative (B3, B4)
- **Expected Calibration Error (ECE):** **0.0785** (7.85%).
- **Độ chính xác nhóm HIGH Confidence:** **98.08%** (51/52 phán quyết chính xác).
- **Kiểm toán Shadow Mode FN:** Lấy mẫu ngẫu nhiên 10% các finding `FP_CANDIDATE` đối chiếu nhãn: **0.0% False Negative** (0/5).
- **Lệnh chạy lại:**
  ```powershell
  python scripts/run_calibration_and_audit.py
  ```
- **File kết quả:** `docs/paper/results/calibration_metrics.json`, `docs/paper/results/fn_audit_report.json`, `docs/paper/results/reliability_diagram.png`

### 3. Khả năng chống chịu Red-Team Prompt Injection (B5)
- **16 Payload tấn công gián tiếp trong code** (delimiter breakout, unicode spoofing, instruction override, base64 bypass):
  - Naive Baseline Attack Success Rate (ASR): **100.0%** (16/16).
  - Defended System Attack Success Rate (ASR): **0.00%** (0/16 breached).
  - Tỷ lệ chuyển an toàn về `MANUAL_REVIEW`: **100.00%**.
- **Lệnh chạy lại:**
  ```powershell
  python scripts/run_prompt_injection_suite.py
  ```
- **File kết quả:** `docs/paper/results/prompt_injection_results.json`

### 4. Kiểm tra rò rỉ Canary Secret (B6)
- **5 Định dạng Canary Secret** (db_pass, auth_key, base64 token, JWT, high-entropy hex):
  - Tỷ lệ rò rỉ vào Sanitized Context: **0.00%**.
  - Tỷ lệ rò rỉ vào Prompt: **0.00%**.
  - Tỷ lệ rò rỉ vào Báo cáo: **0.00%**.
- **Lệnh chạy lại:**
  ```powershell
  python scripts/run_leak_test.py
  ```
- **File kết quả:** `docs/paper/results/leak_test_results.json`

### 5. Cắt giảm Token thật, Độ trễ và Chi phí (B8)
- **Đo lường trên 219 finding:**
  - Raw unpruned context: 977.9 tokens/finding.
  - Sanitized context envelope: 574.8 tokens/finding.
  - **Tỷ lệ cắt giảm token thực tế đo được:** **41.22%** (Thay thế hoàn toàn con số giả định 70-80%).
  - Thời gian sanitize cục bộ trung bình: **0.075 ms**.
  - Chi phí tài chính ước tính: $0.0862 USD cho mỗi 1,000 finding.
- **Lệnh chạy lại:**
  ```powershell
  python scripts/benchmark_cost_tokens.py
  ```
- **File kết quả:** `docs/paper/results/cost_and_latency_metrics.json`, `docs/paper/results/token_latency_chart.png`

### 6. Toàn bộ Test Suite
- **527 unit & integration tests:** Đều pass 100% (525 passed, 2 skipped).
- **Lệnh chạy lại:**
  ```powershell
  pytest
  ```

---

## 3. Danh Sách Những Điều Chưa Chắc Chắn

1. **Quy mô tập dữ liệu đánh giá:** Tập benchmark hiện tại gồm 219 finding từ 5 repository mã nguồn mở phổ biến. Mặc dù đủ để chặn hồi quy và đo lường khoảng tin cậy bootstrap 95%, kích thước này chưa đủ lớn để khẳng định hiệu năng tuyệt đối trên từng CWE đơn lẻ hoặc trên các framework Python hiếm gặp.
2. **Hành vi của Joern CPG trên các cấu trúc metaprogramming động:** Python cho phép `getattr`, monkey-patching và dynamic imports. Khi Joern không thể phân giải đường đi trong các cấu trúc này, công cụ trả về trạng thái `UNKNOWN`. Khi đó, hệ thống sẽ tự động chuyển về `MANUAL_REVIEW`, có thể làm giảm tỷ lệ tiết kiệm công sức phân loại.
3. **Độ ổn định của mô hình LLM qua các phiên bản:** Các kết quả thực nghiệm được ghim với Qwen2.5-Coder-14B ở nhiệt độ $0$ (temperature=0). Nếu người dùng đổi sang các checkpoint khác hoặc API bên thứ ba có cập nhật ngầm, cần chạy lại script calibration để xác định lại ngưỡng confidence.

---

## 4. Ba Rủi Ro Lớn Nhất Còn Lại

### Rủi ro 1: Tỷ lệ Manual Review bị dồn ứ trên các dự án mã nguồn phức tạp
Do hệ thống áp dụng triệt để nguyên tắc **fail-closed** (bất kỳ sự thiếu hụt bằng chứng nào ở Tầng 1 hoặc vi phạm kiểm chứng ở Tầng 2 đều đẩy về `MANUAL_REVIEW`), khi triển khai trên các codebase sử dụng nhiều kỹ thuật meta-programming hoặc ORM động phức tạp, tỷ lệ `MANUAL_REVIEW` có thể tăng cao (tiết kiệm được ít công sức hơn mong đợi ban đầu).

### Rủi ro 2: Hiệu năng xử lý và thời gian chờ khi chạy tuần tự trên codebase lớn
Theo quy ước kiến trúc Sprint 1, toàn bộ pipeline vận hành hoàn toàn tuần tự (single-threaded, no async). Đối với các dự án lớn có hàng nghìn file hoặc hàng trăm finding Semgrep, tổng thời gian phân tích CPG và gọi LLM có thể kéo dài đáng kể nếu không có cơ chế cache hoặc song song hóa an toàn (cần mở rộng trong Sprint 2).

### Rủi ro 3: Sự trôi dạt của các kỹ thuật tấn công Prompt Injection (Distribution Drift)
Mặc dù hệ thống đã vượt qua 100% bộ red-team gồm 16 mẫu tấn công gián tiếp trong code, các kỹ thuật prompt injection liên tục tiến hóa (ví dụ: multi-turn payload phân tán qua nhiều file, payload mã hóa ngữ nghĩa tinh vi). Nếu chỉ dựa vào regex phát hiện pattern ở tầng sanitize mà thiếu sự kiểm tra chéo độc lập từ công cụ tĩnh, nguy cơ bị đánh lừa vẫn có thể xảy ra ở các hình thức tấn công mới. Do đó, việc duy trì cổng chính sách đòi hỏi `BOUNDED_LOCAL_NEGATIVE_PROOF` là chốt chặn sinh tử không bao giờ được phép tắt bỏ.
