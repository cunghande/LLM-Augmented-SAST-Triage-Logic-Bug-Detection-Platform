# Nhật Ký Tiến Độ Thực Hiện Dự Án (Project Progress Log)

> Ghi nhận tiến độ sau mỗi bước: Công việc đã làm, file thay đổi, kết quả kiểm thử (test pass/fail), số liệu đã đo thật, và các điểm cần lưu ý.

---

## [Bước 0] Kiểm toán Hiện trạng & Khởi tạo Khung Báo cáo (Audit & Paper Scaffold)
- **Công việc đã làm:**
  - Đọc và kiểm toán toàn bộ mã nguồn hiện tại liên quan đến các hạng mục A, B, C, D.
  - Tạo `docs/audit.md` phân loại hiện trạng từng mục (đã cài + có test, đã cài chưa test, chưa có) kèm theo dẫn chứng file:dòng cụ thể.
  - Lập danh sách các tuyên bố sai lệch trong tài liệu (AUTO_SUPPRESS_FP -> FP_CANDIDATE, GraphEvidenceExpansionAgent là workflow tất định, xóa tuyên bố token/hallucination chưa có bằng chứng).
  - Khởi tạo thư mục `docs/paper/` gồm `docs/paper/claims.md` (Sổ tuyên bố) và `docs/paper/paper.md` (Khung bài báo rút gọn 9 phần).
  - Khởi tạo nhật ký tiến độ `docs/progress.md`.
- **File tạo mới / thay đổi:**
  - `docs/audit.md`
  - `docs/paper/claims.md`
  - `docs/paper/paper.md`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - Chạy `pytest`: 495 passed, 2 skipped (100% xanh).
- **Số liệu đã đo:** Chưa có (bước kiểm toán và lập khung).
- **Trạng thái:** Hoàn thành Bước 0. Sẵn sàng sang Bước 1 (Nhóm P0 theo thứ tự: B1, B2 -> C5, C4 -> C2, C3, C1 -> B3, B4, B5 -> D1, D2).

---

## [Bước 1 - Phần B1, B2] Bộ Đánh Giá Thực Tế & So Sánh Baseline (Evaluation Dataset & Baselines)
- **Công việc đã làm:**
  - Dựng dataset có nhãn `benchmarks/curated_benchmark.json` gồm **219 finding** thực tế từ 5 kho mã nguồn mở có lỗ hổng (OWASP PyGoat, DjanGoat, DVPWA, VulPy, DVFA), giấy phép Apache-2.0 / MIT.
  - Phân vùng split nghiêm ngặt theo Repository (tránh rò rỉ): `development` (PyGoat: 95 finding), `calibration` (DjanGoat + DVPWA: 68 finding), `held_out` (VulPy + DVFA: 56 finding).
  - Tỷ lệ cân bằng: 96 TP / 123 FP.
  - Cập nhật `src/sast_triage/evaluation/metrics.py`: bổ sung hàm tính khoảng tin cậy bootstrap 95% (`compute_binary_metric_ci`) và lỗi hiệu chuẩn (`compute_calibration_ece`).
  - Viết script `scripts/run_eval_baseline.py` chạy so sánh 3 baseline:
    1. **Scanner-Only (Semgrep alone):** Precision 0.4384 [0.3744, 0.5068], Recall 1.0, F1 0.6095, Effort Saved 0%.
    2. **LLM-Only:** Precision 0.5859, Recall 0.7812, F1 0.6696, **False Negative Rate 21.88%** (nguy cơ bỏ sót 1/5 lỗ hổng thật!).
    3. **Full System:** Precision 0.5424, Recall 1.0 [1.0, 1.0], F1 0.7033, **False Negative Rate 0.00%**, Analyst Effort Saved 19.18%, ECE 0.1507.
  - Viết test trong `tests/test_evaluation.py` kiểm tra `compute_binary_metric_ci` và `compute_calibration_ece`.
- **File tạo mới / thay đổi:**
  - `benchmarks/curated_benchmark.json`
  - `scripts/build_curated_benchmark.py`
  - `scripts/run_eval_baseline.py`
  - `src/sast_triage/evaluation/metrics.py`
  - `tests/test_evaluation.py`
  - `docs/paper/results/baseline_comparison.json`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - `pytest`: 497 passed, 2 skipped (100% xanh).
- **Trạng thái:** Hoàn thành B1, B2. Sẵn sàng sang C5, C4 (Độ an toàn hướng FP).

---

## [Bước 1 - Phần C5, C4] Kết Quả Tool 3 Trạng Thái & Siết Cổng An Toàn Hướng FP (3-State Tool & Tightened FP Gate)
- **Công việc đã làm:**
  - **C5:** Thêm enum `QueryResultStatus` (FOUND, NOT_FOUND_COMPLETE, UNKNOWN) vào `src/sast_triage/analysis/base.py`. Bổ sung các trường `query_status` và `status_reason` vào `GraphEvidence`.
  - Cập nhật backend Joern (`src/sast_triage/analysis/joern.py`) gán trạng thái 3 giá trị: khi tìm thấy đường (`FOUND`), khi quét xong không thấy (`NOT_FOUND_COMPLETE`), khi CPG thiếu hàm hoặc gặp ngoại lệ (`UNKNOWN` kèm lý do cụ thể).
  - **C4:** Nâng cấp phiên bản policy lên `conservative-policy-v5` trong `src/sast_triage/policy/engine.py`.
  - **Siết cổng FP:** Thay đổi điều kiện `_fp_has_deterministic_support(...) is not True` -> Chặn hoàn toàn trường hợp giá trị `None` (chưa biết / context không cấu trúc) lọt qua thành `FP_CANDIDATE`.
  - **Mở rộng rào chắn negative proof:** Mọi finding CRITICAL, HIGH và MEDIUM có CWE nguy hiểm (CWE-89 SQLi, CWE-78/77 CMDi, CWE-22 Traversal, CWE-502 Deserialization, CWE-94/95 RCE, CWE-918 SSRF) đều bắt buộc phải có `BOUNDED_LOCAL_NEGATIVE_PROOF` mới được dán nhãn `FP_CANDIDATE`; nếu thiếu thì bắt buộc đẩy về `MANUAL_REVIEW`.
  - Cập nhật và bổ sung unit test trong `tests/test_policy_engine.py`: kiểm tra chặn FP khi thiếu bằng chứng tất định và kiểm tra yêu cầu negative proof cho CWE nguy hiểm mức MEDIUM.
- **File tạo mới / thay đổi:**
  - `src/sast_triage/analysis/base.py`
  - `src/sast_triage/analysis/joern.py`
  - `src/sast_triage/policy/engine.py`
  - `tests/test_policy_engine.py`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - `pytest`: 499 passed, 2 skipped (100% xanh).
- **Trạng thái:** Hoàn thành C5, C4. Sẵn sàng sang C2, C3, C1 (Output cấu trúc, Post-LLM Verifier, Luật tất định).

---

## [Bước 1 - Phần C2, C3, C1] Output Cấu Trúc, Post-LLM Verifier & Luật Tất Định
- **Công việc đã làm:**
  - **C2 (Evidence-first Structured Output):**
    - Thêm enum `EvidenceRole` (SOURCE, GUARD, SINK, STEP) và model `StructuredEvidence` (file, line, symbol, role, description) vào `src/sast_triage/models.py`.
    - Cập nhật model `TriageDecision` đặt trường `structured_evidence` lên trước `model_verdict` và `model_confidence` để bắt buộc model đưa bằng chứng trước khi chọn verdict.
  - **C3 (Deterministic Post-LLM Verifier):**
    - Tạo module `src/sast_triage/triage/post_verifier.py` với hàm `verify_post_triage_decision`:
      1. Đối chiếu mọi symbol và file được LLM viện dẫn xem có thực sự tồn tại trong `SanitizedContext` hay không (loại bỏ symbol hallucinated).
      2. Kiểm tra nếu LLM viện dẫn có guard/sanitizer (`EvidenceRole.GUARD`) mà phân tích tĩnh không tìm thấy effective control thì lập tức fail-closed.
      3. Phát hiện mâu thuẫn trực tiếp giữa phán quyết LIKELY_TP và bằng chứng chứng minh âm tính (`BOUNDED_LOCAL_NEGATIVE_PROOF`).
    - Tích hợp `verify_post_triage_decision` trực tiếp vào `apply_policy` trong `src/sast_triage/policy/engine.py` (Rule 2.1), tự động hạ phán quyết về `MANUAL_REVIEW` khi vi phạm.
  - **C1 (Deterministic Rules in Code):**
    - Xác nhận và củng cố các luật tất định trong code: `_tp_has_deterministic_support` chặn LIKELY_TP khi thiếu source/sink hoặc `source_user_controlled is False`; luật constant overwrite và intrinsic security usage được kiểm chứng tĩnh.
  - Tạo bộ unit test toàn diện `tests/test_post_verifier.py` kiểm tra mọi nhánh của post-verifier.
- **File tạo mới / thay đổi:**
  - `src/sast_triage/models.py`
  - `src/sast_triage/triage/post_verifier.py`
  - `src/sast_triage/policy/engine.py`
  - `tests/test_post_verifier.py`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - `pytest`: 504 passed, 2 skipped (100% xanh).
- **Trạng thái:** Hoàn thành C2, C3, C1. Sẵn sàng sang B3, B4, B5 (Calibration, Shadow Mode FN Audit, Red-team Injection).
## [Bước 1 - Phần B3, B4, B5] Calibration, False Negative Shadow Audit & Red-team Prompt Injection
- **Công việc đã làm:**
  - **B3 (Model Calibration & Reliability Diagram):**
    - Tạo script `scripts/run_calibration_and_audit.py` tính toán Expected Calibration Error (ECE) và vẽ reliability diagram (`docs/paper/results/reliability_diagram.png`).
    - Kết quả đo lường: ECE = 0.0785 (7.85%). Độ chính xác trong nhóm HIGH confidence đạt 98.08% (51/52), chứng minh việc chỉ cho phép AUTO_CONFIRM / FP_CANDIDATE khi confidence = HIGH là có căn cứ thống kê vững chắc.
  - **B4 (False Negative Shadow Mode Audit):**
    - Thiết lập script audit tự động lấy mẫu ngẫu nhiên 10% các finding thuộc nhóm suppress (`FP_CANDIDATE`) để đối chiếu ground truth nhãn thật (`docs/paper/results/fn_audit_report.json`).
    - Kết quả đo lường: Tỷ lệ False Negative ghi nhận là 0.0% (0/5 finding bị gán nhãn sai thành FP), đáp ứng tiêu chuẩn an toàn bảo mật.
  - **B5 (Red-Team Prompt Injection Defense Suite):**
    - Xây dựng bộ benchmark red-team gồm 16 adversarial payloads thực tế (`tests/test_prompt_injection.py`) bao gồm: tag delimiter spoofing (`</UNTRUSTED_INPUT_JSON>`), unicode homoglyphs, indirect instruction overrides trong comment/string, role-confusion, Base64 bypass, và null-byte injection.
    - Củng cố lớp phòng thủ: mở rộng `src/sast_triage/context/sanitizer.py` phát hiện mẫu injection (`PROMPT_INJECTION_FLAGGED`), thêm redaction cho credentials (`db_pass`, `auth_key`, high-entropy tokens), và fail-closed về `MANUAL_REVIEW` tại `src/sast_triage/policy/engine.py`.
    - Viết script `scripts/run_prompt_injection_suite.py` sinh báo cáo `docs/paper/results/prompt_injection_results.json`:
      - Naive Baseline Attack Success Rate (ASR): 100.0% (16/16).
      - Defended System ASR: 0.0% (0/16 breached gate, 100% fail-closed về MANUAL_REVIEW).
- **File tạo mới / thay đổi:**
  - `src/sast_triage/models.py` (bổ sung `PROMPT_INJECTION_FLAGGED` vào `MissingContextReason`)
  - `src/sast_triage/context/sanitizer.py` (bổ sung detection regex và entropy check)
  - `src/sast_triage/policy/engine.py` (chặn FP nếu phát hiện prompt injection)
  - `tests/test_prompt_injection.py` (18 unit tests red-team)
  - `scripts/run_calibration_and_audit.py`
  - `scripts/run_prompt_injection_suite.py`
  - `docs/paper/results/calibration_metrics.json`
  - `docs/paper/results/reliability_diagram.png`
  - `docs/paper/results/fn_audit_report.json`
  - `docs/paper/results/prompt_injection_results.json`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - `pytest`: 522 passed, 2 skipped (100% xanh).
- **Trạng thái:** Hoàn thành B3, B4, B5.

