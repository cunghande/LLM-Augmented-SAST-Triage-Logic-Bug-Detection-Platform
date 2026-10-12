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


