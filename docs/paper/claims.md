# Sổ Tuyên Bố (Claims Registry)

> **Quy tắc nghiêm ngặt:** Báo cáo nghiên cứu (`paper.md`) CHỈ ĐƯỢC PHÉP nêu các tuyên bố đang ở trạng thái **ĐÃ CHỨNG MINH** kèm theo bằng chứng cụ thể (test/script/kết quả thực nghiệm). Tuyệt đối không nêu các tuyên bố ở trạng thái "CHƯA ĐO" hoặc "CHƯA LÀM" như là sự thật hiển nhiên.

---

## Danh Mục Tuyên Bố & Bằng Chứng

| ID | Tuyên bố (Claim) | Bằng chứng (Evidence / Test / Script) | Trạng thái | Ghi chú & Giới hạn |
|---|---|---|---|---|
| **CLM-01** | Hệ thống tuân thủ mô hình 5 giai đoạn không rò rỉ mã nguồn thô ra ngoài `SafeContextService` | `tests/test_context_sanitizer.py`, `tests/test_finding_pipeline.py` | **ĐÃ CHỨNG MINH** | Public domain model chỉ chứa `SanitizedContext`. |
| **CLM-02** | Secret thô từ Gitleaks và Canary secrets được mask bằng `<REDACTED_SECRET>` và không xuất hiện trong prompt/report | `tests/test_redaction.py`, `tests/test_gitleaks_parser.py`, canary tests | **ĐÃ CHỨNG MINH** | Kiểm thử bằng các mẫu test canary cố định. |
| **CLM-03** | Khung prompt builder loại bỏ nguy cơ spoofing thẻ đóng `</UNTRUSTED_INPUT_JSON>` thông qua unicode escaping | `tests/test_prompt_and_output.py:test_prompt_builder_escapes_delimiter_spoofing` | **ĐÃ CHỨNG MINH** | Ký tự `<` và `>` được escape thành `\u003c` và `\u003e`. |
| **CLM-04** | Bộ thu thập ngữ cảnh CPG/AST chạy hoàn toàn tất định (không phụ thuộc LLM chọn tool) | `src/sast_triage/context/evidence_agent.py`, `tests/test_context_pipeline.py` | **ĐÃ CHỨNG MINH** | Luồng thực thi qua `_next_tool()` là deterministic if-elif; đã đổi tên thành Bounded Evidence Collector. |
| **CLM-05** | PolicyEngine là chốt chặn fail-closed: lỗi triage luôn chuyển về `TRIAGE_ERROR` hoặc `MANUAL_REVIEW`, không bao giờ tự ý loại bỏ finding | `tests/test_policy_engine.py` | **ĐÃ CHỨNG MINH** | Bất biến kiến trúc: 100% finding xuất hiện trong báo cáo. |
| **CLM-06** | Giảm 70-80% token so với gửi toàn bộ source code | Chưa có script đo lường so sánh trên tập repo thực tế | **CHƯA ĐO** | Cần đo đạc bằng script B8; hiện tại không được đưa con số này vào paper. |
| **CLM-07** | Hệ thống có khả năng kháng hoàn toàn ảo giác (hallucination-resistant) | LLM vẫn có thể suy luận sai nếu không có verifier kiểm tra | **CHƯA ĐO** (Không tuyên bố) | Đã sửa thành: "Áp dụng kiểm tra chứng cứ tất định để giảm thiểu hallucination". |
| **CLM-08** | Cải thiện F1 và giảm tỷ lệ Analyst Manual Review so với Scanner Baseline trên tập dữ liệu có nhãn | `scripts/run_eval_benchmark.py`, kết quả trên `benchmarks/curated_benchmark.json` | **ĐANG ĐO (Bước 1)** | Cập nhật sau khi chạy script B1/B2. |
| **CLM-09** | Tỷ lệ False Negative trong hướng `FP_CANDIDATE` được chặn ở mức thấp nhờ cổng bằng chứng tất định | `tests/test_policy_engine.py`, audit script B4 | **ĐANG ĐO (Bước 1)** | Cập nhật sau khi siết cổng C4 và chạy audit B4. |
| **CLM-10** | Khả năng phòng thủ trước các payload prompt injection gián tiếp trong code | Test suite B5 (`tests/test_prompt_injection.py`) | **ĐANG ĐO (Bước 1)** | Đo tỷ lệ phòng thủ thành công trước và sau khi bổ sung heuristic filter. |
| **CLM-11** | Độ bao phủ của Joern CPG trên các repo Python thực tế | Script đo độ phủ B7 | **CHƯA ĐO** | Để placeholder trong paper. |
