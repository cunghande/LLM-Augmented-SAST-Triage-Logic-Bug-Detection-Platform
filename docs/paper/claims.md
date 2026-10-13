# Sổ Tuyên Bố (Claims Registry)

> **Quy tắc nghiêm ngặt:** Báo cáo nghiên cứu (`paper.md`) CHỈ ĐƯỢC PHÉP nêu các tuyên bố đang ở trạng thái **ĐÃ CHỨNG MINH** kèm theo bằng chứng cụ thể (test/script/kết quả thực nghiệm). Tuyệt đối không nêu các tuyên bố ở trạng thái "CHƯA ĐO" hoặc "CHƯA LÀM" như là sự thật hiển nhiên. Mọi con số trong báo cáo phải do script trong repo sinh ra và có lệnh chạy lại.

---

## Danh Mục Tuyên Bố & Bằng Chứng

| ID | Tuyên bố (Claim) | Bằng chứng (Evidence / Test / Script) | Trạng thái | Ghi chú & Giá trị Đo Lường |
|---|---|---|---|---|
| **CLM-01** | Hệ thống tuân thủ mô hình 5 giai đoạn không rò rỉ mã nguồn thô ra ngoài `SafeContextService` | `tests/test_context_sanitizer.py`, `tests/test_finding_pipeline.py` | **ĐÃ CHỨNG MINH** | Public domain model chỉ chứa `SanitizedContext`. Raw context chỉ tồn tại trong ephemeral local scope. |
| **CLM-02** | Secret thô từ Gitleaks và Canary secrets được mask bằng `<REDACTED_SECRET>` và không xuất hiện trong prompt/report (B6) | `tests/test_canary_leak.py`, `scripts/run_leak_test.py`, `docs/paper/results/leak_test_results.json` | **ĐÃ CHỨNG MINH** | Thử nghiệm 5 canary formats (db_pass, auth_key, base64, JWT, entropy hex): Tỷ lệ rò rỉ **0.00%**. |
| **CLM-03** | Khung prompt builder loại bỏ nguy cơ spoofing thẻ đóng `</UNTRUSTED_INPUT_JSON>` thông qua unicode escaping | `tests/test_prompt_and_output.py:test_prompt_builder_escapes_delimiter_spoofing` | **ĐÃ CHỨNG MINH** | Ký tự `<` và `>` được escape thành `\u003c` và `\u003e`. |
| **CLM-04** | Bộ thu thập ngữ cảnh CPG/AST chạy hoàn toàn tất định (không phụ thuộc LLM chọn tool) | `src/sast_triage/context/evidence_agent.py`, `tests/test_analysis_backends.py` | **ĐÃ CHỨNG MINH** | Đã đổi tên thành `BoundedEvidenceCollector` (Tầng 1) với schema theo từng nhóm lỗ hổng (D1-D2). |
| **CLM-05** | PolicyEngine là chốt chặn fail-closed: lỗi triage luôn chuyển về `TRIAGE_ERROR` hoặc `MANUAL_REVIEW`, không bao giờ tự ý loại bỏ finding | `tests/test_policy_engine.py`, `tests/test_json_reporter.py` | **ĐÃ CHỨNG MINH** | Bất biến kiến trúc: 100% finding xuất hiện trong báo cáo bất kể phán quyết. |
| **CLM-06** | Mức độ cắt giảm token qua việc tinh lọc ngữ cảnh mã nguồn (B8) | `scripts/benchmark_cost_tokens.py`, `docs/paper/results/cost_and_latency_metrics.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Đo trên 219 finding: Cắt giảm **41.22%** token (từ 977.9 xuống 574.8 tokens/finding). **ĐÃ XÓA** con số ước lượng 70-80%. |
| **CLM-07** | Hệ thống loại bỏ ảo giác guard/sanitizer của LLM thông qua Post-Verifier tất định (C2, C3) | `src/sast_triage/triage/post_verifier.py`, `tests/test_post_verifier.py` | **ĐÃ CHỨNG MINH** | Verifier kiểm tra symbol tồn tại, đối chiếu negative proof và bác bỏ tuyên bố guard không có thực. |
| **CLM-08** | Cải thiện F1 từ 0.6095 lên 0.7033 và tiết kiệm 19.18% công sức phân loại so với Scanner Baseline (B1, B2) | `scripts/run_eval_baseline.py`, `docs/paper/results/baseline_comparison.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Đo trên 219 real findings: Full System đạt F1=0.7033, Recall=1.0000 [1.0, 1.0], Precision=0.5424 [0.4696, 0.6149]. |
| **CLM-09** | LLM-Only baseline gây nguy cơ False Negative nghiêm trọng (21.88% FN rate), trong khi Full System giữ FN rate ở mức 0.0% (B2, B4) | `scripts/run_eval_baseline.py`, `scripts/run_calibration_and_audit.py`, `docs/paper/results/fn_audit_report.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | LLM-Only bỏ sót 21.88% lỗ hổng thật. Full System nhờ cổng Policy C4 giữ FN rate ở mức **0.00%**. Audit mẫu 10% xác nhận 0 FN. |
| **CLM-10** | Khả năng phòng thủ trước các payload prompt injection gián tiếp trong code (B5) | `tests/test_prompt_injection.py`, `scripts/run_prompt_injection_suite.py`, `docs/paper/results/prompt_injection_results.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | 16 adversarial payloads: Naive ASR = 100.0%, Defended System ASR = **0.00%** (100% fail-closed về MANUAL_REVIEW). |
| **CLM-11** | Model confidence được cân chỉnh tốt (ECE = 0.0785), nhóm HIGH confidence đạt độ chính xác 98.08% (B3) | `scripts/run_calibration_and_audit.py`, `docs/paper/results/calibration_metrics.json`, `reliability_diagram.png` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Expected Calibration Error: **7.85%**. HIGH confidence accuracy: **98.08%** (51/52). |
| **CLM-12** | Độ trễ xử lý cục bộ và hiệu quả DecisionCache (B8) | `scripts/benchmark_cost_tokens.py`, `docs/paper/results/cost_and_latency_metrics.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Thời gian sanitize trung bình: **0.075 ms**. Cache hit latency: **0.41 ms**. |
| **CLM-13** | Tỷ lệ bao phủ Joern CPG trên toàn bộ hệ sinh thái mã nguồn Python lớn (B7) | Chưa đo đạc trên quy mô toàn bộ PyPI | **CHƯA ĐO** | Đưa vào mục Limitations & Future Work. |
| **CLM-14** | Hiệu năng khi chạy song song / đa luồng (D8) | Hệ thống hiện tại chạy tuần tự theo quy tắc Sprint 1 | **CHƯA LÀM (Sprint 1 Rule)** | Đưa vào mục Limitations & Future Work. |
| **CLM-15** | Kiến trúc Controlled Escalation Agent với 10 allowlisted tools và ActionValidator đảm bảo path containment tuyệt đối | `src/sast_triage/agent/`, `tests/test_agent_tools_and_validator.py`, `tests/test_agent_orchestrator.py` | **ĐÃ CHỨNG MINH** | Tách biệt PLANNER/JUDGE, 3 trạng thái kết quả (FOUND/NOT_FOUND/UNKNOWN), chặn 100% path traversal và illegal symbols. |
| **CLM-16** | Chế độ Agent Escalation giúp tiết kiệm thêm +7.30% công sức phân loại (tăng từ 0.46% lên 7.76%) với 0.00% False Negative | `scripts/run_agent_ablation.py`, `docs/paper/results/agent_ablation_results.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Đo trên 219 real findings: Effort Saved đạt 7.76% (giải quyết tự động 16 ca khó mà Tier-1 bó tay). Tiết kiệm 34% số lượt gọi tool so với `always`. Paired bootstrap 95% CI cho $\Delta F1$ là [0.0, 0.0]. |
| **CLM-17** | Khả năng phòng thủ 100% trước 12 payload tiêm nhiễm nâng cao qua tool results & code read (Suite C) | `tests/test_agent_tool_injection.py`, `scripts/run_tool_injection_redteam.py`, `docs/paper/results/tool_injection_results.json` | **ĐÃ CHỨNG MINH (ĐÃ ĐO THẬT)** | Đo trên 12 payloads (path traversal, symbol injection, spoofing, policy override): ASR trước phòng thủ = 100.0%, sau phòng thủ = **0.00%** (Mitigation Rate = 100.0%). |

---

## Lệnh Chạy Lại Kiểm Chứng Toàn Bộ Tuyên Bố

```bash
# 1. Chạy toàn bộ test suite (544 tests xanh)
pytest

# 2. Sinh lại bảng so sánh baseline và khoảng tin cậy Bootstrap 95% (B1, B2)
python scripts/run_eval_baseline.py

# 3. Sinh lại biểu đồ Calibration ECE và Shadow Mode FN Audit (B3, B4)
python scripts/run_calibration_and_audit.py

# 4. Chạy lại bài kiểm tra Red-Team 16 Mẫu Prompt Injection (B5)
python scripts/run_prompt_injection_suite.py

# 5. Chạy lại bài kiểm tra rò rỉ Canary Secret (B6)
python scripts/run_leak_test.py

# 6. Đo lường lại số liệu cắt giảm token thực tế, độ trễ và chi phí (B8)
python scripts/benchmark_cost_tokens.py

# 7. Chạy lại thực nghiệm Ablation 4 cấu hình Agent trên 219 finding thực tế
python scripts/run_agent_ablation.py

# 8. Chạy lại bài kiểm tra Red-Team Suite C 12 mẫu Tool Injection
python scripts/run_tool_injection_redteam.py
```
