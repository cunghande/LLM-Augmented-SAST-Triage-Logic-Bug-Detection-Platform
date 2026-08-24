# Kế hoạch triển khai hiện tại

## Mục tiêu

Xây dựng một pipeline tuần tự để quét repository Python bằng Semgrep và
Gitleaks, chuẩn hóa finding, tạo ngữ cảnh đã sanitize, lấy đề xuất triage từ
LLM, áp dụng policy bảo thủ và xuất báo cáo JSON/Markdown có thể audit.

Pipeline không tự động xóa hoặc suppress finding. Khi context thiếu, provider
lỗi hoặc output không hợp lệ, finding vẫn được giữ và chuyển sang
`MANUAL_REVIEW` hoặc `TRIAGE_ERROR`.

Theo quyết định phạm vi hiện tại, nhánh `main` tập trung Sprint 2 vào hai lớp
logic bug Python: missing authorization/IDOR và business-rule bypass. Detector
gắn source–guard–sink evidence, risk score và remediation cho ba use case ưu
tiên: tài liệu khác chủ sở hữu, tính giá giỏ hàng và giới hạn pagination.

## Deliverable được chấp nhận

1. Parser Semgrep/Gitleaks không đưa raw source hoặc raw secret vào public model.
2. Safe Context chặn path traversal, symlink escape và redact credential.
3. Provider chỉ nhận `TriageInput`; output phải qua schema validation.
4. Policy không cho LLM tự quyết định suppression hoặc system action.
5. Báo cáo không chứa raw prompt, raw response, traceback, secret hay absolute path.
6. Benchmark có nhãn review, split `development`/`calibration`/`held_out` và metric riêng theo split.
7. Audit lưu version/hash/timing an toàn, không lưu nội dung source hoặc prompt.
8. Detector Sprint 2 hỗ trợ missing authz/IDOR và business-rule bypass.
9. Logic finding đi qua đúng pipeline triage chung và có evidence, risk factors,
   remediation cùng validation checklist.
10. Mọi finding được chấm điểm rủi ro deterministic, có phiên bản công thức,
    remediation và validation checklist; điểm không thay thế verdict/policy.
11. Có runbook debug an toàn xuyên suốt scanner, binding, Joern, LLM, policy và
    reporter.

## Stage gate

- Joern là analysis backend duy nhất cho source/sink, dataflow và call graph.
- Detector hai lớp phải bật tường minh bằng
  `--logic-detector python-idor-business-logic`; detector này không thay thế
  dataflow Joern.
- Chỉ công bố chất lượng model khi dùng provider thật, dataset không tổng hợp
  và có kết quả held-out mới.

## Không làm trong phạm vi hiện tại

- Auto-suppression, suppression database hoặc stable fingerprint.
- Cam kết đủ 20 custom Semgrep rules.
- Jenkins gate, dashboard, RBAC hoặc API server.
- Phân tích mọi biến thể Python động, cross-service flow và chứng minh khai thác
  tự động. Detector hiện là AST bounded candidate engine, không phải formal proof.
- Tự động áp dụng code diff. Remediation chỉ là đề xuất cần developer review.
- KPI phần trăm không có baseline và ground truth đáng tin cậy.

## Thứ tự hoàn thiện

1. [x] Bảo vệ domain boundary và kiểm tra rò rỉ.
2. [x] Thêm split-level metric cho benchmark; split hiện tại là retrospective,
   chưa phải claim-bearing held-out evaluation.
3. [x] Thêm adversarial/metamorphic prompt-injection regression evaluation.
4. [ ] Hoàn thiện quy trình adjudication và đóng băng một held-out dataset mới
   trước khi tiếp tục tinh chỉnh detector/prompt.
5. [ ] Review candidate ngoài vùng ground truth và xác thực trên ba service được phép.
6. [ ] Đo độ ổn định, failure rate và calibration của provider thật trên held-out mới.
7. [x] Chạy lại focused detector benchmark trên repository và ground truth hiện có.
8. [x] Xác minh pipeline Joern 66 repository bằng runtime Docker; aggregate
   summary ngoài phạm vi focused đã được loại khỏi kết quả Sprint 2.
9. [x] Chuẩn hóa risk assessment cho mọi finding và xuất đầy đủ qua ba reporter.
10. [x] Viết runbook debug an toàn cho toàn pipeline.
11. [x] Hoàn thành phần S3-07 trong phạm vi CLI: decision cache đã validate, TTL,
    telemetry token/latency/chi phí, retention policy và cache-clear an toàn.
12. [ ] Chọn phạm vi Sprint 3 tiếp theo: feedback/adjudication + stable fingerprint,
    hoặc CI gate/dashboard; không triển khai auto-suppression khi chưa có acceptance.

Chi tiết phạm vi, lệnh demo và benchmark: [`sprint-2-scope.md`](sprint-2-scope.md).
