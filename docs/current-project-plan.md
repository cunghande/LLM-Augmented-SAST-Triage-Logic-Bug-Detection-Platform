# Kế hoạch triển khai hiện tại

## Mục tiêu

Xây dựng một pipeline tuần tự để quét repository Python bằng Semgrep và
Gitleaks, chuẩn hóa finding, tạo ngữ cảnh đã sanitize, lấy đề xuất triage từ
LLM, áp dụng policy bảo thủ và xuất báo cáo JSON/Markdown có thể audit.

Pipeline không tự động xóa hoặc suppress finding. Khi context thiếu, provider
lỗi hoặc output không hợp lệ, finding vẫn được giữ và chuyển sang
`MANUAL_REVIEW` hoặc `TRIAGE_ERROR`.

Theo quyết định triển khai mới, nhánh `main` tiếp tục Sprint 2 của kế hoạch gốc:
phát hiện năm lớp logic bug Python, gắn source–guard–sink evidence, risk score
và remediation. Detector FastAPI missing-authz chuyên biệt được bảo tồn ở nhánh
riêng và không còn là phạm vi Sprint 2 trên `main`.

## Deliverable được chấp nhận

1. Parser Semgrep/Gitleaks không đưa raw source hoặc raw secret vào public model.
2. Safe Context chặn path traversal, symlink escape và redact credential.
3. Provider chỉ nhận `TriageInput`; output phải qua schema validation.
4. Policy không cho LLM tự quyết định suppression hoặc system action.
5. Báo cáo không chứa raw prompt, raw response, traceback, secret hay absolute path.
6. Benchmark có nhãn review, split `development`/`calibration`/`held_out` và metric riêng theo split.
7. Audit lưu version/hash/timing an toàn, không lưu nội dung source hoặc prompt.
8. Detector Sprint 2 hỗ trợ missing authz/IDOR, mass assignment, race/TOCTOU,
   business-rule bypass và insecure workflow.
9. Logic finding đi qua đúng pipeline triage chung và có evidence, risk factors,
   remediation cùng validation checklist.

## Stage gate

- `native` là analysis backend mặc định.
- Joern vẫn là thử nghiệm. Detector năm lớp dùng backend `native` và phải bật
  tường minh bằng `--logic-detector python-five-logic`.
- Chỉ nâng backend thử nghiệm thành mặc định khi A/B benchmark trên held-out data cho thấy cải thiện ổn định và test Docker tái lập được.
- Chỉ công bố chất lượng model khi dùng provider thật, dataset không tổng hợp và có kết quả held-out.

## Không làm trong phạm vi hiện tại

- Auto-suppression, suppression database hoặc stable fingerprint.
- Cam kết đủ 20 custom Semgrep rules.
- Jenkins gate, dashboard, RBAC hoặc API server.
- Phân tích mọi biến thể Python động, cross-service flow và chứng minh khai thác
  tự động. Detector hiện là AST bounded candidate engine, không phải formal proof.
- Tự động áp dụng code diff. Remediation chỉ là đề xuất cần developer review.
- KPI phần trăm không có baseline và ground truth đáng tin cậy.

## Thứ tự hoàn thiện

1. Bảo vệ domain boundary và kiểm tra rò rỉ.
2. Hoàn thiện benchmark held-out và quy trình adjudication.
3. Thêm adversarial/metamorphic prompt-injection evaluation.
4. Review candidate ngoài vùng ground truth và xác thực trên ba service được phép.
5. Đo độ ổn định, failure rate và calibration của provider thật.
6. Đánh giá A/B native với Joern; giữ Joern thử nghiệm nếu chưa có bằng chứng.

Chi tiết phạm vi, lệnh demo và benchmark: [`sprint-2-scope.md`](sprint-2-scope.md).
