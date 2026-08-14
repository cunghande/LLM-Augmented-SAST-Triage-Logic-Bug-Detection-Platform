# Kế hoạch triển khai hiện tại

## Mục tiêu

Xây dựng một pipeline tuần tự để quét repository Python bằng Semgrep và
Gitleaks, chuẩn hóa finding, tạo ngữ cảnh đã sanitize, lấy đề xuất triage từ
LLM, áp dụng policy bảo thủ và xuất báo cáo JSON/Markdown có thể audit.

Pipeline không tự động xóa hoặc suppress finding. Khi context thiếu, provider
lỗi hoặc output không hợp lệ, finding vẫn được giữ và chuyển sang
`MANUAL_REVIEW` hoặc `TRIAGE_ERROR`.

## Deliverable được chấp nhận

1. Parser Semgrep/Gitleaks không đưa raw source hoặc raw secret vào public model.
2. Safe Context chặn path traversal, symlink escape và redact credential.
3. Provider chỉ nhận `TriageInput`; output phải qua schema validation.
4. Policy không cho LLM tự quyết định suppression hoặc system action.
5. Báo cáo không chứa raw prompt, raw response, traceback, secret hay absolute path.
6. Benchmark có nhãn review, split `development`/`calibration`/`held_out` và metric riêng theo split.
7. Audit lưu version/hash/timing an toàn, không lưu nội dung source hoặc prompt.

## Stage gate

- `native` là analysis backend mặc định.
- Joern và Module 2 là thử nghiệm, không phải bằng chứng về khả năng phát hiện logic bug tổng quát.
- Chỉ nâng backend thử nghiệm thành mặc định khi A/B benchmark trên held-out data cho thấy cải thiện ổn định và test Docker tái lập được.
- Chỉ công bố chất lượng model khi dùng provider thật, dataset không tổng hợp và có kết quả held-out.

## Không làm trong phạm vi hiện tại

- Risk score hoặc công thức nhân các hệ số không được hiệu chỉnh.
- Remediation/code diff tự động.
- Auto-suppression, suppression database hoặc stable fingerprint.
- Cam kết đủ 20 custom Semgrep rules.
- Jenkins gate, dashboard, RBAC hoặc API server.
- Phát hiện tổng quát race condition, TOCTOU, cross-service flow hay năm lớp logic bug.
- KPI phần trăm không có baseline và ground truth đáng tin cậy.

## Thứ tự hoàn thiện

1. Bảo vệ domain boundary và kiểm tra rò rỉ.
2. Hoàn thiện benchmark held-out và quy trình adjudication.
3. Thêm adversarial/metamorphic prompt-injection evaluation.
4. Đo độ ổn định, failure rate và calibration trước khi mở rộng detector.
5. Đánh giá A/B native với Joern; giữ Joern thử nghiệm nếu chưa có bằng chứng.
