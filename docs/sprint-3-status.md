# Trạng thái triển khai Sprint 3

Ngày xác minh: 2026-08-24.

## Đã hoàn thành trong S3-07

- Decision cache SQLite theo hash của sanitized triage input và toàn bộ phiên bản có
  ảnh hưởng đến quyết định.
- Chỉ cache `TriageDecision` đã validate; không cache lỗi provider, raw source, raw
  prompt hoặc raw response.
- TTL, invalidation theo version, giới hạn kích thước, kiểm tra symlink và lệnh xóa
  cache an toàn.
- Provider Modal khởi động lười; run toàn cache hit không mở phiên GPU/model.
- Telemetry per-finding và aggregate: hit/miss, token ước tính, provider latency
  P50/P95 và chi phí ước tính theo đơn giá cấu hình.
- JSON, Markdown và HTML cùng xuất risk assessment và telemetry.
- Chính sách retention và hướng dẫn debug cache/telemetry.

## Kiểm chứng

- Full test suite: 469 passed, 2 skipped.
- Ruff: tất cả check đạt.
- Regression xác nhận lần chạy thứ hai cache hit không gọi lại provider.
- Regression xác nhận lazy Modal provider không mở session khi không có cache miss.
- Lệnh rút gọn `python -m sast_triage <REPO>` tự bật cache 7 ngày và telemetry chi
  phí B200; người dùng vẫn có thể ghi đè TTL, cache directory và đơn giá.

## Chưa hoàn thành của Sprint 3 tổng thể

- Feedback/adjudication workflow và stable cross-run fingerprint.
- Bộ custom rules đạt tiêu chí acceptance độc lập.
- Jenkins/CI gate, dashboard và RBAC.
- Held-out dataset mới, hai reviewer và adjudicator để công bố chất lượng.

Các mục trên cần quyết định phạm vi và acceptance riêng; hệ thống hiện vẫn không tự
động suppress finding.
