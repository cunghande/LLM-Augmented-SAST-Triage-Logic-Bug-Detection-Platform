# Chính sách cache và lưu trữ dữ liệu LLM

## Phạm vi

Chính sách này áp dụng cho decision cache, checkpoint, report và metadata do CLI
tạo ra. Cache mặc định tắt; chỉ bật khi người vận hành truyền
`--decision-cache-dir`.

## Dữ liệu được phép lưu

Decision cache chỉ lưu khóa SHA-256, thời điểm tạo/hết hạn, metadata phiên bản và
`TriageDecision` đã qua schema validation. Khóa bao gồm sanitized input digest,
provider, model, prompt version, output schema version, policy version và risk
scoring version để tránh dùng lại quyết định sai cấu hình.

Không được lưu raw source, raw secret, raw prompt, raw response, traceback hoặc
đường dẫn repository tuyệt đối. Provider error và output chưa validate không được
cache. Reporter vẫn thực hiện kiểm tra rò rỉ trước khi ghi.

## Thời hạn đề xuất

- Decision cache: 168 giờ (7 ngày), hoặc ngắn hơn theo chính sách nội bộ.
- Checkpoint: chỉ tồn tại trong run chưa hoàn thành; xóa sau khi report ghi thành công.
- Report và run metadata: giữ theo thời hạn audit của tổ chức, sau đó xóa bằng quy
  trình quản lý artifact của tổ chức.
- Scanner artifact: nhạy cảm hơn report vì có thể chứa snippet; không chia sẻ mặc
  định và nên đặt thời hạn ngắn nhất có thể.

Cache không tự xóa report, checkpoint hoặc scanner artifact.

## Xóa và thu hồi

```powershell
python -m sast_triage cache-clear --cache-dir <CACHE_DIR> --expired-only
python -m sast_triage cache-clear --cache-dir <CACHE_DIR>
```

Lệnh thứ nhất xóa entry hết hạn; lệnh thứ hai xóa toàn bộ entry trong database cache.
Nó không xóa file không thuộc cache. Khi model, prompt, policy hoặc risk scoring đổi,
khóa phiên bản tự làm entry cũ không hit; có thể xóa toàn bộ để thu hồi ngay.

Nếu nghi ngờ rò rỉ dữ liệu: dừng dùng cache, giới hạn quyền truy cập thư mục, xóa
entry, thu hồi credential liên quan và xử lý theo quy trình incident response. Không
đưa database cache vào source control hoặc backup không mã hóa.

## Quyền truy cập và độ chính xác telemetry

Chỉ tài khoản chạy pipeline và người vận hành được ủy quyền được đọc/ghi cache.
Không đặt cache trong target repository. Token dùng phương pháp ước tính được ghi
phiên bản trong report; chi phí dùng đơn giá USD/giờ do người vận hành cung cấp và
provider wall time. Cả hai phục vụ vận hành, không thay thế tokenizer chính thức hay
hóa đơn provider.
