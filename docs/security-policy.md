# Chính sách bảo mật

## Tổng quan

Tài liệu này định nghĩa các bất biến bảo mật, ranh giới mối đe dọa,
và yêu cầu test bắt buộc cho CLI SAST Triage Platform.

Tất cả contributor phải coi đây là ràng buộc cứng. Vi phạm là bug,
không phải vấn đề phong cách.

## 1. Bất biến bảo mật Gitleaks

### G1. Giới hạn phạm vi bí mật thô

Giá trị bí mật thô từ phát hiện Gitleaks (trường `Secret` và `Match`)
chỉ được tồn tại trong phạm vi cục bộ của hàm parse
`GitleaksParser`. Chúng phải được redact trước khi tạo
`NormalizedFinding`.

### G2. Không bí mật thô trong model public

Không model domain public nào (`NormalizedFinding`, `SanitizedContext`,
`TriageInput`, `TriageDecision`, `PolicyDecision`, `TriageResult`,
`BatchResult`, `RunMetadata`, `ProcessingError`) được chứa giá trị
bí mật thô.

### G3. Không bí mật thô trong đầu ra

Bí mật thô không được xuất hiện trong:

- Thông báo log (bất kỳ mức nào).
- Đầu ra model đã serialize (JSON, dict).
- Thông báo exception hoặc traceback.
- Prompt gửi cho LLM.
- Artifact response từ LLM.
- Báo cáo JSON.
- Báo cáo Markdown.
- `ProcessingError.safe_message`.
- `repr` của bất kỳ public model nào.

### G4. Redact sớm

`GitleaksParser` phải redact trường `Secret` và `Match` **trước** khi
xây dựng `NormalizedFinding`. Trường `snippet` trong
`NormalizedFinding` kết quả chứa `<REDACTED_SECRET>`, không bao giờ
là giá trị thô.

### G5. Không hash bí mật

Không hash bí mật thô trong Sprint 1. Dùng placeholder chữ
`<REDACTED_SECRET>`.

### G6. Redact lại ngữ cảnh nguồn

Khi `SafeContextService` đọc file nguồn tại vị trí phát hiện
Gitleaks, mã nguồn trong local scope có thể chứa bí mật thô.
`ContextSanitizer` (bên trong `SafeContextService`) phải redact lại
trước khi tạo `SanitizedContext`. Raw source không bao giờ rời khỏi
`SafeContextService`.

### G7. Kiểm tra rò rỉ phòng thủ sâu

`SafeContextService` phải thực hiện kiểm tra rò rỉ cuối cùng trước
khi trả `SanitizedContext`.

Report generator phải thực hiện kiểm tra rò rỉ bổ sung trước khi ghi
file đầu ra. Nếu phát hiện mẫu bí mật trong đầu ra, phải redact hoặc
lỗi an toàn.

### G8. Yêu cầu test canary

Test phải chèn giá trị bí mật giả đã biết ("canary") vào dữ liệu
fixture Gitleaks và xác minh rằng canary không xuất hiện trong:

- `NormalizedFinding` đã serialize.
- `SanitizedContext`.
- `TriageInput`.
- Nội dung prompt LLM (đầu ra mock prompt builder).
- Đầu ra báo cáo JSON.
- Đầu ra báo cáo Markdown.
- Đầu ra log (bắt qua test log handler).

### G9. Cơ chế redact lại

Cơ chế chính xác để redact lại ngữ cảnh nguồn:
- Với phát hiện `GITLEAKS`, `ContextSanitizer` mask dòng phát hiện dạng `# <REDACTED_GITLEAKS_FINDING_LINE>` (giữ nguyên line count và indentation) và đổi chiến lược thành `REDACTED_LINE_WINDOW`.
- Với phát hiện `SEMGREP`, `ContextSanitizer` áp dụng các pattern credential chuẩn trên mã nguồn.
- Kiểm tra phòng vệ chiều sâu `forbidden_values` từ caller.

### G10. Phạm vi bảo đảm và không bảo đảm của ContextSanitizer

**ContextSanitizer bảo đảm:**
- Mask các dòng phát hiện của Gitleaks khi map line range thành công.
- Redact các pattern credential được hỗ trợ (literal credential assignments, Authorization Bearer, PEM private key blocks, password trong Connection URL).
- Kiểm tra danh sách `forbidden_values` do caller cung cấp (nếu phát hiện rò rỉ ➔ vô hiệu hóa context an toàn với `CONTEXT_SANITIZATION_FAILED`).
- Chỉ `SanitizedContext` (model Pydantic frozen công khai) được phép đi sang layer LLM Provider.

**ContextSanitizer KHÔNG bảo đảm:**
- Thấu thị phát hiện mọi bí mật không tuân theo pattern regex.
- Lọc thông tin nhận dạng cá nhân (PII).
- Che internal hostname hoặc username trong mã nguồn hay URL connection.
- Phát hiện hoặc bóc tách payload prompt injection trong mã nguồn (mã nguồn là untrusted data).
- Đảm bảo mã nguồn hoàn toàn hết tính nhạy cảm tuyệt đối.
- Đảm bảo tính an toàn ngữ nghĩa của phản hồi LLM.

### G11. Không gửi thông tin nhạy cảm Gitleaks cho LLM

`TriageInput` cho phát hiện Gitleaks KHÔNG ĐƯỢC chứa:

- Raw secret.
- Hash của raw secret.
- Raw Match.
- Author email.
- Commit message.
- Đường dẫn tuyệt đối.
- Raw scanner record.

## 2. Ranh giới raw source

### RS1. SafeContextService là ranh giới duy nhất

`SafeContextService` là component duy nhất đọc mã nguồn thô từ
repository. Tất cả truy cập file nguồn đi qua component này.

### RS2. Raw source chỉ trong local scope

Mã nguồn thô:

- Chỉ tồn tại trong local scope của `SafeContextService`.
- Không được serialize.
- Không được log.
- Không được đưa vào exception.
- Không được lưu trong `TriageResult` hoặc bất kỳ public model nào.
- Không xuất hiện trong `repr` của model public.

### RS3. Đầu ra duy nhất là SanitizedContext

Chỉ `SanitizedContext` được trả ra khỏi `SafeContextService`. Không
có `ContextPackage` public hay raw source rời khỏi component boundary.

### RS4. Một trường nội dung duy nhất

Bên trong `SafeContextService`, ngữ cảnh đã chọn dùng một trường
`selected_context` duy nhất (không có `source_snippet` và
`function_body` riêng biệt). `ContextStrategy` quyết định nội dung
đó là function, class, hay line window.

`SanitizedContext` cũng chỉ có một trường `sanitized_snippet`.

## 3. Bất biến bảo mật Semgrep

### S1. Sanitize không phải no-op

Semgrep finding và ngữ cảnh nguồn cũng phải đi qua
`ContextSanitizer` (bên trong `SafeContextService`). Mã nguồn gần
phát hiện có thể chứa credential không liên quan đến rule Semgrep.

### S2. Tất cả ngữ cảnh qua SafeContextService

Không ngữ cảnh nguồn nào được đến `TriageProvider` mà không đi qua
`SafeContextService`, bất kể loại scanner.

### S3. TriageProvider chỉ nhận TriageInput

Prompt gửi cho LLM được xây dựng từ `TriageInput`, không bao giờ từ
raw source hay `NormalizedFinding` trực tiếp. `TriageInput` chỉ chứa
trường an toàn đã chọn lọc.

### S4. Mã nguồn là dữ liệu không tin cậy

Mã nguồn từ repository mục tiêu là dữ liệu không tin cậy. Nó có
thể chứa:

- Giá trị credential.
- Payload prompt injection.
- Thủ thuật encoding hoặc nội dung nhị phân.

Prompt builder phải dùng dấu phân cách rõ ràng để tách ngữ cảnh
nguồn khỏi chỉ dẫn.

### S5. Validate đầu ra LLM

Tất cả response LLM phải được validate theo schema `TriageDecision`.
Response không hợp lệ → `triage_decision = null`,
`PolicyAction = TRIAGE_ERROR`.

### S6. Không thực thi đầu ra LLM

Đầu ra LLM là dữ liệu. Không bao giờ `eval`, `exec`, hay dùng để
xây dựng đường dẫn/lệnh.

## 4. Bất biến an toàn đường dẫn

### P1. Resolve gốc repository

Đường dẫn gốc repository phải được resolve đầy đủ bằng
`Path.resolve()` trước mọi thao tác file.

### P2. Resolve đường dẫn ứng viên

Mọi đường dẫn file từ scanner phải được resolve tương đối với gốc
repository.

### P3. Kiểm tra path containment

Sau khi resolve, đường dẫn ứng viên phải được xác minh nằm bên trong
gốc repository bằng đường dẫn đã resolve, không dùng so sánh chuỗi.

```python
# ĐÚNG
resolved_candidate.is_relative_to(resolved_root)

# SAI
str(candidate).startswith(str(root))
```

### P4. Mẫu đường dẫn bị chặn

| Mẫu | Ví dụ | Rủi ro |
|-----|-------|--------|
| Traversal `../` | `../../etc/passwd` | Đọc file ngoài repository |
| Đường dẫn tuyệt đối | `/etc/passwd` | Vượt ranh giới repository |
| Thoát symlink | `link -> /etc/passwd` | Theo symlink ra ngoài |
| File thiếu | `nonexistent.py` | File không có trong repo |
| File quá lớn | File Python 10 MB | Cạn kiệt bộ nhớ |
| File nhị phân | `.pyc`, `.so` | Không phải ngữ cảnh có ý nghĩa |
| Lỗi encoding | File không phải UTF-8 | Lỗi giải mã |

### P5. Giảm cấp graceful

Lỗi trích xuất ngữ cảnh KHÔNG ĐƯỢC xóa phát hiện. `SafeContextService`
trả `SanitizedContext` với `context_available=False` và
`missing_context_reasons` phù hợp. Policy có thể leo thang lên
`MANUAL_REVIEW`.

## 5. Ràng buộc Repository-Artifact

### B1. Không triage liên repository

Phát hiện từ repository A không bao giờ được triage bằng ngữ cảnh từ
repository B.

### B2. Xử lý mismatch

`ArtifactRepositoryMatch = MISMATCH` → dừng pipeline, lỗi cấu hình
an toàn.

### B3. Artifact chưa xác minh

`UNVERIFIED` hoặc `PARTIAL` → ghi `RunMetadata`, policy tự động leo
thang lên `MANUAL_REVIEW`.

## 6. An toàn báo cáo

### R1. Không bí mật thô

Báo cáo không chứa giá trị bí mật thô.

### R2. Không prompt thô

Báo cáo không chứa toàn bộ prompt LLM. Định danh phiên bản OK.

### R3. Không response LLM thô

Báo cáo không chứa response API LLM thô. Chỉ `TriageDecision` đã
validate.

### R4. Không traceback

`ProcessingError.safe_message` không chứa traceback Python.

### R5. Không đường dẫn tuyệt đối

`RunMetadata` dùng `repository_name` và `repository_identifier`.

### R6. Kiểm tra rò rỉ phòng thủ sâu

Reporter quét đầu ra tìm mẫu bí mật phổ biến trước khi ghi.

### R7. TriageResult không chứa SanitizedContext

`TriageResult` chỉ lưu `context_summary` (chuỗi tóm tắt ngắn), không lưu `SanitizedContext` hay full source snippet để đảm bảo reporter không vô tình ghi toàn bộ mã nguồn ra file báo cáo JSON/Markdown.

## 7. Ngữ nghĩa lỗi

### F1. Cách ly theo từng phát hiện

Một phát hiện thất bại không dừng các phát hiện khác. Phát hiện thất
bại nhận `SanitizedContext` với `context_available=False`,
`triage_decision=null`, `PolicyAction=TRIAGE_ERROR`.

### F2. Cách ly theo từng scanner

Parser một scanner thất bại không loại bỏ kết quả scanner còn lại.

### F3. Thất bại toàn bộ

Cả hai scanner thất bại tạo `BatchResult` với zero `TriageResult`,
hai `ProcessingError`, `RunMetadata` hợp lệ. Không phải crash.

### F4. Xử lý lỗi provider

Khi `TriageProvider` lỗi: KHÔNG bịa `TriageDecision` giả;
`triage_decision=null`; `PolicyAction=TRIAGE_ERROR`.

### F5. Thông báo lỗi an toàn

`ProcessingError.safe_message` không chứa bí mật thô, bản ghi scanner
thô, raw source, traceback, prompt/response LLM thô.

### F6. Log debug

Traceback chỉ trong log debug cục bộ sau redaction.

## 8. Mô hình mối đe dọa

| Mối đe dọa | Ranh giới | Biện pháp |
|-------------|-----------|-----------|
| JSON scanner độc hại với `file_path` craft | Scanner → Parser | Path containment trong SafeContextService (P1–P4) |
| Rò rỉ bí mật qua log, LLM, báo cáo | Gitleaks → Tất cả | Redact sớm (G4), redact lại (G6), leak check (G7, R6) |
| Prompt injection qua mã nguồn | Source → LLM | Dấu phân cách; validate LLM output (S4–S6) |
| LLM ảo giác verdict | LLM → Triage | Validate enum nghiêm ngặt (S5) |
| Path traversal | Scanner → Context | Resolve + containment (P1–P4) |
| Thoát symlink | Repository → Context | Resolve symlink, containment (P1, P3) |
| File quá lớn gây OOM | Repository → Context | Giới hạn kích thước file (mặc định 1 MB) |
| Phát hiện từ repository sai | Artifact → Pipeline | Xác minh ràng buộc (B1–B3) |
| Traceback rò rỉ bí mật | Bất kỳ → Báo cáo | Chỉ safe_message (F5); traceback trong debug log (F6) |
| Raw source rò rỉ qua public model | Context → Model | SafeContextService boundary (RS1–RS4) |
| Metadata nhạy cảm Gitleaks đến LLM | Parser → Provider | TriageInput lọc metadata (G10) |

## 9. Yêu cầu test bảo mật

| Iteration | Test bảo mật bắt buộc |
|-----------|----------------------|
| 2 (Parser) | Canary secret cho `GitleaksParser` (G8). Verify `NormalizedFinding` không chứa canary |
| 3 (Context) | Path traversal rejection (P4). Canary cho re-redaction (G6). Symlink escape. Verify raw source không trong SanitizedContext. Verify SafeContextService trả UNAVAILABLE khi lỗi (P5) |
| 4 (Triage) | Verify TriageInput không chứa bí mật (G10). Verify invalid LLM → TRIAGE_ERROR. Verify provider failure → null. Verify policy xét confidence + path_category |
| 5 (Báo cáo) | Verify báo cáo không chứa bí mật (R1). Không đường dẫn tuyệt đối (R5). Leak check (R6) |
| 6 (Runner) | Verify không `shell=True`. Không command injection. Stderr không log |
| 7 (LLM) | Prompt injection không bypass validation. LLM output không executed (S6) |
