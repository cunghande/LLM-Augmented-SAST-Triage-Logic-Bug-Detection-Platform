# Scanner Field Mapping Document

> [!IMPORTANT]
> **Tuyên bố Phạm vi:** Tài liệu này là tài liệu kỹ thuật chốt hợp đồng ánh xạ (contract specification) giữa dữ liệu scanner thô (Semgrep JSON & Gitleaks JSON) và domain model `NormalizedFinding`. Tài liệu này **chưa phải là code triển khai** (chưa viết parser hay utility function trong task này).

---

## 1. Môi Trường Kiểm Thử và Blocker Môi Trường

- **Phiên bản Python hiện tại trên máy chủ:** `Python 3.14.6`
- **Yêu cầu hỗ trợ trong `pyproject.toml`:** `requires-python = ">=3.11, <3.14"`

> [!CAUTION]
> **Blocker Nghiệm Thu Iteration 1:** Do máy chủ chạy Python 3.14.6 (vượt phạm vi `<3.14`), kết quả chạy test thành công trong Iteration 1 được ghi nhận là **compatibility observation**, KHÔNG thể tuyên bố Iteration 1 đã được nghiệm thu (verified) trong môi trường hỗ trợ chính thức cho đến khi môi trường kiểm thử dùng Python 3.12 hoặc 3.13.

---

## 2. Ánh Xạ Semgrep Raw JSON → NormalizedFinding

### 2.1 Bảng Ánh Xạ Trường

| Raw Semgrep Field (thô) | Field trong `NormalizedFinding` | Kiểu dữ liệu | Bắt buộc | Ghi chú xử lý |
|-------------------------|--------------------------------|--------------|----------|---------------|
| *(được sinh ra)* | `finding_instance_id` | `str` | Có | Hash xác định: `sha256(f"SEMGREP:{check_id}:{path}:{start.line}:{end.line}")[:16]` |
| *(hằng số)* | `scanner` | `ScannerType` | Có | `ScannerType.SEMGREP` |
| *(hằng số)* | `finding_type` | `FindingType` | Có | `FindingType.SAST` |
| `check_id` | `rule_id` | `str` | Có | Rule identifier thô từ Semgrep |
| `extra.metadata.category` (hoặc `check_id`) | `rule_name` | `str \| None` | Không | Tên rule hiển thị |
| `path` | `file_path` | `str` | Có | Đường dẫn tương đối với gốc repository |
| `start.line` | `start_line` | `int` | Có | Đánh số dòng bắt đầu từ 1 |
| `end.line` | `end_line` | `int \| None` | Không | Đánh số dòng kết thúc (mặc định bằng `start_line` nếu thiếu) |
| `extra.severity` | `severity` | `Severity` | Có | Ánh xạ: `ERROR` → `HIGH`, `WARNING` → `MEDIUM`, `INFO` → `LOW`, khác → `UNKNOWN` |
| `extra.message` | `message` | `str` | Có | Mô tả lỗi từ Semgrep |
| `extra.lines` | *(không lưu)* | — | Không | Raw source fragment bị bỏ tại parser boundary |
| `extra.metadata` | `metadata` | `dict[str, Any]` | Có | Lọc theo allowlist an toàn bên dưới |

### 2.2 Semgrep Metadata Allowlist
Chỉ các key sau trong `extra.metadata` mới được đưa vào `NormalizedFinding.metadata`:
- `cwe`: Danh sách mã CWE
- `owasp`: Danh sách hạng mục OWASP
- `technology`: Danh sách công nghệ (ví dụ: `python`)
- `category`: Thể loại rule (ví dụ: `security`)
- `confidence`: Mức độ tin cậy từ rule author (`HIGH`, `MEDIUM`, `LOW`)
- `references`: Danh sách URL tham khảo

---

## 3. Ánh Xạ Gitleaks Raw JSON → NormalizedFinding

### 3.1 Bảng Ánh Xạ Trường

| Raw Gitleaks Field (thô) | Field trong `NormalizedFinding` | Kiểu dữ liệu | Bắt buộc | Ghi chú xử lý an toàn |
|--------------------------|--------------------------------|--------------|----------|-----------------------|
| *(được sinh ra)* | `finding_instance_id` | `str` | Có | Hash xác định: `sha256(f"GITLEAKS:{RuleID}:{File}:{StartLine}:{EndLine}")[:16]` |
| *(hằng số)* | `scanner` | `ScannerType` | Có | `ScannerType.GITLEAKS` |
| *(hằng số)* | `finding_type` | `FindingType` | Có | `FindingType.SECRET` |
| `RuleID` | `rule_id` | `str` | Có | Rule ID của bí mật |
| `Description` | `rule_name` | `str \| None` | Không | Mô tả loại bí mật |
| `File` | `file_path` | `str` | Có | Đường dẫn file chứa bí mật (tương đối) |
| `StartLine` | `start_line` | `int` | Có | Dòng chứa bí mật |
| `EndLine` | `end_line` | `int \| None` | Không | Dòng kết thúc bí mật |
| *(mặc định)* | `severity` | `Severity` | Có | Luôn là `Severity.UNKNOWN` trong Sprint 1 |
| `Description` | `message` | `str` | Có | Thông báo phát hiện bí mật |
| `Match` | *(không lưu)* | — | Không | Chỉ kiểm tra redaction consistency trong local scope rồi loại bỏ |
| `Entropy` | `metadata` | `dict[str, Any]` | Có | Lọc theo allowlist an toàn bên dưới |

### 3.2 Quy Tắc Bảo Mật Gitleaks (Gitleaks Security Mapping)
1. **Trường `Secret` thô:** **KHÔNG BAO GIỜ** truyền vào `NormalizedFinding`, `metadata`, hay bất kỳ public domain model nào.
2. **Trường `Match` thô:** Chỉ tồn tại trong local scope của parser để kiểm tra consistency, sau đó bị loại bỏ; không có trường snippet trong `NormalizedFinding`.
3. **Thông tin tác giả & commit:** Các trường `Author`, `Email`, `Commit`, `Date`, `Message` thô từ Gitleaks **Bị LOẠI BỎ (DROPPED)** hoàn toàn, không đưa vào `NormalizedFinding` hay `TriageInput`.
4. **Không copy nguyên văn:** Không lưu nguyên văn raw Gitleaks JSON record vào `metadata`.
5. **Raw Test Fixtures:** Các file fixture JSON của Gitleaks chứa canary secret `CANARY_SUPER_SECRET_DO_NOT_LEAK` được coi là **dữ liệu nhạy cảm phục vụ kiểm thử (test-sensitive data)**. Không log hoặc copy nội dung fixture này vào các bản báo cáo public.

### 3.3 Gitleaks Metadata Allowlist
Chỉ các key an toàn sau mới được lưu vào `NormalizedFinding.metadata`:
- `entropy`: Giá trị entropy của chuỗi phát hiện (`float`)
- `secret_category`: Phân loại bí mật an toàn được suy ra từ `RuleID` (ví dụ: `cloud_credential`, `private_key`, `api_key`)
- `rule_description`: Mô tả quy tắc phát hiện bí mật (`str`)

---

## 4. Ánh Xạ Severity

- **Semgrep Severity Mapping:**
  - `"ERROR"` → `Severity.HIGH`
  - `"WARNING"` → `Severity.MEDIUM`
  - `"INFO"` → `Severity.LOW`
  - Giá trị khác/thiếu → `Severity.UNKNOWN`
- **Gitleaks Severity Mapping:**
  - Gitleaks scanner thô không cung cấp severity đáng tin cậy. Mặc định luôn đặt `Severity.UNKNOWN` trong Sprint 1. (Policy sau này sẽ tự động leo thang hoặc kiểm soát theo `secret_category`).

---

## 5. Danh Sách Các Trường Bị Loại Bỏ (Dropped Fields)

Các trường thô sau từ scanner bị loại bỏ triệt để để bảo vệ an toàn dữ liệu và tối ưu token prompt:
- **Từ Semgrep:** `start.col`, `end.col`, `start.offset`, `end.offset`, các trường mở rộng không nằm trong allowlist của `extra.metadata`.
- **Từ Gitleaks:** `Secret` (thô), `Author`, `Email`, `Commit`, `Date`, `Message` (commit message), `SymlinkFile`, `Fingerprint` thô.

---

## 6. Xử Lý Các Trạng Thái Biên (Edge Cases & Exception Handling)

1. **Thiếu trường bắt buộc (Missing Required Fields):**
   - Trường bắt buộc của Semgrep: `check_id`, `path`, `start.line`, `extra.message`.
   - Trường bắt buộc của Gitleaks: `RuleID`, `File`, `StartLine`.
   - Hành vi: Nếu một record thô thiếu bất kỳ trường bắt buộc nào, parser sẽ **bỏ qua (skip)** record đó và tạo một bản ghi `ProcessingError` với `stage = ProcessingStage.PARSE`.
2. **Cách ly lỗi từng record (Per-finding Isolation):**
   - Nếu một record trong mảng findings bị lỗi (thiếu trường, sai kiểu dữ liệu), parser chỉ bỏ qua record đó và tiếp tục xử lý các record hợp lệ còn lại.
3. **Báo cáo rỗng (Empty Report):**
   - File JSON chứa mảng `results: []` (Semgrep) hoặc mảng rỗng `[]` (Gitleaks) sẽ trả về danh sách `NormalizedFinding` rỗng `[]` và 0 lỗi.
4. **Lỗi đọc file cấp Artifact (Artifact-level File Errors):**
   - File không tồn tại: `PARSE_FILE_NOT_FOUND`.
   - File không thể đọc do từ chối truy cập (permission denied): `PARSE_FILE_READ_ERROR`.
   - File không phải mã hóa UTF-8: `PARSE_UNSUPPORTED_ENCODING`.
5. **Cấu trúc JSON bị hỏng (Malformed JSON):**
   - Nếu file JSON bị lỗi cú pháp mã hóa (sai định dạng JSON), parser ghi bản ghi `ProcessingError` cấp scanner với `error_code = PARSE_INVALID_JSON`.
6. **Kiểu Root JSON không đúng (Invalid Root Type):**
   - Semgrep bắt buộc root là JSON object (`PARSE_INVALID_ROOT`). Gitleaks bắt buộc root là JSON array (`PARSE_INVALID_ROOT`).

---

## 7. Khác Biệt Chính Giữa Semgrep và Gitleaks

| Đặc điểm | Semgrep | Gitleaks |
|----------|---------|----------|
| `finding_type` | `SAST` | `SECRET` |
| Severity | Ánh xạ từ scanner (`ERROR`, `WARNING`, `INFO`) | Mặc định `UNKNOWN` |
| Yêu cầu Redaction | Không giữ `extra.lines`; source được đọc qua Safe Context | Không giữ `Secret`/`Match`; source repository được redact lại qua Safe Context |
| Metadata allowlist | CWE, OWASP, technology, category, confidence | Entropy, secret_category, rule_description |
| Cấu trúc JSON thô | Object có key `results: [...]` | Array các đối tượng `[...]` |
