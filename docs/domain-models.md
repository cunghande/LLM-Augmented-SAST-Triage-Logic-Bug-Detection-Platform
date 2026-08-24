# Domain Models

## Nguyên tắc thiết kế

1. **Model đầu ra bất biến.** Tất cả model rời khỏi ranh giới
   component là Pydantic v2 frozen model. Trạng thái nội bộ có thể
   thay đổi không bao giờ được serialize vào báo cáo hoặc metadata.

2. **Tách biệt trách nhiệm.** Mỗi model đại diện cho một giai đoạn
   của pipeline. Model không hấp thụ trách nhiệm từ giai đoạn khác.

3. **Không bí mật thô trong model public.** Giá trị bí mật thô từ
   Gitleaks chỉ tồn tại trong phạm vi cục bộ của `GitleaksParser`.
   Tất cả model phía sau chỉ chứa giá trị đã redact.

4. **Kết hợp thay vì thay đổi.** `TriageResult` kết hợp tham chiếu
   đến các sub-model. Nó không thay đổi bất kỳ model nào.

5. **Raw source không vượt component boundary.** Mã nguồn thô từ
   repository chỉ tồn tại trong local scope của `SafeContextService`.
   Không có public Pydantic model nào chứa raw source text.

6. **Sáu public model rời khỏi ranh giới component:**
   - `NormalizedFinding` — dữ kiện scanner an toàn.
   - `SanitizedContext` — ngữ cảnh duy nhất LLM provider được nhận.
   - `TriageInput` — gói đầu vào cho provider.
   - `TriageDecision` — kết quả LLM.
   - `PolicyDecision` — quyết định hệ thống.
   - `TriageResult` — kết quả tổng hợp cuối cùng.

---

## Enum

### ScannerType

| Giá trị | Mô tả |
|---------|-------|
| `SEMGREP` | Scanner SAST Semgrep |
| `GITLEAKS` | Scanner phát hiện bí mật Gitleaks |

### FindingType

| Giá trị | Mô tả |
|---------|-------|
| `SAST` | Phát hiện phân tích tĩnh (lỗ hổng mã) |
| `SECRET` | Bí mật hoặc credential được phát hiện |

### Severity

| Giá trị | Mô tả |
|---------|-------|
| `CRITICAL` | Mức nghiêm trọng tới hạn |
| `HIGH` | Mức nghiêm trọng cao |
| `MEDIUM` | Mức nghiêm trọng trung bình |
| `LOW` | Mức nghiêm trọng thấp |
| `INFO` | Thông tin |
| `UNKNOWN` | Không xác định được mức nghiêm trọng |

**Ánh xạ từ scanner:**

- Semgrep: `ERROR` → `HIGH`, `WARNING` → `MEDIUM`, `INFO` → `LOW`,
  thiếu → `UNKNOWN`.
- Gitleaks: mặc định `UNKNOWN` trong Sprint 1. Scanner không cung cấp
  severity đáng tin cậy. Có thể lưu `secret_category` an toàn trong
  metadata để policy xử lý bảo thủ theo danh mục.

### ContextStrategy

| Giá trị | Mô tả |
|---------|-------|
| `PYTHON_FUNCTION` | Hàm bao quanh được trích xuất qua AST |
| `PYTHON_CLASS` | Class bao quanh được trích xuất qua AST |
| `LINE_WINDOW` | Cửa sổ dòng cố định (AST thất bại hoặc phạm vi quá lớn) |
| `REDACTED_LINE_WINDOW` | Cửa sổ dòng cố định với redaction mạnh (mặc định cho Gitleaks) |
| `UNAVAILABLE` | Không trích xuất được ngữ cảnh |

**Chiến lược theo scanner:**

- Semgrep: ưu tiên `PYTHON_FUNCTION` → `PYTHON_CLASS` → `LINE_WINDOW`
  → `UNAVAILABLE`.
- Gitleaks: mặc định `REDACTED_LINE_WINDOW`. AST chỉ dùng để lấy
  structural metadata (tên hàm/class bao quanh), không gửi toàn bộ
  function body theo mặc định.

### SourceKind

Nguồn gốc mã được trích xuất.

| Giá trị | Mô tả |
|---------|-------|
| `WORKTREE` | Cây làm việc hiện tại (Sprint 1 chỉ hỗ trợ giá trị này) |

### PathCategory

Phân loại đường dẫn file để hỗ trợ policy.

| Giá trị | Mô tả |
|---------|-------|
| `PRODUCTION` | Mã sản xuất |
| `TEST` | File test |
| `FIXTURE` | Test fixture hoặc mock data |
| `EXAMPLE` | Mã ví dụ, tutorial |
| `DOCUMENTATION` | File tài liệu có chứa code |
| `UNKNOWN` | Không phân loại được |

### MissingContextReason

Lý do ngữ cảnh không có sẵn hoặc bị giới hạn.

| Giá trị | Mô tả |
|---------|-------|
| `SOURCE_FILE_NOT_FOUND` | File nguồn không tồn tại trong repository |
| `SOURCE_PATH_OUTSIDE_REPOSITORY` | Đường dẫn nguồn nằm ngoài gốc repository |
| `SOURCE_FILE_TOO_LARGE` | File nguồn vượt giới hạn kích thước |
| `SOURCE_FILE_UNSUPPORTED_ENCODING` | File nguồn không phải UTF-8 hoặc encoding không hỗ trợ |
| `SOURCE_FILE_READ_ERROR` | Lỗi đọc file nguồn khi file tồn tại nhưng không thể đọc do permission/IO failure |
| `PYTHON_AST_PARSE_FAILED` | Parse AST Python thất bại |
| `ENCLOSING_SCOPE_EXCEEDED_LIMIT` | Phạm vi hàm/class bao quanh vượt giới hạn kích thước |
| `INVALID_FINDING_LINE_RANGE` | Dải dòng từ scanner không hợp lệ hoặc ngoài phạm vi file |
| `ARTIFACT_REPOSITORY_MISMATCH` | Artifact và repository không khớp |
| `CONTEXT_SANITIZATION_FAILED` | Thất bại khi làm sạch ngữ cảnh (ví dụ: leak-check thất bại hoặc line mapping bị lỗi) |

### ModelVerdict

Phân loại triage do LLM đề xuất.

| Giá trị | Ý nghĩa |
|---------|---------|
| `LIKELY_TP` | LLM cho rằng đây có khả năng là true positive |
| `LIKELY_FP` | LLM cho rằng đây có khả năng là false positive |
| `NEEDS_REVIEW` | LLM không chắc chắn, cần người xem xét |

### ModelConfidence

Mức độ tin cậy của LLM.

| Giá trị | Mô tả |
|---------|-------|
| `LOW` | Độ tin cậy thấp với verdict |
| `MEDIUM` | Độ tin cậy trung bình |
| `HIGH` | Độ tin cậy cao |

### PolicyAction

Quyết định triage cấp hệ thống sau khi áp dụng quy tắc policy.

| Giá trị | Ý nghĩa |
|---------|---------|
| `LIKELY_TP` | Được policy xác nhận có khả năng là true positive |
| `FP_CANDIDATE` | Được chấp nhận là ứng viên false positive (vẫn được báo cáo) |
| `MANUAL_REVIEW` | Cần người xem xét thủ công |
| `TRIAGE_ERROR` | Triage thất bại; phát hiện cần người xem xét |

### ProcessingStage

| Giá trị | Mô tả |
|---------|-------|
| `PARSE` | Parse đầu ra scanner |
| `CONTEXT` | Trích xuất ngữ cảnh mã nguồn |
| `SANITIZE` | Làm sạch ngữ cảnh mã nguồn |
| `TRIAGE` | Phân loại bằng LLM |
| `POLICY` | Áp dụng policy |
| `REPORT` | Tạo báo cáo |
| `BINDING` | Xác minh ràng buộc repository-artifact |

### ArtifactRepositoryMatch

| Giá trị | Ý nghĩa |
|---------|---------|
| `VERIFIED` | Artifact được xác nhận thuộc về repository này |
| `PARTIAL` | Một số đường dẫn file khớp, một số không |
| `UNVERIFIED` | Không xác định được ràng buộc |
| `MISMATCH` | Metadata artifact mâu thuẫn với repository |

---

## Public Model

### NormalizedFinding

Dữ kiện từ scanner, an toàn để serialize. Được tạo bởi parser.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `finding_instance_id` | `str` | Có | ID thể hiện: hash của `(scanner, rule_id, file_path, start_line, end_line)` |
| `scanner` | `ScannerType` | Có | Scanner nào tạo ra phát hiện này |
| `finding_type` | `FindingType` | Có | `SAST` hoặc `SECRET` |
| `rule_id` | `str` | Có | Định danh rule của scanner |
| `rule_name` | `str \| None` | Không | Tên rule dễ đọc |
| `file_path` | `str` | Có | Tương đối với gốc repository |
| `start_line` | `int` | Có | Dòng bắt đầu, đánh số từ 1 |
| `end_line` | `int \| None` | Không | Dòng kết thúc, đánh số từ 1 |
| `severity` | `Severity` | Có | Ánh xạ từ scanner |
| `message` | `str` | Có | Mô tả của scanner |
| `metadata` | `dict[str, Any]` | Có | Dữ liệu scanner-specific an toàn |

**Ràng buộc:**

- Frozen (bất biến).
- KHÔNG ĐƯỢC chứa: `Secret` thô Gitleaks, `Match` thô chứa bí
  mật, LLM verdict, policy action, ngữ cảnh nguồn nhúng.
- `metadata` cho Semgrep có thể bao gồm: `cwe`, `owasp`,
  `technology`, `references`.
- `metadata` cho Gitleaks có thể bao gồm: `entropy`,
  `commit_sha` (không phải nội dung commit), `secret_category`,
  `rule_description`. KHÔNG ĐƯỢC chứa: `author` email, commit
  message, raw match.
- Không chứa snippet hoặc source text. Parser chỉ giữ vị trí và metadata an toàn;
  source được đọc và sanitize riêng bởi `SafeContextService`.
- `file_path` luôn tương đối. Đường dẫn tuyệt đối bị từ chối.

### SanitizedContext

Ngữ cảnh mã nguồn đã sanitize, an toàn cho LLM. Là đầu ra duy nhất
của `SafeContextService` và là model ngữ cảnh duy nhất được phép rời
khỏi component boundary.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `finding_id` | `str` | Có | Tham chiếu `NormalizedFinding.finding_instance_id` |
| `sanitized_snippet` | `str \| None` | Không | Đoạn mã đã redact và cắt ngắn. None nếu context unavailable |
| `context_strategy` | `ContextStrategy` | Có | Chiến lược trích xuất đã dùng |
| `context_start_line` | `int \| None` | Không | Dòng bắt đầu ngữ cảnh đã trích xuất |
| `context_end_line` | `int \| None` | Không | Dòng kết thúc ngữ cảnh đã trích xuất |
| `finding_start_line` | `int` | Có | Dòng bắt đầu phát hiện (để LLM định vị) |
| `finding_end_line` | `int \| None` | Không | Dòng kết thúc phát hiện |
| `enclosing_function` | `str \| None` | Không | Tên hàm bao quanh (từ AST) |
| `enclosing_class` | `str \| None` | Không | Tên class bao quanh (từ AST) |
| `limited_imports` | `list[str] \| None` | Không | Import liên quan (đã lọc, giới hạn số lượng) |
| `limited_decorators` | `list[str] \| None` | Không | Decorator của hàm/class bao quanh |
| `path_category` | `PathCategory` | Có | Phân loại đường dẫn file |
| `source_kind` | `SourceKind` | Có | Nguồn gốc mã (Sprint 1: luôn `WORKTREE`) |
| `context_available` | `bool` | Có | Có trích xuất được ngữ cảnh không |
| `missing_context_reasons` | `list[MissingContextReason]` | Có | Lý do ngữ cảnh thiếu (rỗng nếu context_available=True) |
| `redactions_applied` | `int` | Có | Số lượng redaction được thực hiện |
| `redaction_types` | `list[str]` | Có | Loại redaction (ví dụ: `secret_value`, `credential_pattern`, `high_entropy`) |
| `truncated` | `bool` | Có | Đoạn mã có bị cắt ngắn không |

**Ràng buộc:**

- Frozen (bất biến).
- KHÔNG ĐƯỢC chứa giá trị bí mật thô hoặc mẫu credential chưa
  sanitize.
- Luôn được tạo ra, kể cả khi context không trích xuất được
  (`context_available=False`, `missing_context_reasons` không rỗng).
- Chỉ có một trường chứa nội dung mã: `sanitized_snippet`. Không có
  trường riêng cho `function_body` hay `source_snippet`.
  `ContextStrategy` quyết định nội dung đó là function, class, hay
  line window.
- Đây là model ngữ cảnh duy nhất `TriageProvider` được nhận (qua
  `TriageInput`).

### TriageInput

Gói đầu vào duy nhất cho `TriageProvider`. Dùng composition chứa `finding: NormalizedFinding` và `context: SanitizedContext`. `TriageProvider` KHÔNG nhận raw source.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `finding` | `NormalizedFinding` | Có | Dữ kiện phát hiện an toàn từ parser |
| `context` | `SanitizedContext` | Có | Ngữ cảnh đã sanitize từ SafeContextService |
| `prompt_version` | `str` | Có | Phiên bản mẫu prompt |
| `output_schema_version` | `str` | Có | Phiên bản schema đầu ra mong đợi |
| `prompt_type` | `str` | Có | Loại prompt: `semgrep_triage` hoặc `gitleaks_triage` |

**Ràng buộc:**

- Frozen (bất biến).
- `context.finding_id` phải trùng khớp với `finding.finding_instance_id`.
- `prompt_version`, `output_schema_version`, và `prompt_type` không được rỗng.
  raw match, raw secret.
- Không chứa bí mật thô, đường dẫn tuyệt đối, hay raw source.

**Nội dung Semgrep TriageInput:**

- `rule_id`, `message`, `severity`.
- `safe_metadata` với CWE/OWASP.
- Đường dẫn tương đối, dải dòng phát hiện.
- `SanitizedContext` với: AST scope hoặc line window đã sanitize,
  tên hàm/class bao quanh, import/decorator giới hạn, trạng thái
  ngữ cảnh.

**Nội dung Gitleaks TriageInput:**

- `rule_id`, `rule_description`.
- `safe_metadata` với `secret_category` nếu có.
- Đường dẫn tương đối, `path_category`, dải dòng phát hiện.
- `SanitizedContext` với: cửa sổ dòng đã redact, tên hàm/class bao
  quanh, cách dùng xung quanh placeholder, trạng thái ngữ cảnh.

### TriageDecision

Đề xuất phân loại từ LLM. Tùy chọn trong `TriageResult` (null khi
provider lỗi).

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `model_verdict` | `ModelVerdict` | Có | Phân loại của LLM |
| `model_confidence` | `ModelConfidence` | Có | Mức tin cậy |
| `summary` | `str` | Có | Tóm tắt ngắn lý do phân loại |
| `evidence` | `list[str]` | Có | Bằng chứng kiểm chứng được từ context |
| `missing_information` | `list[str]` | Có | Thông tin bổ sung cần thiết |
| `assumptions` | `list[str]` | Có | Giả định LLM đặt ra |
| `model_version` | `str` | Có | Định danh model LLM |
| `prompt_version` | `str` | Có | Phiên bản mẫu prompt |

**Ràng buộc:**

- Frozen (bất biến).
- `model_verdict` phải là giá trị enum `ModelVerdict` hợp lệ.
- `model_confidence` phải là giá trị enum `ModelConfidence` hợp lệ.
- Không yêu cầu chain-of-thought. Chỉ yêu cầu `summary` ngắn và
  `evidence` kiểm chứng được từ context.
- KHÔNG ĐƯỢC chứa ngữ cảnh nguồn thô hoặc bí mật.
- Khi provider lỗi, `TriageDecision` không được bịa đặt.
  `TriageResult` đặt `triage_decision = None`.

### PolicyDecision

Quyết định cấp hệ thống sau khi áp dụng quy tắc policy bảo thủ.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `action` | `PolicyAction` | Có | Hành động triage của hệ thống |
| `reasons` | `list[str]` | Có | Giải thích tại sao chọn hành động này |
| `policy_version` | `str` | Có | Định danh phiên bản quy tắc policy |
| `escalated` | `bool` | Có | Hành động có bị leo thang từ đề xuất model không |
| `escalation_reason` | `str \| None` | Không | Lý do leo thang |

**Ràng buộc:**

- Frozen (bất biến).
- `action` phải là giá trị enum `PolicyAction` hợp lệ.
- Khi `triage_decision` là null → `action = TRIAGE_ERROR`.
- Không tự động loại bỏ: mọi phát hiện nhận `PolicyDecision` và
  xuất hiện trong báo cáo.

**Bảng policy bảo thủ (mặc định, cấu hình được ở Iteration 4):**

| Model Verdict | Confidence | Điều kiện bổ sung | Policy Action |
|---------------|------------|-------------------|---------------|
| `LIKELY_TP` | `HIGH` | — | `LIKELY_TP` |
| `LIKELY_TP` | `MEDIUM` | — | `MANUAL_REVIEW` (leo thang) |
| `LIKELY_TP` | `LOW` | — | `MANUAL_REVIEW` (leo thang) |
| `LIKELY_FP` | `HIGH` | path ∈ {TEST, FIXTURE, EXAMPLE} VÀ không phải protected secret category | `FP_CANDIDATE` |
| `LIKELY_FP` | `HIGH` | path = PRODUCTION | `MANUAL_REVIEW` (leo thang) |
| `LIKELY_FP` | `MEDIUM` | — | `MANUAL_REVIEW` (leo thang) |
| `LIKELY_FP` | `LOW` | — | `MANUAL_REVIEW` (leo thang) |
| `NEEDS_REVIEW` | bất kỳ | — | `MANUAL_REVIEW` |
| null (lỗi) | N/A | — | `TRIAGE_ERROR` |

**Điều kiện bổ sung luôn áp dụng (override kết quả trên):**

| Điều kiện | Policy Action |
|-----------|---------------|
| `context_available = false` | `MANUAL_REVIEW` |
| `truncated = true` nghiêm trọng | `MANUAL_REVIEW` |
| `artifact_repository_match` ∈ {UNVERIFIED, PARTIAL} | `MANUAL_REVIEW` |
| Gitleaks protected category (private key, cloud credential, signing key, database credential) | `MANUAL_REVIEW` (trừ khi `LIKELY_TP` + `HIGH`) |

**Policy cũng xem xét:** scanner, context availability, truncation,
path category, artifact repository match, severity, protected
category.

### TriageResult

Kết quả tổng hợp cuối cùng cho một phát hiện. Kết hợp các sub-model
mà không thay đổi chúng.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `finding` | `NormalizedFinding` | Có | Phát hiện gốc |
| `context_summary` | `str \| None` | Không | Tóm tắt ngắn gọn chiến lược ngữ cảnh (ví dụ: "PYTHON_FUNCTION context, lines 10-25"). Null nếu không có ngữ cảnh |
| `evidence_details` | `dict \| None` | Không | Projection source-free của source, sink, path, caller, control và completeness |
| `triage_decision` | `TriageDecision \| None` | Không | Kết quả LLM. Null nếu provider lỗi |
| `policy_decision` | `PolicyDecision` | Có | Quyết định hệ thống |
| `processing_errors` | `list[ProcessingError]` | Có | Lỗi trong quá trình xử lý |
| `processed_at` | `datetime` | Có | Thời điểm xử lý hoàn tất |
| `processing_duration_ms` | `int \| None` | Không | Thời gian xử lý (mili giây) |
| `provider_duration_ms` | `int \| None` | Không | Thời gian dành cho provider (mili giây) |
| `triage_input_digest` | `str \| None` | Không | SHA-256 của `TriageInput` đã sanitize để đối soát, không phải raw prompt |
| `risk_score` / `risk_level` | `float \| None` / `str \| None` | Không | Điểm ưu tiên deterministic 0–5 và mức LOW/MEDIUM/HIGH/CRITICAL |
| `risk_factors` | `dict[str, float]` | Có | Năm thành phần severity, reachability, exposure, data sensitivity và exploitability |
| `risk_scoring_version` | `str \| None` | Không | Phiên bản công thức để audit và tái lập |
| `remediation` | `str \| None` | Không | Hướng khắc phục an toàn, chỉ là đề xuất cần developer review |
| `validation_checklist` | `list[str]` | Có | Các bước xác minh và regression test sau khi sửa |
| `decision_cache_status` / `cache_hit` | `str` / `bool` | Có | `DISABLED`, `MISS` hoặc `HIT`; cờ hit phải nhất quán với trạng thái |
| `input_tokens` / `output_tokens` | `int \| None` | Không | Token ước tính trên prompt an toàn và decision đã validate |
| `token_count_method` | `str \| None` | Không | Phiên bản phương pháp ước tính token |
| `estimated_cost_usd` | `float \| None` | Không | Chi phí provider ước tính; `None` khi chưa cấu hình đơn giá |
| `cost_model_version` | `str \| None` | Không | Phiên bản công thức ước tính chi phí |

**Ràng buộc:**

- Frozen (bất biến).
- Không thay đổi `NormalizedFinding` để thêm ngữ cảnh hoặc verdict.
- `context_summary` là chuỗi tóm tắt ngắn, không chứa full source snippet, imports, decorators, hay bí mật.
- Không lưu `SanitizedContext` trong `TriageResult` để tránh vô tình serialize toàn bộ mã nguồn ra report.
- Không chứa raw source text hay traceback.
- Risk assessment không đọc raw source và không dùng verdict LLM làm đầu vào;
  cùng dữ kiện chuẩn hóa và structured evidence cho cùng kết quả.

### ProcessingError

Bản ghi lỗi an toàn cho báo cáo.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `finding_id` | `str \| None` | Không | Null cho lỗi cấp scanner |
| `scanner` | `ScannerType \| None` | Không | Scanner nào, nếu liên quan |
| `stage` | `ProcessingStage` | Có | Giai đoạn pipeline xảy ra lỗi |
| `error_code` | `str` | Có | Mã lỗi máy đọc được |
| `safe_message` | `str` | Có | Thông báo an toàn. Không traceback, không bí mật |
| `retryable` | `bool` | Có | Thử lại có thể thành công không |

**Ràng buộc:**

- KHÔNG ĐƯỢC chứa traceback, bí mật thô, bản ghi scanner thô, hoặc
  raw source.

### BatchResult

Kết quả cấp cao nhất của một lần chạy pipeline.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `run_metadata` | `RunMetadata` | Có | Metadata cấp lần chạy |
| `results` | `list[TriageResult]` | Có | Kết quả từng phát hiện |
| `scanner_errors` | `list[ProcessingError]` | Có | Lỗi cấp scanner/parser |

### ScannerParseResult

Kết quả phân tích một artifact scanner đơn lẻ. Được trả về từ parser
(ví dụ: `parse_semgrep_json`, `parse_gitleaks_json`).

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `findings` | `tuple[NormalizedFinding, ...]` | Có | Các phát hiện đã chuẩn hóa (rỗng nếu không có) |
| `errors` | `tuple[ProcessingError, ...]` | Có | Lỗi cấp artifact hoặc per-record (rỗng nếu không có) |

**Ràng buộc:**

- Frozen (bất biến).
- Dùng `tuple` thay `list` để collection không bị mutate sau khi
  parser trả kết quả.
- Không chứa raw artifact content hoặc đường dẫn artifact tuyệt đối.

### RunMetadata

Metadata cấp lần chạy. Không chứa đường dẫn tuyệt đối.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `run_id` | `str` | Có | Định danh lần chạy (UUID) |
| `repository_name` | `str` | Có | Tên thư mục repository |
| `repository_identifier` | `str` | Có | Định danh ổn định |
| `commit_sha` | `str \| None` | Không | SHA commit HEAD nếu có |
| `working_tree_state` | `str \| None` | Không | `clean`, `dirty`, hoặc `unknown` |
| `artifact_repository_match` | `ArtifactRepositoryMatch` | Có | Kết quả xác minh ràng buộc |
| `scanners_attempted` | `list[ScannerType]` | Có | Scanner đã gọi hoặc artifact cung cấp |
| `scanners_succeeded` | `list[ScannerType]` | Có | Scanner parse artifact thành công |
| `scanner_versions` | `dict[str, str \| None]` | Có | Scanner → phiên bản |
| `scanner_config_ids` | `dict[str, str \| None]` | Có | Scanner → định danh cấu hình |
| `input_artifact_hashes` | `dict[str, str \| None]` | Có | Scanner → SHA256 file artifact |
| `prompt_version` | `str \| None` | Không | Phiên bản mẫu prompt |
| `model_version` | `str \| None` | Không | Phiên bản model LLM |
| `policy_version` | `str` | Có | Phiên bản quy tắc policy |
| `triage_provider` | `str` | Có | Tên provider (`fake`, `openai`, v.v.) |
| `tool_version` | `str` | Có | Phiên bản công cụ CLI |
| `cli_mode` | `str` | Có | `triage` hoặc `scan-and-triage` |
| `started_at` | `datetime` | Có | Thời điểm bắt đầu |
| `completed_at` | `datetime` | Có | Thời điểm hoàn tất |
| `total_findings_parsed` | `int` | Có | Tổng phát hiện từ parser |
| `findings_triaged_ok` | `int` | Có | Phát hiện xử lý thành công |
| `findings_with_errors` | `int` | Có | Phát hiện có lỗi |
| `decision_cache_enabled` | `bool` | Có | Cache quyết định có được bật trong run hay không |
| `decision_cache_hits` / `decision_cache_misses` | `int` | Có | Tổng hit/miss của cache trong run |
| `provider_input_tokens` / `provider_output_tokens` | `int` | Có | Tổng token ước tính chỉ cho các lần thực sự gọi provider |
| `estimated_cost_usd` | `float \| None` | Không | Tổng chi phí provider ước tính của run |
| `cost_model_version` | `str \| None` | Không | Phiên bản công thức chi phí |
| `provider_latency_p50_ms` / `provider_latency_p95_ms` | `int \| None` | Không | Phân vị latency của các lần thực sự gọi provider |

**Ràng buộc:**

- Không chứa đường dẫn tuyệt đối repository. Đường dẫn tuyệt đối
  chỉ là cấu hình runtime.

### ScannerRunResult (Iteration 6)

Kết quả thực thi subprocess scanner.

| Trường | Kiểu | Bắt buộc | Mô tả |
|--------|------|----------|-------|
| `scanner` | `ScannerType` | Có | Scanner nào |
| `status` | `ScannerStatus` | Có | Kết quả thực thi |
| `version` | `str \| None` | Không | Phiên bản scanner |
| `config_id` | `str \| None` | Không | Định danh cấu hình |
| `artifact_path` | `str \| None` | Không | Đường dẫn artifact đã lưu |
| `duration_ms` | `int` | Có | Thời gian thực thi |
| `error_message` | `str \| None` | Không | Thông báo lỗi an toàn |
| `exit_code` | `int \| None` | Không | Exit code scanner |

**Enum ScannerStatus:**

| Giá trị | Mô tả |
|---------|-------|
| `SUCCESS` | Scanner chạy, không có finding |
| `FINDINGS_FOUND` | Scanner chạy, tìm thấy finding |
| `EXECUTION_ERROR` | Scanner thất bại |
| `TIMEOUT` | Scanner vượt timeout |
| `NOT_INSTALLED` | Không tìm thấy executable |

---

## Kiểu nội bộ tạm thời (Ephemeral Internal Types)

### ContextPackage (không phải public model)

`ContextPackage` là giá trị nội bộ tạm thời bên trong
`SafeContextService`. Nó KHÔNG phải Pydantic model public và KHÔNG
rời khỏi ranh giới component.

Nó tồn tại ngắn hạn trong local scope và biểu diễn ngữ cảnh đã chọn
chưa sanitize:

- `finding_id` — tham chiếu phát hiện.
- `selected_context` — nội dung mã đã chọn duy nhất (function,
  class, hoặc line window). Không có hai bản sao riêng biệt.
- `context_strategy` — chiến lược đã dùng.
- `enclosing_function` — tên hàm bao quanh.
- `enclosing_class` — tên class bao quanh.
- Metadata dòng.

**Ràng buộc:**

- Không phải public boundary model.
- Không được serialize.
- Không được log.
- Không được đưa vào exception.
- Không xuất hiện trong `repr` của model public.
- Bị hủy sau khi `ContextSanitizer` xử lý.
- Dùng một trường `selected_context` duy nhất, không có
  `source_snippet` và `function_body` riêng biệt.

---

## Sở hữu theo giai đoạn

| Giai đoạn | Component | Tạo ra | Tiêu thụ |
|-----------|-----------|--------|----------|
| Parse | `SemgrepParser` | `NormalizedFinding` | JSON semgrep |
| Parse | `GitleaksParser` | `NormalizedFinding` (đã redact) | JSON gitleaks |
| Ngữ cảnh | `SafeContextService` | `SanitizedContext` | `NormalizedFinding`, file repository |
| Đóng gói | `TriageInputBuilder` | `TriageInput` | `NormalizedFinding`, `SanitizedContext` |
| Triage | `TriageProvider` | `TriageDecision` | `TriageInput` |
| Policy | `PolicyEngine` | `PolicyDecision` | `NormalizedFinding`, `TriageDecision \| None`, `SanitizedContext` |
| Lắp ráp | `Pipeline` | `TriageResult` | Tất cả trên |
| Báo cáo | Reporter | File JSON/Markdown | `BatchResult` |

---

## Finding Instance ID

`NormalizedFinding.finding_instance_id` là hash xác định được tính từ:

```
hash_input = f"{scanner}:{rule_id}:{normalized_relative_file_path}:{start_line}:{end_line}"
finding_instance_id = sha256(hash_input.encode()).hexdigest()[:16]
```

**Bảo đảm:**

- Xác định (deterministic) cho cùng scanner location trong cùng lần
  chạy.
- Không phải persistent fingerprint — ID có thể thay đổi khi dòng
  code dịch chuyển do refactor hoặc chỉnh sửa.
- Không tuyên bố mọi phát hiện khác nhau luôn có ID khác nhau tuyệt
  đối (hash truncation có thể gây va chạm trong lý thuyết).
- Fingerprint bền vững (stable cross-run fingerprint) nằm ngoài phạm
  vi Sprint 1.
