# Phạm vi Sprint 1

## Mục tiêu sản phẩm

Công cụ CLI phân loại các phát hiện phân tích tĩnh và phát hiện bí mật
cho Python repository. Người dùng cung cấp một Python repository. Hệ
thống quét nó bằng Semgrep và Gitleaks, chuẩn hóa các phát hiện, trích
xuất ngữ cảnh mã nguồn Python, làm sạch dữ liệu nhạy cảm, dùng LLM
để đề xuất phân loại, áp dụng chính sách bảo thủ, và xuất báo cáo
JSON cùng Markdown.

## Đầu vào sản phẩm và đầu vào pipeline

**Đầu vào sản phẩm** là thứ người dùng cung cấp:

- Một Python repository cục bộ.

**Đầu vào pipeline** là thứ pipeline triage nhận bên trong:

- Repository (để trích xuất ngữ cảnh).
- Báo cáo Semgrep JSON được tạo từ repository đó.
- Báo cáo Gitleaks JSON được tạo từ repository đó.

Hai chế độ CLI nối đầu vào sản phẩm với đầu vào pipeline.

## Hai chế độ CLI

### Chế độ A: `triage`

Nhận artifact scanner có sẵn. Được triển khai trước để kiểm thử
pipeline mà không phụ thuộc scanner.

```
python -m sast_triage triage \
  --repo-path ./target-repository \
  --semgrep-report ./scanner-output/semgrep.json \
  --gitleaks-report ./scanner-output/gitleaks.json \
  --output-dir ./artifacts/run-001 \
  --provider fake
```

### Chế độ B: `scan-and-triage`

Chỉ nhận repository. Chạy scanner, lưu artifact, rồi gọi cùng
pipeline triage.

```
python -m sast_triage scan-and-triage \
  --repo-path ./target-repository \
  --output-dir ./artifacts/run-001 \
  --provider fake
```

Cả hai chế độ dùng chung một pipeline triage duy nhất.

## Trong phạm vi

- Nền tảng viết bằng Python.
- Repository mục tiêu: chỉ Python.
- Một repository cho mỗi lần chạy.
- Semgrep JSON findings.
- Gitleaks JSON findings (chỉ trạng thái hiện tại, không lịch sử git).
- Scanner runner cho Semgrep và Gitleaks.
- Schema `NormalizedFinding`.
- `SafeContextService` với raw source chỉ trong local scope.
- Trích xuất function/class bằng Python `ast`.
- Fallback line-window khi AST thất bại.
- `REDACTED_LINE_WINDOW` mặc định cho Gitleaks.
- Redact sớm cho bí mật Gitleaks.
- Sanitize ngữ cảnh cho cả Semgrep và Gitleaks.
- `TriageInput` model cho provider.
- Fake LLM provider.
- Một real LLM provider adapter.
- Policy engine bảo thủ (xét confidence, path category, context
  availability, protected secret category).
- Báo cáo JSON và Markdown.
- Run metadata (không đường dẫn tuyệt đối).
- Lỗi xử lý theo từng phát hiện.
- Xác minh ràng buộc repository-artifact.
- Benchmark đánh giá nhỏ (Iteration 7).

## Ngoài phạm vi

- Ngôn ngữ ngoài Python.
- Đầu ra SARIF.
- Trích xuất ngữ cảnh từ commit lịch sử git.
- Đồ thị gọi hàm liên file hoặc phân tích luồng dữ liệu.
- Đồ thị thuộc tính mã (CPG).
- Phát hiện lỗi logic.
- Đề xuất khắc phục hoặc diff mã.
- Lưu trữ cơ sở dữ liệu.
- API server hoặc giao diện web.
- Dashboard.
- Tích hợp CI/CD.
- Điều phối multi-agent.
- Tự động loại bỏ phát hiện.
- Tạo rule Semgrep tùy chỉnh.
- Quét nhiều repository trong một lần chạy.
- Xử lý song song hoặc bất đồng bộ.
- Stable cross-run fingerprint cho finding.

## Các iteration

### Iteration 1: Nền tảng

**Sản phẩm:**

- `pyproject.toml` (metadata dự án, Pydantic v2, pytest).
- `src/sast_triage/__init__.py`
- `src/sast_triage/models.py` — tất cả class domain model và enum.
- `src/sast_triage/errors.py` — các kiểu lỗi.
- `tests/test_models.py` — test validation và ràng buộc model.

**Số file tối đa:** 5 file. Không tạo thêm file nguồn.

**Tiêu chí chấp nhận:**

- [ ] Tất cả domain enum: `ScannerType`, `FindingType`, `Severity`,
  `ContextStrategy` (5 giá trị bao gồm `REDACTED_LINE_WINDOW`),
  `SourceKind`, `PathCategory`, `MissingContextReason`,
  `ModelVerdict`, `ModelConfidence`, `PolicyAction`,
  `ProcessingStage`, `ArtifactRepositoryMatch`, `ScannerStatus`.
- [ ] `NormalizedFinding` validate với dữ liệu đúng; từ chối thiếu
  trường bắt buộc; frozen; dùng `finding_instance_id` (không phải
  `id`).
- [ ] `SanitizedContext` có đầy đủ 17 trường; validate
  `context_strategy`, `path_category`, `source_kind`;
  `missing_context_reasons` là danh sách `MissingContextReason`.
- [ ] `TriageInput` chứa `context: SanitizedContext`, `prompt_type`,
  `prompt_version`, `output_schema_version`; frozen.
- [ ] `TriageDecision` validate enum; `evidence`,
  `missing_information`, `assumptions` là `list[str]`.
- [ ] `PolicyDecision` validate `action` theo `PolicyAction`;
  `reasons` là `list[str]`.
- [ ] `TriageResult` kết hợp `finding`, `sanitized_context` (bắt
  buộc), optional `triage_decision`, `policy_decision`, và lỗi mà
  không thay đổi sub-model.
- [ ] `ProcessingError` có `safe_message`, `error_code`, `retryable`.
- [ ] `RunMetadata` không chứa đường dẫn tuyệt đối.
- [ ] `BatchResult` kết hợp `RunMetadata`, `list[TriageResult]`,
  `list[ProcessingError]`.
- [ ] `pytest` chạy thành công, 0 lỗi.

---

### Iteration 2: Parser

**Sản phẩm:**

- Công cụ redaction (`<REDACTED_SECRET>` placeholder).
- `SemgrepParser` với test.
- `GitleaksParser` với redact sớm và test.
- Test bảo mật cho parser (canary secret).

**Tiêu chí chấp nhận:**

- [ ] `SemgrepParser` parse Semgrep JSON hợp lệ thành
  `List[NormalizedFinding]` với `finding_type=SAST`.
- [ ] Malformed JSON raise `ParserError`, không crash.
- [ ] Thiếu trường: bỏ qua phát hiện, ghi `ProcessingError`.
- [ ] `GitleaksParser` parse thành `List[NormalizedFinding]` với
  `finding_type=SECRET`.
- [ ] `Secret` và `Match` thô redact thành `<REDACTED_SECRET>` trước
  khi tạo `NormalizedFinding`.
- [ ] Gitleaks severity mặc định `UNKNOWN`.
- [ ] `secret_category` an toàn lưu trong `metadata` nếu suy ra được.
- [ ] Canary test: bí mật giả không xuất hiện trong `NormalizedFinding`
  đã serialize.
- [ ] Mảng rỗng → danh sách rỗng, không lỗi.
- [ ] File không tồn tại → lỗi phù hợp.

---

### Iteration 3: Trích xuất ngữ cảnh

**Sản phẩm:**

- `SafeContextService` (API public duy nhất cho context).
- Bên trong: `SafeRepositoryReader`, `PythonExtractor`,
  `ContextSanitizer`.

**Tiêu chí chấp nhận:**

- [ ] `SafeContextService` nhận `NormalizedFinding` + repo config →
  trả `SanitizedContext`.
- [ ] Raw source chỉ trong local scope; không serialize, log, hoặc
  đưa vào exception.
- [ ] SafeRepositoryReader: reject traversal, absolute escape,
  symlink escape, oversized file, binary file, encoding error.
- [ ] Semgrep: AST tìm enclosing function → `PYTHON_FUNCTION`;
  enclosing class → `PYTHON_CLASS`; fallback → `LINE_WINDOW`.
- [ ] Gitleaks: mặc định `REDACTED_LINE_WINDOW`; AST chỉ cho
  structural metadata (tên hàm/class).
- [ ] File không đọc được → `context_strategy=UNAVAILABLE`,
  `context_available=False`, phát hiện không bị loại bỏ.
- [ ] `SanitizedContext` chỉ có một trường `sanitized_snippet` (không
  có `source_snippet` và `function_body` riêng).
- [ ] Sanitizer redact mẫu credential cho Semgrep context.
- [ ] Sanitizer re-redact bí mật cho Gitleaks context.
- [ ] `path_category` được xác định từ đường dẫn file.
- [ ] `missing_context_reasons` ghi lý do khi context thiếu.
- [ ] Kiểm tra rò rỉ phòng thủ sâu trước khi trả `SanitizedContext`.
- [ ] Canary test: bí mật giả không trong `SanitizedContext`.
- [ ] Test path traversal, symlink escape.

---

### Iteration 4: Triage và Policy

**Sản phẩm:**

- `TriageInputBuilder`.
- Fake `TriageProvider`.
- `PolicyEngine` với quy tắc bảo thủ mới.
- Pipeline orchestrator dùng artifact có sẵn.

**Tiêu chí chấp nhận:**

- [ ] `TriageInputBuilder` tạo `TriageInput` từ `NormalizedFinding`
  + `SanitizedContext` + prompt config.
- [ ] `TriageInput` cho Gitleaks không chứa author email, commit
  message, raw match.
- [ ] Fake provider trả `TriageDecision` xác định với cả ba
  `ModelVerdict` và các mức `ModelConfidence`.
- [ ] `PolicyEngine` áp dụng bảng policy mới:
  - `LIKELY_TP` + `HIGH` → `LIKELY_TP`.
  - `LIKELY_TP` + `MEDIUM`/`LOW` → `MANUAL_REVIEW`.
  - `LIKELY_FP` + `HIGH` + test/fixture path + không protected
    category → `FP_CANDIDATE`.
  - `LIKELY_FP` + `HIGH` + production path → `MANUAL_REVIEW`.
  - `LIKELY_FP` + `MEDIUM`/`LOW` → `MANUAL_REVIEW`.
  - `NEEDS_REVIEW` → `MANUAL_REVIEW`.
  - null → `TRIAGE_ERROR`.
- [ ] Policy xét: `context_available`, `truncated`, `path_category`,
  `artifact_repository_match`, protected secret category.
- [ ] `context_available=false` → `MANUAL_REVIEW`.
- [ ] Protected category (private key, cloud credential, signing key,
  database credential) → luôn bảo thủ.
- [ ] Một phát hiện lỗi không dừng các phát hiện khác.
- [ ] Một scanner lỗi không loại bỏ kết quả scanner còn lại.
- [ ] Ràng buộc repository-artifact được xác minh.

---

### Iteration 5: Báo cáo và CLI

**Tiêu chí chấp nhận:**

- [ ] Báo cáo JSON hợp lệ, chứa `RunMetadata`, `TriageResult`,
  `ProcessingError`.
- [ ] Báo cáo Markdown có bảng tóm tắt và chi tiết từng phát hiện.
- [ ] Báo cáo không chứa bí mật thô, prompt thô, response LLM thô,
  traceback, đường dẫn tuyệt đối.
- [ ] Reporter kiểm tra rò rỉ phòng thủ sâu trước khi ghi.
- [ ] CLI `triage` chấp nhận đúng tham số.
- [ ] Exit code: 0 = thành công, 1 = lỗi một phần, 2 = lỗi nghiêm
  trọng.
- [ ] End-to-end test: artifact mẫu → fake provider → báo cáo đúng.

---

### Iteration 6: Scanner Runner

**Tiêu chí chấp nhận:**

- [ ] Runner kiểm tra executable, ghi version, có timeout.
- [ ] Dùng `subprocess` không `shell=True`.
- [ ] Không ghép đầu vào thành chuỗi shell.
- [ ] Phân biệt exit code finding với lỗi thực thi.
- [ ] Không log stdout/stderr nếu có thể chứa bí mật.
- [ ] Cấu hình scanner rõ ràng, config ID trong `RunMetadata`.
- [ ] `scan-and-triage` chạy scanner rồi gọi cùng pipeline.

---

### Iteration 7: Real LLM và đánh giá

**Tiêu chí chấp nhận:**

- [ ] Real provider gửi prompt có cấu trúc, validate response.
- [ ] Invalid response → `triage_decision=null`, `TRIAGE_ERROR`.
- [ ] Timeout xử lý graceful.
- [ ] Prompt không chứa ngữ cảnh chưa sanitize.
- [ ] Đánh giá dùng labeled findings (TP, FP, DISPUTED,
  INSUFFICIENT_CONTEXT).
- [ ] Nếu ground truth không đủ → ghi rõ là pipeline verification.
- [ ] Không dùng classification distribution làm metric chính.

## Test fixture và benchmark đánh giá

**Test fixture tự động:**

- Dùng ví dụ tổng hợp để test parser, sanitizer, pipeline, policy,
  reporting.
- Không tuyên bố precision, recall, hay F1.

**Benchmark đánh giá (Iteration 7):**

- Cần labeled findings với ground truth.
- Nhãn: TP, FP, DISPUTED, INSUFFICIENT_CONTEXT.
- Nếu chất lượng reviewer hoặc kích thước dataset không đủ → nêu rõ.

## Hoãn ra ngoài Sprint 1

- Hỗ trợ đa ngôn ngữ.
- SARIF.
- Trích xuất ngữ cảnh từ lịch sử git.
- Phân tích liên file, call graph, data flow.
- CPG.
- Phát hiện lỗi logic.
- Đề xuất khắc phục.
- Lưu trữ database.
- REST API hoặc web server.
- Dashboard.
- Tích hợp CI/CD.
- Multi-agent.
- Tự động loại bỏ phát hiện.
- Tạo rule Semgrep tùy chỉnh.
- Quét nhiều repository.
- Xử lý bất đồng bộ/song song.
- Stable cross-run fingerprint.
