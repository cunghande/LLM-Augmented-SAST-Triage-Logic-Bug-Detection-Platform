# AGENTS.md — CLI SAST Triage Platform

## Tổng quan dự án

Công cụ CLI phân loại (triage) các phát hiện từ Semgrep (phân tích mã
tĩnh) và Gitleaks (phát hiện bí mật) bằng phân tích hỗ trợ LLM.

Đầu vào là một Python repository. Hệ thống quét repository, chuẩn hóa
các phát hiện, trích xuất ngữ cảnh mã nguồn, làm sạch dữ liệu nhạy
cảm, gọi LLM để đề xuất phân loại, áp dụng chính sách bảo thủ, và
xuất báo cáo JSON cùng Markdown.

## Quy tắc kiến trúc

1. **Một pipeline triage duy nhất.** Cả hai chế độ CLI (`triage` và
   `scan-and-triage`) dùng chung một pipeline. Không bao giờ sao chép
   logic triage.

2. **Tách biệt domain model.** Sáu public model rời khỏi ranh giới
   component. Không được gộp chúng lại:
   - `NormalizedFinding` — dữ kiện scanner an toàn.
   - `SanitizedContext` — ngữ cảnh duy nhất LLM provider được nhận.
   - `TriageInput` — gói đầu vào cho provider.
   - `TriageDecision` — kết quả từ LLM.
   - `PolicyDecision` — quyết định của hệ thống.
   - `TriageResult` — kết quả tổng hợp cuối cùng, bất biến.

3. **Raw source không vượt component boundary.** Mã nguồn thô từ
   repository chỉ tồn tại trong local scope của `SafeContextService`.
   Không có public Pydantic model nào chứa raw source text. Kiểu nội
   bộ tạm thời (ContextPackage) không phải public model.

4. **Xử lý tuần tự.** Không dùng async, không song song trong
   Sprint 1.

5. **Không tự động loại bỏ.** Mọi phát hiện phải xuất hiện trong
   báo cáo bất kể kết quả phân loại.

6. **Model đầu ra bất biến.** Dùng Pydantic v2 frozen model cho tất
   cả kiểu domain rời khỏi ranh giới component. Trạng thái nội bộ
   có thể thay đổi không bao giờ được serialize vào báo cáo hoặc
   metadata.

7. **Ràng buộc repository-artifact.** Các phát hiện từ repository A
   không bao giờ được triage bằng ngữ cảnh từ repository B. Pipeline
   phải xác minh ràng buộc trước khi xử lý.

## Quy tắc bảo mật

### Bí mật (Secrets)

- Giá trị bí mật thô từ Gitleaks chỉ tồn tại trong phạm vi cục bộ
  hẹp của `GitleaksParser`. Chúng không được đưa vào bất kỳ public
  model, log, exception message, prompt, hay báo cáo nào.
- Placeholder cho bí mật đã redact: `<REDACTED_SECRET>`.
- Không hash bí mật thô trong Sprint 1.
- Ngữ cảnh mã nguồn trích xuất cho phát hiện Gitleaks phải được
  redact lại vì file nguồn có thể vẫn chứa bí mật.

### Ngữ cảnh (Context)

- Tất cả ngữ cảnh mã nguồn (Semgrep và Gitleaks) phải đi qua
  `SafeContextService` trước khi đến `TriageProvider`.
- Raw source chỉ trong local scope của `SafeContextService`. Không
  serialize, log, đưa vào exception, hay `repr` public model.
- Không bao giờ coi quá trình sanitize cho Semgrep là không cần thiết.
  Mã nguồn gần phát hiện có thể chứa thông tin xác thực.
- Mã nguồn là dữ liệu không đáng tin cậy. Nó có thể chứa payload
  prompt injection.
- `TriageProvider` chỉ nhận `TriageInput`, không nhận raw source hay
  `NormalizedFinding` trực tiếp.

### Đường dẫn (Paths)

- Resolve cả đường dẫn gốc repository và đường dẫn file ứng viên.
- Xác minh đường dẫn ứng viên nằm bên trong gốc repository bằng kiểm
  tra path containment thực sự, không dùng so sánh chuỗi đơn giản.
- Chặn traversal `../`, thoát đường dẫn tuyệt đối, và symlink escape.
- Lỗi trích xuất ngữ cảnh không được xóa phát hiện. Chuyển nó đến
  `MANUAL_REVIEW` hoặc `TRIAGE_ERROR` qua policy.

### Báo cáo (Reports)

- Không chứa bí mật thô.
- Không chứa prompt thô gửi cho LLM.
- Không chứa response thô từ LLM.
- Không chứa traceback.
- Không chứa đường dẫn tuyệt đối của repository trong báo cáo mặc định.
- Reporter phải thực hiện kiểm tra rò rỉ phòng thủ sâu trước khi ghi file.

### LLM

- Validate tất cả output của LLM theo schema.
- Không bao giờ thực thi output của LLM.
- Khi provider lỗi: `triage_decision = null`,
  `PolicyAction = TRIAGE_ERROR`, tạo `ProcessingError` an toàn.

## Ngôn ngữ và phụ thuộc

- Python >= 3.11, < 3.14.
- Không dùng câu lệnh `match` hoặc cú pháp Python mới trừ khi nó
  làm code rõ ràng hơn đáng kể.
- Pydantic v2 cho domain model contracts.
- Module `logging` của thư viện chuẩn. Không thêm `structlog` mà
  không có lý do cụ thể và phân tích đánh đổi.
- Framework CLI được hoãn đến Iteration 5. Mặc định dùng `argparse`
  trừ khi độ phức tạp đòi hỏi khác.
- Không thêm phụ thuộc mà không giải thích tại sao thư viện chuẩn
  không đủ.

## Quy ước viết code

- Type hint trên tất cả hàm public và trường model.
- Docstring trên tất cả class và hàm public.
- Không dùng tham số mặc định có thể thay đổi (mutable default).
- Không dùng `except` trần. Bắt exception cụ thể.
- Giữ nguyên comment và docstring hiện có không liên quan đến thay đổi.

## Quy tắc testing

- Mọi domain model phải có test kiểm tra validation.
- Pipeline Gitleaks phải có canary secret test: chèn một bí mật giả
  đã biết và xác minh nó không xuất hiện trong model đã serialize,
  log, prompt, hay báo cáo.
- Test fixture dùng để kiểm tra tính đúng đắn. Chúng không phải
  benchmark chất lượng model.
- Không báo cáo precision, recall, hay F1 từ fixture tổng hợp.

## Kỷ luật iteration

- Tuân thủ thứ tự iteration trong `docs/sprint-1-scope.md`.
- Không triển khai scanner runner trước khi pipeline dựa trên artifact
  chạy end-to-end.
- Không tích hợp real LLM provider trước khi pipeline với fake
  provider chạy end-to-end.
- Iteration 1 tạo tối đa:
  - `pyproject.toml`
  - `src/sast_triage/__init__.py`
  - `src/sast_triage/models.py`
  - `src/sast_triage/errors.py`
  - `tests/test_models.py`

## Tham khảo

- [Phạm vi Sprint 1](docs/sprint-1-scope.md)
- [Kiến trúc](docs/architecture.md)
- [Domain Models](docs/domain-models.md)
- [Chính sách bảo mật](docs/security-policy.md)
