# Xây dựng bài toán — Sprint 1 và Sprint 2

## 1. Bối cảnh bài toán

Trong quá trình phát triển phần mềm, các công cụ phân tích tĩnh như Semgrep
và Gitleaks có thể tạo ra rất nhiều cảnh báo. Không phải cảnh báo nào cũng là
lỗ hổng thật; một số cảnh báo là false positive, một số thiếu ngữ cảnh để kết
luận, và một số có mức độ rủi ro khác nhau tùy thuộc vào vị trí cũng như cách
mã được sử dụng.

Nếu reviewer phải kiểm tra thủ công toàn bộ cảnh báo, thời gian xử lý sẽ tăng
nhanh theo kích thước repository. Vì vậy, bài toán của dự án là xây dựng một
công cụ CLI hỗ trợ triage finding bảo mật bằng LLM, nhưng vẫn bảo đảm các
nguyên tắc an toàn:

- Không làm mất hoặc tự động xóa finding.
- Không gửi secret thô hoặc mã nguồn chưa làm sạch cho LLM.
- LLM chỉ đưa ra đề xuất; quyết định cuối cùng thuộc về policy của hệ thống.
- Khi thiếu ngữ cảnh hoặc xảy ra lỗi, finding được giữ lại và chuyển sang
  `MANUAL_REVIEW` hoặc `TRIAGE_ERROR`.
- Finding chỉ được phân tích bằng ngữ cảnh của đúng repository đã tạo ra nó.

Đối tượng đầu vào chính là một Python repository cục bộ. Đầu ra là các báo cáo
JSON, Markdown và HTML giúp reviewer biết finding nào có khả năng là lỗi thật,
finding nào cần xem xét thêm và lý do của quyết định.

## 2. Phát biểu bài toán

Cho một repository Python `R`, hai artifact scanner gồm báo cáo Semgrep và
Gitleaks, hệ thống cần thực hiện tuần tự các công việc sau:

1. Kiểm tra repository và ràng buộc giữa repository với scanner artifact.
2. Đọc, kiểm tra và chuẩn hóa các finding từ nhiều scanner về một schema chung.
3. Trích xuất ngữ cảnh liên quan từ chính repository đó.
4. Làm sạch credential, secret và dữ liệu có khả năng gây prompt injection.
5. Đóng gói dữ liệu an toàn thành đầu vào cho provider/LLM.
6. Nhận đề xuất triage và kiểm tra output theo schema.
7. Áp dụng policy bảo thủ dựa trên verdict, confidence, context, path và loại
   finding.
8. Lưu mọi finding cùng lỗi xử lý vào kết quả cuối.
9. Sinh báo cáo có thể audit nhưng không làm rò rỉ secret, prompt, response
   thô, traceback hoặc đường dẫn tuyệt đối.

Trong Sprint 2, hệ thống được mở rộng để phát hiện thêm các lỗi logic Python
mà scanner rule thông thường khó nhận diện, tập trung vào:

- Missing authorization/IDOR: người dùng có thể truy cập object của người
  khác do thiếu kiểm tra owner, user, tenant hoặc ACL.
- Business-rule bypass: client kiểm soát giá, số lượng, tổng tiền hoặc tham số
  phân trang/giới hạn mà không có kiểm tra hợp lệ phía server.

## 3. Mô hình xử lý tổng quát

```text
Python repository
        │
        ├── Semgrep ──┐
        └── Gitleaks ─┤
                      ▼
             Scanner artifacts
                      │
          Kiểm tra repository-artifact
                      │
                      ▼
             Parser + Redaction sớm
                      │
                      ▼
             NormalizedFinding
                      │
          Xử lý độc lập từng finding
                      │
                      ▼
             SafeContextService
          (đọc source, chọn context,
                 sanitize, redact)
                      │
                      ├── Evidence/logic analysis
                      │   (Sprint 2, nếu bật)
                      ▼
              SanitizedContext
                      │
                      ▼
                TriageInput
                      │
                      ▼
             Fake/Real LLM Provider
                      │
                      ▼
              TriageDecision
                      │
                      ▼
                PolicyEngine
                      │
                      ▼
               PolicyDecision
                      │
                      ▼
               TriageResult
                      │
                      ▼
              JSON/MD/HTML report
```

Pipeline trên là pipeline duy nhất. Hai chế độ CLI chỉ khác nhau ở cách tạo
artifact:

```text
triage:
  repository + artifact có sẵn ───────────────┐
                                              ▼
scan-and-triage: repository → scanner runner ─┘
                                              ▼
                                  Pipeline triage dùng chung
```

## 4. Các thành phần chính

| Thành phần | Vai trò |
|---|---|
| Scanner runner | Chạy Semgrep và Gitleaks, tạo artifact JSON. |
| Parser | Đọc artifact và chuyển finding về `NormalizedFinding`. |
| Redaction | Thay secret bằng `<REDACTED_SECRET>` ngay khi có thể. |
| SafeContextService | Đọc source an toàn, kiểm tra path, chọn và sanitize context. |
| Evidence/analysis backend | Bổ sung source/sink, dataflow, guard và call-site evidence; Sprint 2 dùng cho logic finding. |
| TriageInputBuilder | Chỉ đưa dữ liệu an toàn vào `TriageInput`. |
| TriageProvider | Fake hoặc real provider đề xuất verdict, confidence và evidence. |
| PolicyEngine | Chuyển đề xuất của LLM thành hành động hệ thống bảo thủ. |
| Reporter | Xuất báo cáo và kiểm tra rò rỉ trước khi ghi file. |

Các domain model chính được tách biệt: `NormalizedFinding`,
`SanitizedContext`, `TriageInput`, `TriageDecision`, `PolicyDecision` và
`TriageResult`. Các model này là Pydantic v2 frozen model; trạng thái nội bộ
của component không được serialize vào báo cáo.

## 5. Sprint 1 — Xây dựng pipeline triage nền tảng

### 5.1. Mục tiêu

Xây dựng một pipeline end-to-end có khả năng nhận artifact Semgrep/Gitleaks,
chuẩn hóa finding, tạo context an toàn, gọi provider, áp dụng policy và xuất
báo cáo. Sprint 1 ưu tiên tính đúng đắn, khả năng audit và an toàn dữ liệu hơn
là mở rộng phạm vi phát hiện.

### 5.2. Công việc thực hiện

**Nền tảng và domain model**

- Khai báo enum, model và lỗi dùng chung.
- Validate dữ liệu đầu vào và output bằng Pydantic v2.
- Đóng băng model đầu ra để tránh thay đổi sau khi tạo.
- Thiết kế `ProcessingError` an toàn, không chứa secret hoặc traceback.

**Thu nhận và chuẩn hóa finding**

- `SemgrepParser` ánh xạ rule, file, dòng, severity và metadata.
- `GitleaksParser` ánh xạ rule, file, dòng và category.
- Redact `Secret`/`Match` trước khi tạo public model.
- Cô lập lỗi theo từng finding; finding lỗi không làm dừng toàn bộ batch.

**Đọc và bảo vệ context**

- Resolve repository path và file path bằng kiểm tra containment thực sự.
- Chặn path traversal, absolute escape, symlink escape, file binary, file quá
  lớn và lỗi encoding.
- Với Semgrep, ưu tiên lấy function/class bao quanh bằng Python AST; nếu AST
  thất bại thì dùng line window.
- Với Gitleaks, dùng `REDACTED_LINE_WINDOW` và redact lại source vì file có thể
  vẫn còn secret.
- Sanitize context của cả Semgrep và Gitleaks; không coi Semgrep là an toàn
  mặc định.

**Triage bằng provider**

- Tạo `TriageInput` chỉ từ dữ liệu đã được chọn lọc.
- Fake provider phục vụ test offline và end-to-end.
- Real provider là adapter thay thế được, không làm thay đổi pipeline.
- Validate response của LLM; response sai schema trở thành lỗi xử lý.

**Policy và báo cáo**

- Áp dụng policy bảo thủ theo verdict và confidence.
- Context thiếu, protected secret category hoặc artifact không xác minh được
  phải được nâng lên review.
- Không tự động suppress hoặc xóa finding.
- Xuất JSON, Markdown và HTML; kiểm tra rò rỉ phòng thủ sâu trước khi ghi file.

### 5.3. Kết quả đầu ra Sprint 1

- CLI `triage` chạy với artifact có sẵn.
- CLI `scan-and-triage` chạy scanner rồi gọi pipeline triage chung.
- `NormalizedFinding` cho Semgrep và Gitleaks.
- Context đã sanitize và không chứa raw source ngoài boundary cho phép.
- Triage decision, policy decision và lỗi xử lý theo từng finding.
- Báo cáo JSON/Markdown/HTML có thể dùng cho reviewer và audit.
- Test model, parser, redaction, path security, context và end-to-end.

### 5.4. Tiêu chí hoàn thành Sprint 1

Sprint 1 được xem là đạt khi một repository Python có thể đi từ artifact hoặc
scanner đến báo cáo cuối mà không làm rò rỉ secret; một finding lỗi không làm
mất các finding khác; provider không hợp lệ được xử lý an toàn; và cả hai chế
độ CLI dùng cùng một pipeline triage.

## 6. Sprint 2 — Phát hiện IDOR và business-rule bypass

### 6.1. Mục tiêu

Sprint 2 bổ sung khả năng phát hiện lỗi logic ứng dụng Python. Đây là các lỗi
thường phụ thuộc vào quan hệ giữa input, object lookup, guard authorization và
thao tác cuối cùng, nên khó kết luận chỉ bằng một pattern cục bộ.

Detector được bật tường minh:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\<TEN_REPO> `
  --output-dir ..\triage-runs\sprint2 `
  --module2 `
  --logic-detector python-idor-business-logic `
  --provider fake
```

Detector Sprint 2 không tạo pipeline riêng. Finding mới vẫn đi theo chuỗi:

```text
Logic detector
   → NormalizedFinding
   → SafeContextService
   → Evidence/analysis
   → TriageInput
   → Provider
   → PolicyEngine
   → Reporter
```

### 6.2. Lớp phát hiện thứ nhất: missing authorization/IDOR

Detector theo dõi identifier bắt nguồn từ route, query hoặc body đến thao tác
lookup object. Candidate IDOR được tạo khi identifier của request được dùng để
truy cập object mà không thấy guard phù hợp.

Các guard hợp lệ cần được nhận diện gồm:

- lọc theo `owner` hoặc `user`;
- lọc theo `tenant`;
- kiểm tra share/ACL;
- authorization guard bảo vệ đúng object trước khi đọc hoặc mutate.

Candidate được loại trong trường hợp query đã scope theo owner/user/tenant,
có share ACL hợp lệ hoặc có guard authorization gắn đúng với object đang truy
cập. Nếu detector không đủ bằng chứng, finding không bị loại mà chuyển sang
review thông qua pipeline chung.

### 6.3. Lớp phát hiện thứ hai: business-rule bypass

Detector tập trung vào ba nhóm use case:

**Tính tiền giỏ hàng**

- Theo dõi `price`, `unit_price`, `discount`, `subtotal`, `total`, `quantity`
  và alias lấy từ request.
- Tạo candidate khi giá hoặc tổng do client kiểm soát đi tới kết quả hoặc
  mutation.
- Tạo candidate khi quantity/domain value đi tới operation mà không có bound
  phía server.
- Trường hợp an toàn: giá được load từ nguồn server, quantity dương và có
  upper bound.

**Pagination và limit**

- Tạo candidate khi `page`/`limit` từ request đi vào query mà không có lower
  bound hoặc upper bound.
- Tạo candidate khi collection query dùng `all()`/`fetchall()` mà không có
  `limit`, `slice` hoặc `paginate`.
- Vấn đề có thể liên quan đến CWE-400, nhưng taxonomy public của detector vẫn
  giữ trong lớp `business_rule_bypass`.

**Các giá trị domain do client kiểm soát**

- Theo dõi input từ request tới kết quả nghiệp vụ hoặc thao tác ghi dữ liệu.
- Phân biệt dữ liệu do client gửi với dữ liệu được tính/đọc lại từ server.
- Ghi nhận risk factor, evidence và remediation để reviewer xác minh.

### 6.4. Kết quả đầu ra Sprint 2

- Hai logic class công khai: `missing_authz_idor` (`CWE-639`) và
  `business_rule_bypass` (`CWE-840`).
- Candidate có vị trí, trace/evidence, risk factors và remediation an toàn.
- Guard object/tenant/share hợp lệ chặn candidate IDOR.
- Regression test cho client-controlled price, quantity thiếu bound,
  pagination thiếu cap và collection query không giới hạn.
- Negative test cho server-side price, quantity bounded và pagination bounded.
- Logic finding xuất hiện cùng Semgrep/Gitleaks trong cùng báo cáo.

### 6.5. Giới hạn của Sprint 2

Detector là bounded candidate engine, không phải formal proof về khả năng khai
thác. Detector có thể bỏ sót framework hoặc coding pattern động chưa được hỗ
trợ. Vì vậy, kết quả cần được xác nhận bởi AppSec/service owner trên service
thật; remediation chỉ là đề xuất và không tự động sửa code.

## 7. Nguyên tắc đánh giá và an toàn

Việc đánh giá cần dùng fixture và benchmark có ground truth, chia rõ dữ liệu
phát triển, calibration và held-out khi đánh giá provider thật. Không dùng
fixture tổng hợp để tuyên bố precision, recall hoặc F1 cho hệ thống thực tế.

Các kiểm thử bắt buộc gồm:

- canary secret không xuất hiện trong model, prompt, log hoặc report;
- traversal và symlink escape bị chặn;
- repository-artifact mismatch không được xử lý như dữ liệu hợp lệ;
- lỗi provider không làm mất finding;
- output LLM sai schema không được thực thi;
- prompt injection nằm trong source không được coi là instruction đáng tin;
- báo cáo không chứa raw prompt, raw response, traceback hoặc absolute path.

## 8. Kết luận

Sprint 1 xây dựng nền móng triage an toàn và có thể audit: từ scanner finding
đến quyết định policy và báo cáo. Sprint 2 tận dụng nền móng đó để bổ sung
phân tích logic cho IDOR và business-rule bypass. Điểm quan trọng của thiết kế
là detector mới chỉ bổ sung evidence/finding vào pipeline hiện có; mọi finding,
kể cả finding do logic detector tạo ra, đều chịu cùng một cơ chế context,
provider, policy, bảo mật và báo cáo.
