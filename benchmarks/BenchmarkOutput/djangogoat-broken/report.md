# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Có lỗi cần xử lý; không được bỏ qua các finding liên quan\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 4 |
| Triage thành công | 4 |
| Finding có lỗi | 0 |
| Lỗi scanner | 1 |
| Thời gian toàn run (giây) | 0\.023536 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 4 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | b580a2cb\-abcc\-4e7d\-bfdd\-57923d4b8cc2 |
| Repository | DjangoGoat\-broken |
| Repository identifier | red\-and\-black\/DjangoGoat@broken |
| Commit | null |
| Trạng thái working tree | null |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v4 |
| Policy version | conservative\-policy\-v1 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-07T03\:29\:03\.971084\+00\:00 |
| Kết thúc | 2026\-08\-07T03\:29\:03\.994620\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS
- Thành công: SEMGREP; GITLEAKS
- Phiên bản: Không có
- Cấu hình: Không có
- Hash artifact: gitleaks=c1c5bc7ef861e90836581652308671b0218776ff6bd4aca4970e3bce58a2a6d8; semgrep=887a4921c9005af2ed8e460f08977561ec80e1a25904d8214f73ef527cd67354

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | a59484cd86b5a3f1 | generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key | dg\-server\.key\:1–2 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | e6ce663816670c94 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | authentication\/views\.py\:46–55 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | MEDIUM | 10bd4ae8d3815e93 | python\.django\.security\.audit\.xss\.template\-autoescape\-off\.template\-autoescape\-off | notes\/templates\/conversation\.html\:46 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | MEDIUM | 453c2cf5b6eb7976 | python\.django\.security\.audit\.raw\-query\.avoid\-raw\-sql | authentication\/views\.py\:57 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a59484cd86b5a3f1 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key |
| File | dg\-server\.key |
| Dòng | 1–2 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-798\: Use of Hard\-coded Credentials'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A07\_2021\-Identification\_and\_Authentication\_Failures'\]; technology=\['secrets'\] |
| Thời gian xử lý | 3 ms |

**Thông báo của scanner**

> Private Key detected\. This is a sensitive credential and should not be hardcoded here\. Instead, store this in a separate, private file\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-12, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Provider giả lập sử dụng quyết định mặc định và chuyển finding sang review thủ công\.

**Bằng chứng LLM sử dụng**

- Không có kịch bản prompt\_type chuyên biệt nên provider dùng nhánh mặc định\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - Bằng chứng ngữ cảnh vẫn chưa đầy đủ sau khi mở rộng trong giới hạn an toàn\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.2. MANUAL\_REVIEW — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e6ce663816670c94 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | authentication\/views\.py |
| Dòng | 46–55 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-915\: Improperly Controlled Modification of Dynamically\-Determined Object Attributes'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 7 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 40\-66, hàm log\_in\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Provider giả lập sử dụng quyết định mặc định và chuyển finding sang review thủ công\.

**Bằng chứng LLM sử dụng**

- Không có kịch bản prompt\_type chuyên biệt nên provider dùng nhánh mặc định\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM yêu cầu chuyên gia review thủ công\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.3. MANUAL\_REVIEW — python\.django\.security\.audit\.xss\.template\-autoescape\-off\.template\-autoescape\-off

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 10bd4ae8d3815e93 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.xss\.template\-autoescape\-off\.template\-autoescape\-off |
| File | notes\/templates\/conversation\.html |
| Dòng | 46 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.1\/ref\/templates\/builtins\/\#autoescape'\]; technology=\['django'\] |
| Thời gian xử lý | 3 ms |

**Thông báo của scanner**

> Detected a template block where autoescaping is explicitly disabled with '\{% autoescape off %\}'\. This allows rendering of raw HTML in this segment\. Turn autoescaping on to prevent cross\-site scripting \(XSS\)\. If you must do this, consider instead, using \`mark\_safe\` in Python code\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 36\-56, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Provider giả lập sử dụng quyết định mặc định và chuyển finding sang review thủ công\.

**Bằng chứng LLM sử dụng**

- Không có kịch bản prompt\_type chuyên biệt nên provider dùng nhánh mặc định\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - Bằng chứng ngữ cảnh vẫn chưa đầy đủ sau khi mở rộng trong giới hạn an toàn\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.4. MANUAL\_REVIEW — python\.django\.security\.audit\.raw\-query\.avoid\-raw\-sql

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 453c2cf5b6eb7976 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.raw\-query\.avoid\-raw\-sql |
| File | authentication\/views\.py |
| Dòng | 57 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/models\/expressions\/\#raw\-sql\-expressions', 'https\:\/\/semgrep\.dev\/blog\/2020\/preventing\-sql\-injection\-a\-django\-authors\-perspective\/'\]; technology=\['django'\] |
| Thời gian xử lý | 8 ms |

**Thông báo của scanner**

> Detected the use of 'RawSQL' or 'raw' indicating the execution of a non\-parameterized SQL query\. This could lead to a SQL injection and therefore protected information could be leaked\. Instead, use Django ORM and parameterized queries before raw SQL\. An example of using the Django ORM is\: \`People\.objects\.get\(name\='Bob'\)\`

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 40\-66, hàm log\_in\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Provider giả lập sử dụng quyết định mặc định và chuyển finding sang review thủ công\.

**Bằng chứng LLM sử dụng**

- Không có kịch bản prompt\_type chuyên biệt nên provider dùng nhánh mặc định\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM yêu cầu chuyên gia review thủ công\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

## 6. Lỗi scanner
- Giai đoạn: PARSE — Đọc và chuẩn hóa artifact; mã lỗi: PARSE\_RECORD\_INVALID\_FIELD; scanner: GITLEAKS; finding: null; có thể thử lại: False; thông báo an toàn: Gitleaks record\[0\] produced an invalid NormalizedFinding\.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
