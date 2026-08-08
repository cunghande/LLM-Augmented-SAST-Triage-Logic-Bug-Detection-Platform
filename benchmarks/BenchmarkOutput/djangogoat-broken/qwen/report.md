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
| Thời gian toàn run (giây) | 92\.30567 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 2 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 2 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 8f82ee68\-6d0e\-49f8\-b9de\-3d804bf67487 |
| Repository | DjangoGoat\-broken |
| Repository identifier | red\-and\-black\/DjangoGoat@broken |
| Commit | b5123eba8c002adb4f5513197e7e69a724385d29 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | modal\-qwen\-structured |
| Model | Qwen\/Qwen3\-14B\-AWQ |
| Prompt version | triage\-prompt\-v4 |
| Policy version | conservative\-policy\-v1 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | benchmark\-modal\-qwen\-djangogoat |
| Bắt đầu | 2026\-08\-07T03\:34\:44\.268512\+00\:00 |
| Kết thúc | 2026\-08\-07T03\:36\:16\.574182\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS
- Thành công: SEMGREP; GITLEAKS
- Phiên bản: Không có
- Cấu hình: Không có
- Hash artifact: Không có

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | a59484cd86b5a3f1 | generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key | dg\-server\.key\:1–2 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 2 | MANUAL\_REVIEW | MEDIUM | 10bd4ae8d3815e93 | python\.django\.security\.audit\.xss\.template\-autoescape\-off\.template\-autoescape\-off | notes\/templates\/conversation\.html\:46 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | LIKELY\_TP | HIGH | e6ce663816670c94 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | authentication\/views\.py\:46–55 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 4 | LIKELY\_TP | MEDIUM | 453c2cf5b6eb7976 | python\.django\.security\.audit\.raw\-query\.avoid\-raw\-sql | authentication\/views\.py\:57 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |

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
| Thời gian xử lý | 13560 ms |

**Thông báo của scanner**

> Private Key detected\. This is a sensitive credential and should not be hardcoded here\. Instead, store this in a separate, private file\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-12, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule đang kiểm tra việc phát hiện khóa riêng tư được mã hóa cứng trong mã nguồn\. Context cho thấy một khóa riêng tư dạng PEM được lưu trữ trực tiếp trong tệp dg\-server\.key, không được bảo vệ hoặc ẩn\. Không có guard\/sanitizer nào được áp dụng để bảo vệ thông tin nhạy cảm này\. Việc lưu trữ khóa riêng tư trong mã nguồn là một lỗ hổng bảo mật rõ ràng theo CWE\-798 và OWASP A07\. Khóa này có thể bị lộ nếu mã nguồn bị rò rỉ\.

**Bằng chứng LLM sử dụng**

- Nguồn\: Khóa riêng tư dạng PEM được lưu trữ trực tiếp trong tệp dg\-server\.key \(line\_range\=1\-2\)\.
- Loại bằng chứng\: Điểm sử dụng nguy hiểm \- Khóa riêng tư được lưu trữ trong mã nguồn, không được bảo vệ\.
- Loại bằng chứng\: Guard\/Sanitizer \- Không có cơ chế nào được áp dụng để bảo vệ khóa riêng tư\.
- Loại bằng chứng\: Kết luận \- Khóa riêng tư được phát hiện trong mã nguồn, không được lưu trữ an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả định\: Tệp dg\-server\.key là một tệp mã nguồn và không được bảo vệ bằng bất kỳ cơ chế nào như môi trường biến hoặc tệp cấu hình riêng tư\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Có
- **Lý do escalation:** LLM đã đưa ra verdict khi bằng chứng từ nguồn đến điểm sử dụng nguy hiểm chưa đầy đủ\.
- **Lý do policy:**
  - Bằng chứng ngữ cảnh vẫn chưa đầy đủ sau khi mở rộng trong giới hạn an toàn\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.2. MANUAL\_REVIEW — python\.django\.security\.audit\.xss\.template\-autoescape\-off\.template\-autoescape\-off

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
| Thời gian xử lý | 14249 ms |

**Thông báo của scanner**

> Detected a template block where autoescaping is explicitly disabled with '\{% autoescape off %\}'\. This allows rendering of raw HTML in this segment\. Turn autoescaping on to prevent cross\-site scripting \(XSS\)\. If you must do this, consider instead, using \`mark\_safe\` in Python code\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 36\-56, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule kiểm tra việc tắt autoescape trong Django template, điều này có thể dẫn đến XSS nếu nội dung không được xử lý đúng\. Đoạn mã sử dụng \`\{% autoescape off %\}\` để hiển thị \`note\.content\` mà không có bảo vệ\. Tuy nhiên, không có bằng chứng rõ ràng cho thấy \`note\.content\` chứa dữ liệu người dùng không được kiểm tra hoặc không được đánh dấu an toàn\. Cần xác minh liệu \`note\.content\` có được xử lý an toàn trước khi truyền vào template hay không\.

**Bằng chứng LLM sử dụng**

- Nguồn\: \`\{% autoescape off %\}\` được sử dụng để hiển thị \`note\.content\` mà không có bảo vệ\.
- Điểm sử dụng nguy hiểm\: \`\{\{ note\.content \}\}\` được hiển thị trực tiếp mà không có \`mark\_safe\` hoặc xử lý bảo vệ\.
- Guard\/Sanitizer\: Không có bằng chứng về việc \`note\.content\` được kiểm tra hoặc xử lý an toàn trước khi truyền vào template\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Liệu \`note\.content\` có chứa dữ liệu người dùng không được kiểm tra hay không?
- Liệu \`note\.content\` có được xử lý bằng \`mark\_safe\` hoặc các phương pháp tương tự trước khi truyền vào template hay không?

**Giả định LLM đã sử dụng**

- Giả định rằng \`note\.content\` có thể chứa dữ liệu người dùng không được kiểm tra, vì không có bằng chứng ngược lại\.

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

### 5.3. LIKELY\_TP — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

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
| Thời gian xử lý | 22049 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 40\-66, hàm log\_in\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule đang kiểm tra việc xây dựng chuỗi SQL thủ công từ đầu vào người dùng, điều này có thể dẫn đến lỗ hổng SQL injection\. Trong code, username và password từ request\.POST được sử dụng trực tiếp trong chuỗi SQL không được parameterized\. Không có guard, sanitizer hay validation nào được áp dụng để bảo vệ đầu vào\. Điều này cho thấy khả năng cao là true positive\.

**Bằng chứng LLM sử dụng**

- Nguồn\: username và password được lấy từ request\.POST, là đầu vào người dùng\.
- Luồng dữ liệu\: username và password được chèn trực tiếp vào chuỗi SQL bằng toán tử %, không được parameterized\.
- Điểm sử dụng nguy hiểm\: query \= \("\.\.\. WHERE username \= '%s' AND \.\.\." % \(username, password\)\)
- Kết luận\: không có cơ chế bảo vệ đầu vào, dẫn đến nguy cơ SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả định rằng username và password có thể bị kiểm soát bởi người tấn công, vì chúng là đầu vào người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.4. LIKELY\_TP — python\.django\.security\.audit\.raw\-query\.avoid\-raw\-sql

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

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
| Thời gian xử lý | 42445 ms |

**Thông báo của scanner**

> Detected the use of 'RawSQL' or 'raw' indicating the execution of a non\-parameterized SQL query\. This could lead to a SQL injection and therefore protected information could be leaked\. Instead, use Django ORM and parameterized queries before raw SQL\. An example of using the Django ORM is\: \`People\.objects\.get\(name\='Bob'\)\`

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 40\-66, hàm log\_in\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule đang kiểm tra việc sử dụng RawSQL hoặc raw trong Django, điều này có thể dẫn đến SQL injection\. Trong code, query được xây dựng bằng cách chèn trực tiếp username và password vào chuỗi SQL, không sử dụng parameterized query\. Điều này cho thấy có nguy cơ lỗ hổng SQL injection\. Không có guard\/sanitizer nào được áp dụng để bảo vệ dữ liệu đầu vào\. Do đó, đây là true positive\.

**Bằng chứng LLM sử dụng**

- Nguồn\: username và password được lấy từ request\.POST, là input người dùng\.
- Luồng dữ liệu\: username và password được chèn trực tiếp vào chuỗi SQL bằng cách sử dụng toán tử %, không có tham số hóa\.
- Điểm sử dụng nguy hiểm\: User\.objects\.raw\(query\) được gọi với query chứa dữ liệu người dùng không được kiểm tra\.
- Kết luận\: Không có cơ chế bảo vệ nào được áp dụng, dẫn đến nguy cơ SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả định rằng username và password có thể bị kiểm soát bởi người tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

## 6. Lỗi scanner
- Giai đoạn: PARSE — Đọc và chuẩn hóa artifact; mã lỗi: PARSE\_RECORD\_INVALID\_FIELD; scanner: GITLEAKS; finding: null; có thể thử lại: False; thông báo an toàn: Gitleaks record\[0\] produced an invalid NormalizedFinding\.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
