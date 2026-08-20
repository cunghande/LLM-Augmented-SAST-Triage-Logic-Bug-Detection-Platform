# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 13 |
| Triage thành công | 13 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 7\.746849 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 13 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 2ab80b15\-8439\-46d2\-9c3e\-412b541b13ad |
| Repository | realvuln\-vulnerable\-flask\-app |
| Repository identifier | realvuln\-vulnerable\-flask\-app |
| Commit | b6a4f97afd466e83e1f60781494252dec1c37039 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 15\.459842 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:46\:53\.886492\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:47\:01\.633341\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=b90f1a7894b93124f96f9af187aaf8912768fd1faa4d970e2b760e31d9ae58d1

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 4e66993f36d9d2fb | python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string | app\/app\.py\:103–114 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 76a9c0045eb241c6 | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | app\/app\.py\:261 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 8ffb95f6c99dfd71 | python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string | app\/app\.py\:271–281 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | a87d313452dedce5 | python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization | app\/app\.py\:329 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | c87766d0c03d2cc1f4725397a5a2d02bc3e700c7467fd0c3fe462d221cd2cea5 | module2\.logic\.missing\-authz\-idor | app\/app\.py\:231 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | d044cdc3caef18acb0437e53c595f0388eeb0631fa791591919c91893d1090cf | module2\.logic\.missing\-authz\-idor | app\/app\.py\:208 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | MEDIUM | 091255b95fbbf7ab | python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string | app\/app\.py\:114 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | MEDIUM | 1f41f750afd20175 | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | app\/app\.py\:141 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | MEDIUM | 5c768e8b67d6d7a0 | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href | app\/templates\/index\.html\:12 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | MEDIUM | 6f2dba1d994aef7e | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format | app\/app\.py\:103–112 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | MEDIUM | 784f18b6142bfdeb | python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string | app\/app\.py\:281 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | MEDIUM | 8b746cdb91f12972 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | app\/app\.py\:141 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | a6cfa72fdb838103 | python\.flask\.security\.injection\.raw\-html\-concat\.raw\-html\-format | app\/app\.py\:103–112 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4e66993f36d9d2fb |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string |
| File | app\/app\.py |
| Dòng | 103–114 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-96\: Improper Neutralization of Directives in Statically Saved Code \('Static Code Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nvisium\.com\/blog\/2016\/03\/09\/exploring\-ssti\-in\-flask\-jinja2\.html', 'https\:\/\/pequalsnp\-team\.github\.io\/cheatsheet\/flask\-jinja2\-ssti'\]; technology=\['flask'\] |
| Thời gian xử lý | 1334 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8bc2517552f58c0cfdca9cb8f4edda7b8910cc39c578745af937cad10bbd512e |

**Thông báo của scanner**

> Found a template created with string formatting\. This is susceptible to server\-side template injection and cross\-site scripting attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source app\/app\.py\:112; sink app\/app\.py\:114; đường source–sink app\/app\.py\:112 → app\/app\.py\:103 → app\/app\.py\:103 → app\/app\.py\:114 → app\/app\.py\:114; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.2. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 76a9c0045eb241c6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | app\/app\.py |
| Dòng | 261 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 614 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | b94dde58903c1d4e448165981148f190608e6940ba4648959d8b930f47811cf0 |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.3. MANUAL\_REVIEW — python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8ffb95f6c99dfd71 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.dangerous\-template\-string\.dangerous\-template\-string |
| File | app\/app\.py |
| Dòng | 271–281 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-96\: Improper Neutralization of Directives in Statically Saved Code \('Static Code Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nvisium\.com\/blog\/2016\/03\/09\/exploring\-ssti\-in\-flask\-jinja2\.html', 'https\:\/\/pequalsnp\-team\.github\.io\/cheatsheet\/flask\-jinja2\-ssti'\]; technology=\['flask'\] |
| Thời gian xử lý | 587 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e02adf6c4f97a4d8465d0d6fd4a287ae3609ea7852089ac256dd33be1fc234d3 |

**Thông báo của scanner**

> Found a template created with string formatting\. This is susceptible to server\-side template injection and cross\-site scripting attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink app\/app\.py\:281; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.4. MANUAL\_REVIEW — python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a87d313452dedce5 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization |
| File | app\/app\.py |
| Dòng | 329 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['flask'\] |
| Thời gian xử lý | 582 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 90e1f70e28f1f178b94b5b76a259bebeee4849d8aef3a1c9e2e5f42adc69d542 |

**Thông báo của scanner**

> Detected the use of an insecure deserialization library in a Flask route\. These libraries are prone to code execution vulnerabilities\. Ensure user data does not enter this function\. To fix this, try to avoid serializing whole objects\. Consider instead using a serializer such as JSON\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source app\/app\.py\:322; sink app\/app\.py\:329; đường source–sink app\/app\.py\:322 → app\/app\.py\:322 → app\/app\.py\:322 → app\/app\.py\:323 → app\/app\.py\:323 → app\/app\.py\:324 → app\/app\.py\:326 → app\/app\.py\:326 → app\/app\.py\:326 → app\/app\.py\:326; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.5. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c87766d0c03d2cc1f4725397a5a2d02bc3e700c7467fd0c3fe462d221cd2cea5 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | app\/app\.py |
| Dòng | 231 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=get\_customer; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:get\_customer@222', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@231'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 062c5e17b6778dbd45831901eaddfca5cb507a43ee59ae464d1cdf198eebf03d |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 171\-291\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.6. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d044cdc3caef18acb0437e53c595f0388eeb0631fa791591919c91893d1090cf |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | app\/app\.py |
| Dòng | 208 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=fetch\_customer; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_request\_body; trace=\['entrypoint\:fetch\_customer@197', 'source\:http\_request\_body', 'sink\:object\_lookup\_without\_subject\_scope@208'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 39b9b3c4764e974552410e0bc268a91967c5f1eeb42d0d20699fbb6523c6b52b |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 148\-268\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.7. MANUAL\_REVIEW — python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 091255b95fbbf7ab |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string |
| File | app\/app\.py |
| Dòng | 114 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-96\: Improper Neutralization of Directives in Statically Saved Code \('Static Code Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nvisium\.com\/blog\/2016\/03\/09\/exploring\-ssti\-in\-flask\-jinja2\.html'\]; technology=\['flask'\] |
| Thời gian xử lý | 798 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c76be1988ca371e96eb49ddb08bac994e836cd09b5101f513e0d9c8125582a04 |

**Thông báo của scanner**

> Found a template created with string formatting\. This is susceptible to server\-side template injection and cross\-site scripting attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source app\/app\.py\:112; sink app\/app\.py\:114; đường source–sink app\/app\.py\:112 → app\/app\.py\:103 → app\/app\.py\:103 → app\/app\.py\:114 → app\/app\.py\:114; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.8. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1f41f750afd20175 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | app\/app\.py |
| Dòng | 141 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 719 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | cf3073092cef8847853adead806d0ffb9c763c27d48708c0a4e0d66e848c5c6e |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source app\/app\.py\:137; sink app\/app\.py\:141; đường source–sink app\/app\.py\:137 → app\/app\.py\:137 → app\/app\.py\:140 → app\/app\.py\:140 → app\/app\.py\:141 → app\/app\.py\:141 → app\/app\.py\:141; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.9. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5c768e8b67d6d7a0 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href |
| File | app\/templates\/index\.html |
| Dòng | 12 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss\#\:\~\:text\=javascript\:%20URI', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.1\/ref\/templates\/builtins\/\#url', 'https\:\/\/github\.com\/pugjs\/pug\/issues\/2952', 'https\:\/\/content\-security\-policy\.com\/'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 454 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e839f97c90c485e1d477d371eb262b66a0626b35e725e2ceda26f1b6c72a2a0e |

**Thông báo của scanner**

> Detected a template variable used in an anchor tag with the 'href' attribute\. This allows a malicious actor to input the 'javascript\:' URI and is subject to cross\- site scripting \(XSS\) attacks\. If using Flask, use 'url\_for\(\)' to safely generate a URL\. If using Django, use the 'url' filter to safely generate a URL\. If using Mustache, use a URL encoding library, or prepend a slash '\/' to the variable for relative links \(\`href\="\/\{\{link\}\}"\`\)\. You may also consider setting the Content Security Policy \(CSP\) header\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.10. MANUAL\_REVIEW — python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6f2dba1d994aef7e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format |
| File | app\/app\.py |
| Dòng | 103–112 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/http\/shortcuts\/\#render', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/security\/\#cross\-site\-scripting\-xss\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1004 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | efe08f48a5537cce721b75eb4f62ff659ee69aa72b02b02de0fdefc9561e2399 |

**Thông báo của scanner**

> Detected user input flowing into a manually constructed HTML string\. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross\-site scripting vulnerability, which could let attackers steal sensitive user data\. To be sure this is safe, check that the HTML is rendered safely\. Otherwise, use templates \(\`django\.shortcuts\.render\`\) which will safely render HTML instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.11. MANUAL\_REVIEW — python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 784f18b6142bfdeb |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.render\-template\-string\.render\-template\-string |
| File | app\/app\.py |
| Dòng | 281 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-96\: Improper Neutralization of Directives in Statically Saved Code \('Static Code Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nvisium\.com\/blog\/2016\/03\/09\/exploring\-ssti\-in\-flask\-jinja2\.html'\]; technology=\['flask'\] |
| Thời gian xử lý | 428 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | fff10fa67d981e91c08396a8f7bd4f30a9e3213cd7b69c5a07bf627ba9e63729 |

**Thông báo của scanner**

> Found a template created with string formatting\. This is susceptible to server\-side template injection and cross\-site scripting attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink app\/app\.py\:281; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.12. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8b746cdb91f12972 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | app\/app\.py |
| Dòng | 141 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 269 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f53bc6e2a3119c17dbc92fedad98a7241e103c9a510048441b88956230596b7d |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink app\/app\.py\:141; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

### 5.13. MANUAL\_REVIEW — python\.flask\.security\.injection\.raw\-html\-concat\.raw\-html\-format

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a6cfa72fdb838103 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.raw\-html\-concat\.raw\-html\-format |
| File | app\/app\.py |
| Dòng | 103–112 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/2\.0\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 892 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | ec921f25a52e7f77cb4fb5dc528b2d4efabaf8786985f088896e3ad95d1e2c04 |

**Thông báo của scanner**

> Detected user input flowing into a manually constructed HTML string\. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross\-site scripting vulnerability, which could let attackers steal sensitive user data\. To be sure this is safe, check that the HTML is rendered safely\. Otherwise, use templates \(\`flask\.render\_template\`\) which will safely render HTML instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** fake\-triage\-v1 / triage\-prompt\-v13

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
- **Policy version:** conservative\-policy\-v2
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

## 6. Lỗi scanner
- Không có lỗi scanner.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
