# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 6 |
| Triage thành công | 6 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 3\.31424 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 6 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 2030b2dc\-c41c\-4e1f\-9a14\-dd1fb01be8c7 |
| Repository | realvuln\-damn\-vulnerable\-graphql\-application |
| Repository identifier | realvuln\-damn\-vulnerable\-graphql\-application |
| Commit | a961308c02d1fb462b192681c336b0739e432da7 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 20\.91246 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:32\:48\.024023\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:32\:51\.338263\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=8f8588dd47129b4b4d2706c4642379c15324ee0a4c5bc6e2fc2c4189be31da5a; semgrep=b13846ce7c9e09f5637f79de6162dee90c79c571beeb18562ef7a9502c8855d4

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 7bc45c81712441ea | python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode | core\/helpers\.py\:21 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | cd034c12ee3adc79 | python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text | core\/views\.py\:320 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | fad4ef183220aacc | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | app\.py\:14 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | MEDIUM | 2b3efd03176b0f1f | python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie | core\/views\.py\:395 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | UNKNOWN | 0100ad1a66ac6ba3 | jwt | tests\/test\_auth\.py\:52 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | UNKNOWN | 22ae0f2635374ab5 | jwt | tests\/test\_auth\.py\:34 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7bc45c81712441ea |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode |
| File | core\/helpers\.py |
| Dòng | 21 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-287\: Improper Authentication'\]; owasp=\['A02\:2017 \- Broken Authentication', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/github\.com\/we45\/Vulnerable\-Flask\-App\/blob\/752ee16087c0bfb79073f68802d907569a1f0df7\/app\/app\.py\#L96'\]; technology=\['jwt'\] |
| Thời gian xử lý | 803 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6259370cb41d7cf0b60f9689c28e4016a34fe48da20d01ef5583f3ff0352248c |

**Thông báo của scanner**

> Detected JWT token decoded with 'verify\=False'\. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors\. Ensure that the JWT token is verified\.

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

### 5.2. MANUAL\_REVIEW — python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cd034c12ee3adc79 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text |
| File | core\/views\.py |
| Dòng | 320 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 763 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | ccbaad7633b20628825adcc6b8aea4a7c0f02d3a355c5c61e7e952e47361ae67 |

**Thông báo của scanner**

> sqlalchemy\.text passes the constructed SQL statement to the database mostly unchanged\. This means that the usual SQL injection protections are not applied and this function is vulnerable to SQL injection if user input can reach here\. Use normal SQLAlchemy operators \(such as \`or\_\(\)\`, \`and\_\(\)\`, etc\.\) to construct SQL\.

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

### 5.3. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | fad4ef183220aacc |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | app\.py |
| Dòng | 14 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 1013 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 819f16f2a16fb5c5db13b755d2ddcabbae6ef461053f87b960c1eede0bc8dccf |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

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

### 5.4. MANUAL\_REVIEW — python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2b3efd03176b0f1f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie |
| File | core\/views\.py |
| Dòng | 395 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-614\: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/3\.0\.x\/api\/\#flask\.Response\.set\_cookie', 'https\:\/\/flask\.palletsprojects\.com\/en\/3\.0\.x\/security\/\#set\-cookie\-options'\]; technology=\['python', 'flask'\] |
| Thời gian xử lý | 709 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6ad0419047b273b4670285ebc1547e8ce970da3ada84c7444bd3b303b304cf0f |

**Thông báo của scanner**

> Found a Flask cookie with insecurely configured properties\.  By default the secure, httponly and samesite ar configured insecurely\. cookies should be handled securely by setting \`secure\=True\`, \`httponly\=True\`, and \`samesite\='Lax'\` in response\.set\_cookie\(\.\.\.\)\. If these parameters are not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker\. Include the \`secure\=True\`, \`httponly\=True\`, \`samesite\='Lax'\` arguments or set these to be true in the Flask configuration\.

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

### 5.5. MANUAL\_REVIEW — jwt

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0100ad1a66ac6ba3 |
| Scanner / loại finding | GITLEAKS / SECRET |
| Rule | jwt — Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\. |
| File | tests\/test\_auth\.py |
| Dòng | 52 |
| Severity | UNKNOWN |
| Metadata an toàn | entropy=5\.57466; rule\_description=Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\. |
| Thời gian xử lý | 1 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 07d7b28a06366e28f00579d22dd97b5128bdb36325ecdf7cbd1339dcfb13bba0 |

**Thông báo của scanner**

> Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-64\.

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

### 5.6. MANUAL\_REVIEW — jwt

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 22ae0f2635374ab5 |
| Scanner / loại finding | GITLEAKS / SECRET |
| Rule | jwt — Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\. |
| File | tests\/test\_auth\.py |
| Dòng | 34 |
| Severity | UNKNOWN |
| Metadata an toàn | entropy=5\.5611672; rule\_description=Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\. |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7774da6cc0eb7f2a2f1c55d31e36d86d827aacd5dce721fa659f164010bc72f9 |

**Thông báo của scanner**

> Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-64\.

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

## 6. Lỗi scanner
- Không có lỗi scanner.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
