# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 9 |
| Triage thành công | 9 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 5\.638649 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 9 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 32fcd914\-cbb5\-40fd\-8173\-0919832d5ac3 |
| Repository | realvuln\-dsvpwa |
| Repository identifier | realvuln\-dsvpwa |
| Commit | a06abb306ed3699bb2f073e3f41d3d9c57012819 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 15\.914771 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:34\:12\.850463\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:34\:18\.489112\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=ced4ad1c98d6a0fc344f5b842ddddd34dc3659a23ed09c582fcdbefbffe2e4ee; semgrep=c2180ccdbd3ad9a6da8bac278a9b34b9ed38e61ae304120d6b320dd1d9f14d11

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 267fc34bbb67393b | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml | dsvpwa\/server\.py\:2 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 42a92c3363ba8fde | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true | dsvpwa\/handlers\.py\:185 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 4552ec45da5e313f | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true | dsvpwa\/attacks\.py\:167 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | d97fad5ff0f94280 | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml | dsvpwa\/handlers\.py\:12 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | MEDIUM | 5db5cc99b918bb93 | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | dsvpwa\/attacks\.py\:199 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | MEDIUM | 81ef2785ca9d0ad5 | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | dsvpwa\/attacks\.py\:213 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | MEDIUM | ab7f20a7f2d053b2 | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | dsvpwa\/attacks\.py\:185 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | MEDIUM | cd6201d512dae384 | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | dsvpwa\/attacks\.py\:187 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | UNKNOWN | c525c84d54044165 | private\-key | ssl\/key\.pem\:1–28 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 267fc34bbb67393b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml |
| File | dsvpwa\/server\.py |
| Dòng | 2 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-611\: Improper Restriction of XML External Entity Reference'\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/xml\.html', 'https\:\/\/github\.com\/tiran\/defusedxml', 'https\:\/\/owasp\.org\/www\-community\/vulnerabilities\/XML\_External\_Entity\_\(XXE\)\_Processing'\]; technology=\['python'\] |
| Thời gian xử lý | 481 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a07b39d551ff8840157c20f6a8487fe693d323633ad1c92d184cd07396072666 |

**Thông báo của scanner**

> The Python documentation recommends using \`defusedxml\` instead of \`xml\` because the native Python \`xml\` library is vulnerable to XML External Entity \(XXE\) attacks\. These attacks can leak confidential data and "XML bombs" can cause denial of service\.

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

### 5.2. MANUAL\_REVIEW — python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 42a92c3363ba8fde |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true |
| File | dsvpwa\/handlers\.py |
| Dòng | 185 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-78\: Improper Neutralization of Special Elements used in an OS Command \('OS Command Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/3172470\/actual\-meaning\-of\-shell\-true\-in\-subprocess', 'https\:\/\/docs\.python\.org\/3\/library\/subprocess\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 546 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7434b2617a5dc117e5e5049f3bdb75a96d38a420206dbe1e6b812a0239e16ba0 |

**Thông báo của scanner**

> Found 'subprocess' function 'check\_output' with 'shell\=True'\. This is dangerous because this call will spawn the command using a shell process\. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands\. Use 'shell\=False' instead\.

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

### 5.3. MANUAL\_REVIEW — python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4552ec45da5e313f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true |
| File | dsvpwa\/attacks\.py |
| Dòng | 167 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-78\: Improper Neutralization of Special Elements used in an OS Command \('OS Command Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/3172470\/actual\-meaning\-of\-shell\-true\-in\-subprocess', 'https\:\/\/docs\.python\.org\/3\/library\/subprocess\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 948 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | ef406675ba6ed2f6a9d38547c7d39180fe5e1989c739aec31ad811db34eb4330 |

**Thông báo của scanner**

> Found 'subprocess' function 'check\_output' with 'shell\=True'\. This is dangerous because this call will spawn the command using a shell process\. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands\. Use 'shell\=False' instead\.

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

### 5.4. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d97fad5ff0f94280 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml |
| File | dsvpwa\/handlers\.py |
| Dòng | 12 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-611\: Improper Restriction of XML External Entity Reference'\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/xml\.html', 'https\:\/\/github\.com\/tiran\/defusedxml', 'https\:\/\/owasp\.org\/www\-community\/vulnerabilities\/XML\_External\_Entity\_\(XXE\)\_Processing'\]; technology=\['python'\] |
| Thời gian xử lý | 539 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 79f2d2937adc2985835806f1b8cd0651350e08518d241a4f9cc331d92a9649fe |

**Thông báo của scanner**

> The Python documentation recommends using \`defusedxml\` instead of \`xml\` because the native Python \`xml\` library is vulnerable to XML External Entity \(XXE\) attacks\. These attacks can leak confidential data and "XML bombs" can cause denial of service\.

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

### 5.5. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5db5cc99b918bb93 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | dsvpwa\/attacks\.py |
| Dòng | 199 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 735 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4d42500257e33c2352e1756fcf6d28752272d0f2ac9be62f01f2b1bb86d1a363 |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink dsvpwa\/attacks\.py\:199; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.6. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 81ef2785ca9d0ad5 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | dsvpwa\/attacks\.py |
| Dòng | 213 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 675 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f404ac17836770d37d0830f3449db193b81ebd059e9b105d5fdb50cb4c997601 |

**Thông báo của scanner**

> Detected a dynamic value being used with urllib\. urllib supports 'file\:\/\/' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files\. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead\.

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

### 5.7. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ab7f20a7f2d053b2 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | dsvpwa\/attacks\.py |
| Dòng | 185 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 818 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | aede4d64c09f97b6c29768fb842f5f1508536047bb983b5c08d98de28552d564 |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

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

### 5.8. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cd6201d512dae384 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | dsvpwa\/attacks\.py |
| Dòng | 187 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 845 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 40907c1ae433f923a6ab4884dedd70ae16eafda639eb0a2ab3b1cea37efc5068 |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

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

### 5.9. MANUAL\_REVIEW — private\-key

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c525c84d54044165 |
| Scanner / loại finding | GITLEAKS / SECRET |
| Rule | private\-key — Identified a Private Key, which may compromise cryptographic security and sensitive data encryption\. |
| File | ssl\/key\.pem |
| Dòng | 1–28 |
| Severity | UNKNOWN |
| Metadata an toàn | entropy=6\.034928; rule\_description=Identified a Private Key, which may compromise cryptographic security and sensitive data encryption\. |
| Thời gian xử lý | 1 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f1341d8ec53aaa1595d44b6e0528fa1006996890b63bf6b355b907f37b885dba |

**Thông báo của scanner**

> Identified a Private Key, which may compromise cryptographic security and sensitive data encryption\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-28\.

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
