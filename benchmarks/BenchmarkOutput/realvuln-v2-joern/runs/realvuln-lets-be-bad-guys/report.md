# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 14 |
| Triage thành công | 14 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 8\.922744 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 14 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 3c94ddc0\-43f9\-4005\-923b\-47fc8e3f9eb9 |
| Repository | realvuln\-lets\-be\-bad\-guys |
| Repository identifier | realvuln\-lets\-be\-bad\-guys |
| Commit | 7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 15\.785895 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:39\:20\.837170\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:39\:29\.759914\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=e2ef51086e83397fad89f96dfce11fb77986ce0dca4c41b798075067fee4bf20

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | MEDIUM | 01e6db76da65abac | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag | badguys\/templates\/vulnerable\/xss\/path\.html\:49 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | MEDIUM | 143a7f4924cc3688 | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie | badguys\/vulnerable\/views\.py\:100 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | MEDIUM | 3b001fe0ce297f2c | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | badguys\/templates\/vulnerable\/xss\/path\.html\:49 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | MEDIUM | 5a46023f16fad0d3 | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | badguys\/vulnerable\/views\.py\:72 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | MEDIUM | 5b301e108b089817 | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | badguys\/vulnerable\/views\.py\:76 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | MEDIUM | 747b5559fbfed4ee | python\.django\.security\.injection\.open\-redirect\.open\-redirect | badguys\/vulnerable\/views\.py\:177–178 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | MEDIUM | 7aceb948c150f886 | python\.django\.security\.injection\.code\.user\-exec\-format\-string\.user\-exec\-format\-string | badguys\/vulnerable\/views\.py\:68–80 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | MEDIUM | 99c2b338b7a12ea0 | python\.django\.security\.injection\.code\.globals\-misuse\-code\-execution\.globals\-misuse\-code\-execution | badguys\/vulnerable\/views\.py\:182–186 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | MEDIUM | 9fea47ba1ca14dbb | python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt | badguys\/vulnerable\/views\.py\:164–167 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | MEDIUM | bcb9e131b2eeabea | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag | badguys\/templates\/vulnerable\/xss\/query\.html\:37 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | MEDIUM | bee9ea9c9280dd3f | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | badguys\/templates\/vulnerable\/csrf\/image\.html\:48 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | MEDIUM | dee97c72465ab72a | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | badguys\/templates\/vulnerable\/xss\/query\.html\:37 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | ed2151df3e1d2736 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | badguys\/templates\/vulnerable\/xss\/form\.html\:28 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | MEDIUM | f72336199da4f338 | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag | badguys\/templates\/vulnerable\/csrf\/image\.html\:48 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 01e6db76da65abac |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag |
| File | badguys\/templates\/vulnerable\/xss\/path\.html |
| Dòng | 49 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/adamj\.eu\/tech\/2020\/02\/18\/safely\-including\-data\-for\-javascript\-in\-a\-django\-template\/?utm\_campaign\=Django%2BNewsletter&amp;utm\_medium\=rss&amp;utm\_source\=Django\_Newsletter\_12A', 'https\:\/\/www\.veracode\.com\/blog\/secure\-development\/nodejs\-template\-engines\-why\-default\-encoders\-are\-not\-enough', 'https\:\/\/github\.com\/ESAPI\/owasp\-esapi\-js'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 703 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f98dd1ac6afb5e452126cb0d88ede4817271a177f9b1a27779025b39a4be4691 |

**Thông báo của scanner**

> Detected a template variable used in a script tag\. Although template variables are HTML escaped, HTML escaping does not always prevent cross\-site scripting \(XSS\) attacks when used directly in JavaScript\. If you need this data on the rendered page, consider placing it in the HTML portion \(outside of a script tag\)\. Alternatively, use a JavaScript\-specific encoder, such as the one available in OWASP ESAPI\. For Django, you may also consider using the 'json\_script' template tag and retrieving the data in your script by using the element ID \(e\.g\., \`document\.getElementById\`\)\.

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

### 5.2. MANUAL\_REVIEW — python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 143a7f4924cc3688 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 100 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-614\: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/request\-response\/\#django\.http\.HttpResponse\.set\_cookie', 'https\:\/\/semgrep\.dev\/blog\/2020\/bento\-check\-keeping\-cookies\-safe\-in\-flask\/', 'https\:\/\/bento\.dev\/checks\/flask\/secure\-set\-cookie\/'\]; technology=\['django'\] |
| Thời gian xử lý | 398 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 33d644613a51aca82841c06ef0c43ec886adbbbb313e80da041c4f931593c4fb |

**Thông báo của scanner**

> Django cookies should be handled securely by setting secure\=True, httponly\=True, and samesite\='Lax' in response\.set\_cookie\(\.\.\.\)\. If your situation calls for different settings, explicitly disable the setting\. If you want to send the cookie over http, set secure\=False\. If you want to let client\-side JavaScript read the cookie, set httponly\=False\. If you want to attach cookies to requests for external sites, set samesite\=None\.

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

### 5.3. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3b001fe0ce297f2c |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | badguys\/templates\/vulnerable\/xss\/path\.html |
| Dòng | 49 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 760 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 3903a24ac8abcea1be10e39567c67b1e7c9b25fbd70e5481376cc026656e77a6 |

**Thông báo của scanner**

> Detected a segment of a Flask template where autoescaping is explicitly disabled with '\| safe' filter\. This allows rendering of raw HTML in this segment\. Ensure no user data is rendered here, otherwise this is a cross\-site scripting \(XSS\) vulnerability\.

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

### 5.4. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5a46023f16fad0d3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 72 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 613 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 13238b3bddc06e16a8d49c131bbee235319c7553a63bbbd7ca3149c4911110eb |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source badguys\/vulnerable\/views\.py\:68; sink badguys\/vulnerable\/views\.py\:72; đường source–sink badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.5. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5b301e108b089817 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 76 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 610 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 88ba67bbfb76e3af894f188e7167adbd7ade64c7f144f59b288ab9f6627f05b7 |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source badguys\/vulnerable\/views\.py\:68; sink badguys\/vulnerable\/views\.py\:76; đường source–sink badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:76 → badguys\/vulnerable\/views\.py\:76; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.6. MANUAL\_REVIEW — python\.django\.security\.injection\.open\-redirect\.open\-redirect

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 747b5559fbfed4ee |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.open\-redirect\.open\-redirect |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 177–178 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-601\: URL Redirection to Untrusted Site \('Open Redirect'\)"\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/www\.djm\.org\.uk\/posts\/djangos\-little\-protections\-word\-redirect\-dangers\/', 'https\:\/\/github\.com\/django\/django\/blob\/d1b7bd030b1db111e1a3505b1fc029ab964382cc\/django\/utils\/http\.py\#L231'\]; technology=\['django'\] |
| Thời gian xử lý | 422 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9206180f88e8673512c109b4201c10a4c3da47699ab78bcfb1f370b3a583052b |

**Thông báo của scanner**

> Data from request \(url\) is passed to redirect\(\)\. This is an open redirect and could be exploited\. Ensure you are redirecting to safe URLs by using django\.utils\.http\.is\_safe\_url\(\)\. See https\:\/\/cwe\.mitre\.org\/data\/definitions\/601\.html for more information\.

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

### 5.7. MANUAL\_REVIEW — python\.django\.security\.injection\.code\.user\-exec\-format\-string\.user\-exec\-format\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7aceb948c150f886 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.code\.user\-exec\-format\-string\.user\-exec\-format\-string |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 68–80 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/www\-community\/attacks\/Code\_Injection'\]; technology=\['django'\] |
| Thời gian xử lý | 752 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0af3a60571e45d90ebee77cf2f55620a6286749bceb46c0481b2d1c21510dfab |

**Thông báo của scanner**

> Found user data in a call to 'exec'\. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system\. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source badguys\/vulnerable\/views\.py\:68; sink badguys\/vulnerable\/views\.py\:72; đường source–sink badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:68 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72 → badguys\/vulnerable\/views\.py\:72; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.8. MANUAL\_REVIEW — python\.django\.security\.injection\.code\.globals\-misuse\-code\-execution\.globals\-misuse\-code\-execution

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 99c2b338b7a12ea0 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.code\.globals\-misuse\-code\-execution\.globals\-misuse\-code\-execution |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 182–186 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-96\: Improper Neutralization of Directives in Statically Saved Code \('Static Code Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/github\.com\/mpirnat\/lets\-be\-bad\-guys\/blob\/d92768fb3ade32956abd53bd6bb06e19d634a084\/badguys\/vulnerable\/views\.py\#L181\-L186'\]; technology=\['django'\] |
| Thời gian xử lý | 391 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a7e4a572146cbcc1fa5af9d652c8f161f068acc8db72d80085e205723d882edc |

**Thông báo của scanner**

> Found request data as an index to 'globals\(\)'\. This is extremely dangerous because it allows an attacker to execute arbitrary code on the system\. Refactor your code not to use 'globals\(\)'\.

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

### 5.9. MANUAL\_REVIEW — python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9fea47ba1ca14dbb |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt |
| File | badguys\/vulnerable\/views\.py |
| Dòng | 164–167 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-352\: Cross\-Site Request Forgery \(CSRF\)'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['django'\] |
| Thời gian xử lý | 392 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a813013f4d6021f462791a07031da3a3645759ac8d8f0647a2dcd5bb0e24bf0d |

**Thông báo của scanner**

> Detected usage of @csrf\_exempt, which indicates that there is no CSRF token set for this route\. This could lead to an attacker manipulating the user's account and exfiltration of private data\. Instead, create a function without this decorator\.

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

### 5.10. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | bcb9e131b2eeabea |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag |
| File | badguys\/templates\/vulnerable\/xss\/query\.html |
| Dòng | 37 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/adamj\.eu\/tech\/2020\/02\/18\/safely\-including\-data\-for\-javascript\-in\-a\-django\-template\/?utm\_campaign\=Django%2BNewsletter&amp;utm\_medium\=rss&amp;utm\_source\=Django\_Newsletter\_12A', 'https\:\/\/www\.veracode\.com\/blog\/secure\-development\/nodejs\-template\-engines\-why\-default\-encoders\-are\-not\-enough', 'https\:\/\/github\.com\/ESAPI\/owasp\-esapi\-js'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 571 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 765265ff701e5e5d7d9f86133660ba59f25b0f85d7993b25caf783ba9445e101 |

**Thông báo của scanner**

> Detected a template variable used in a script tag\. Although template variables are HTML escaped, HTML escaping does not always prevent cross\-site scripting \(XSS\) attacks when used directly in JavaScript\. If you need this data on the rendered page, consider placing it in the HTML portion \(outside of a script tag\)\. Alternatively, use a JavaScript\-specific encoder, such as the one available in OWASP ESAPI\. For Django, you may also consider using the 'json\_script' template tag and retrieving the data in your script by using the element ID \(e\.g\., \`document\.getElementById\`\)\.

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

### 5.11. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | bee9ea9c9280dd3f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | badguys\/templates\/vulnerable\/csrf\/image\.html |
| Dòng | 48 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 1017 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 655ed5be9f540a1b4145293a34cdf1cb116b794373f8faa16a7429c9d8b64a1f |

**Thông báo của scanner**

> Detected a segment of a Flask template where autoescaping is explicitly disabled with '\| safe' filter\. This allows rendering of raw HTML in this segment\. Ensure no user data is rendered here, otherwise this is a cross\-site scripting \(XSS\) vulnerability\.

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

### 5.12. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dee97c72465ab72a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | badguys\/templates\/vulnerable\/xss\/query\.html |
| Dòng | 37 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 460 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 40d32dc1bccaa5addee61c9a18df3583ce193a57d3f209b9397c8c9b4e9aaa1f |

**Thông báo của scanner**

> Detected a segment of a Flask template where autoescaping is explicitly disabled with '\| safe' filter\. This allows rendering of raw HTML in this segment\. Ensure no user data is rendered here, otherwise this is a cross\-site scripting \(XSS\) vulnerability\.

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

### 5.13. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ed2151df3e1d2736 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | badguys\/templates\/vulnerable\/xss\/form\.html |
| Dòng | 28 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 760 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 380d007ec2810a21667bfbc13fcd1bd24e05c2ab477516a133889ded30ca4c17 |

**Thông báo của scanner**

> Detected a segment of a Flask template where autoescaping is explicitly disabled with '\| safe' filter\. This allows rendering of raw HTML in this segment\. Ensure no user data is rendered here, otherwise this is a cross\-site scripting \(XSS\) vulnerability\.

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

### 5.14. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f72336199da4f338 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-script\-tag\.var\-in\-script\-tag |
| File | badguys\/templates\/vulnerable\/csrf\/image\.html |
| Dòng | 48 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/adamj\.eu\/tech\/2020\/02\/18\/safely\-including\-data\-for\-javascript\-in\-a\-django\-template\/?utm\_campaign\=Django%2BNewsletter&amp;utm\_medium\=rss&amp;utm\_source\=Django\_Newsletter\_12A', 'https\:\/\/www\.veracode\.com\/blog\/secure\-development\/nodejs\-template\-engines\-why\-default\-encoders\-are\-not\-enough', 'https\:\/\/github\.com\/ESAPI\/owasp\-esapi\-js'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 994 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7e16a36442b6c0889fe78562742a6469779cc901d9425be37f210ce2553b601a |

**Thông báo của scanner**

> Detected a template variable used in a script tag\. Although template variables are HTML escaped, HTML escaping does not always prevent cross\-site scripting \(XSS\) attacks when used directly in JavaScript\. If you need this data on the rendered page, consider placing it in the HTML portion \(outside of a script tag\)\. Alternatively, use a JavaScript\-specific encoder, such as the one available in OWASP ESAPI\. For Django, you may also consider using the 'json\_script' template tag and retrieving the data in your script by using the element ID \(e\.g\., \`document\.getElementById\`\)\.

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
