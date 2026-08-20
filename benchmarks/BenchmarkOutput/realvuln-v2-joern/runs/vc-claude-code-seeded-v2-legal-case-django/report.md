# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 29 |
| Triage thành công | 29 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 13\.592054 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 29 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 9178f8dd\-1411\-49df\-8554\-2de932fe7b5a |
| Repository | vc\-claude\-code\-seeded\-v2\-legal\-case\-django |
| Repository identifier | vc\-claude\-code\-seeded\-v2\-legal\-case\-django |
| Commit | 3c38d4caf4386567c26bd136f5baddfeb51fc302 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 22\.215653 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:54\:45\.937152\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:54\:59\.529206\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=7ca70862e8ef6c4cb2b6fb81fa1329e99558a7e271d89db7e50ae18fa9f67e03

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 0335507c67d9fc6436444eabc67cc5767fe0c9fffaa24fe764279da82d7e8328 | module2\.logic\.business\-rule\-bypass | cases\/views\_admin\.py\:61 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 1701687693cfe7ab56e4a0c90f6ffe0e1322e19441ef0c6717d0d292f2ab47b5 | module2\.logic\.business\-rule\-bypass | cases\/views\_clients\.py\:20 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 3e061f63b5f7aabe | python\.django\.security\.nan\-injection\.nan\-injection | legal\_firm\/case\_operations\.py\:21 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 433577af30e6b786 | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context | legal\_firm\/case\_operations\.py\:176 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | 575d42806de6a98333730f0a985d1d0b619af91f0f5dc724ffd5f73baf1962c5 | module2\.logic\.missing\-authz\-idor | cases\/views\_admin\.py\:87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | 6a486b63a668c98c3d14cde21fad4b38855a0dbde2bc62eccb033bb00de07890 | module2\.logic\.business\-rule\-bypass | legal\_firm\/case\_operations\.py\:59 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | HIGH | 6aa4d357337fa5221e82a56417e6bcd4be2c7d92dbce6aad2691a74d3a9b3e28 | module2\.logic\.missing\-authz\-idor | accounts\/views\.py\:254 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 84295e4a3f345d1cce587cd630bc2619dbb640d1ec5ec5f0e9edf290d2224750 | module2\.logic\.business\-rule\-bypass | accounts\/views\.py\:206 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | HIGH | b6bbb9ee2d68a72a358bfc0265a51584cf6af0bbab7f6fbc619ed05170de9c14 | module2\.logic\.business\-rule\-bypass | accounts\/views\.py\:96 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | HIGH | ce9ba9d812b1d94e | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization | legal\_firm\/case\_operations\.py\:73 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | HIGH | f3789a02e96c7be46e5cb9423d521fae8119f83cc9d895cd139a2c2bd3138783 | module2\.logic\.business\-rule\-bypass | accounts\/views\.py\:70 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | MEDIUM | 0c9b9f82d86b3075 | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password | cases\/management\/commands\/seed\_minimal\.py\:35 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | 11da400b26c4935b | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | legal\_firm\/case\_operations\.py\:177 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | MEDIUM | 344948cec58684d7 | python\.django\.security\.audit\.avoid\-mark\-safe\.avoid\-mark\-safe | cases\/templatetags\/cases\_extras\.py\:28 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | MEDIUM | 3a74b571c5185185 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/accounts\/password\_change\.html\:12 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 16 | MANUAL\_REVIEW | MEDIUM | 40a423bc63433cb3 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/cases\/client\_form\.html\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 17 | MANUAL\_REVIEW | MEDIUM | 47468ac65f7a3ddc | python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt | integrations\/api\_views\.py\:29–41 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 18 | MANUAL\_REVIEW | MEDIUM | 491e5656f3773b16 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/accounts\/password\_reset\_confirm\.html\:13 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 19 | MANUAL\_REVIEW | MEDIUM | 51d5966db87aa871 | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format | legal\_firm\/case\_operations\.py\:32 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 20 | MANUAL\_REVIEW | MEDIUM | 63e619b0203cf1e5 | python\.lang\.security\.audit\.eval\-detected\.eval\-detected | legal\_firm\/case\_operations\.py\:87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 21 | MANUAL\_REVIEW | MEDIUM | 8cf2357c7de20a0a | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href | templates\/accounts\/notifications\.html\:15 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 22 | MANUAL\_REVIEW | MEDIUM | 9c933c1c86c1d9c2 | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | legal\_firm\/case\_operations\.py\:73 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 23 | MANUAL\_REVIEW | MEDIUM | ab36f46117ca1cba | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/cases\/document\_form\.html\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 24 | MANUAL\_REVIEW | MEDIUM | c1d7e827a92bf449 | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password | cases\/management\/commands\/seed\_demo\.py\:175 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 25 | MANUAL\_REVIEW | MEDIUM | c4b4be7343ed73ae | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/accounts\/user\_create\.html\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 26 | MANUAL\_REVIEW | MEDIUM | c775b835c1d4651e | python\.django\.security\.injection\.code\.user\-eval\.user\-eval | legal\_firm\/case\_operations\.py\:86–87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 27 | MANUAL\_REVIEW | MEDIUM | cd4f4b8fdfbd454b | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/cases\/firm\_settings\.html\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 28 | MANUAL\_REVIEW | MEDIUM | d93aab13c39c8123 | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie | legal\_firm\/case\_operations\.py\:95 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 29 | MANUAL\_REVIEW | MEDIUM | eb0a8b06787b7ab4 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | templates\/cases\/matter\_form\.html\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0335507c67d9fc6436444eabc67cc5767fe0c9fffaa24fe764279da82d7e8328 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | cases\/views\_admin\.py |
| Dòng | 61 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=practice\_area\_list; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:practice\_area\_list@60', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@61'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0d2637d80350f68d755f08f4801423c24e5d4866cefaa02e639b68d3c36516c4 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-121\.

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

### 5.2. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1701687693cfe7ab56e4a0c90f6ffe0e1322e19441ef0c6717d0d292f2ab47b5 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | cases\/views\_clients\.py |
| Dòng | 20 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=client\_list; entrypoint\_exposed=True; guards=\['matters\_visible\_to', 'request\.user', 'request\.user\.role', 'role', 'role\.firm\_admin'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:client\_list@19', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@20'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c3e28f76facce50d3181ff65b5f19b38d60621428ef43eeedabf3196391dcd5e |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-80\.

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

### 5.3. MANUAL\_REVIEW — python\.django\.security\.nan\-injection\.nan\-injection

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3e061f63b5f7aabe |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.nan\-injection\.nan\-injection |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 21 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; references=\['https\:\/\/discuss\.python\.org\/t\/nan\-breaks\-min\-max\-and\-sorting\-functions\-a\-solution\/2868', 'https\:\/\/blog\.bitdiscovery\.com\/2021\/12\/python\-nan\-injection\/'\]; technology=\['django'\] |
| Thời gian xử lý | 1011 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5da50a17e1840038ea75a9bf8ce4086c32d89da439ac3a9822a260dd20062315 |

**Thông báo của scanner**

> Found user input going directly into typecast for bool\(\), float\(\), or complex\(\)\. This allows an attacker to inject Python's not\-a\-number \(NaN\) into the typecast\. This results in undefind behavior, particularly when doing comparisons\. Either cast to a different type, or add a guard checking for all capitalizations of the string 'nan'\.

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

### 5.4. MANUAL\_REVIEW — python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 433577af30e6b786 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 176 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-295\: Improper Certificate Validation'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\-security', 'https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection'\]; technology=\['python'\] |
| Thời gian xử lý | 666 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1481e82e72e08f8e7482709f589964d2dc1a77a79c3664b6de53fad1b9b370dd |

**Thông báo của scanner**

> Unverified SSL context detected\. This will permit insecure connections without verifying SSL certificates\. Use 'ssl\.create\_default\_context' instead\.

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

### 5.5. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 575d42806de6a98333730f0a985d1d0b619af91f0f5dc724ffd5f73baf1962c5 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | cases\/views\_admin\.py |
| Dòng | 87 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=practice\_area\_edit; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:practice\_area\_edit@86', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@87'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d54787f15e1e9fe05cd28f450a51b691ef4955ab3b44148c3b619ac5584ce774 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 27\-147\.

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

### 5.6. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6a486b63a668c98c3d14cde21fad4b38855a0dbde2bc62eccb033bb00de07890 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 59 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=case\_delta\_125; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unvalidated\_domain\_value\_operation; source\_kind=http\_request\_parameter; trace=\['entrypoint\:case\_delta\_125@50', 'source\:http\_request\_parameter', 'sink\:unvalidated\_domain\_value\_operation@59'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | b49a9be1bf05eba8c7633b5b7c734874e9b1c4f20746b6c6678de4ffba3d1c26 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-119\.

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

### 5.7. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6aa4d357337fa5221e82a56417e6bcd4be2c7d92dbce6aad2691a74d3a9b3e28 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | accounts\/views\.py |
| Dòng | 254 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=invitation\_accept; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:invitation\_accept@252', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@254'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a276d7eb8476cdbd34cdaeb7a921ead3b865334db74339c882b55ec6f5214c7f |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 194\-285\.

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

### 5.8. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 84295e4a3f345d1cce587cd630bc2619dbb640d1ec5ec5f0e9edf290d2224750 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | accounts\/views\.py |
| Dòng | 206 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=invitation\_list; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:invitation\_list@205', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@206'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 96b0e9b5f286a23e303aa288ae6558b6208da815838a50c3ac6b33dabbfbe1fc |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 146\-266\.

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

### 5.9. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b6bbb9ee2d68a72a358bfc0265a51584cf6af0bbab7f6fbc619ed05170de9c14 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | accounts\/views\.py |
| Dòng | 96 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=user\_list; entrypoint\_exposed=True; guards=\['role', 'role\.choices'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:user\_list@93', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@96'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6da7d1c4b8f505a27e023058c5b0998cb532ca76ce9cc3ad6a3fb65d4a4fd83d |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 36\-156\.

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

### 5.10. MANUAL\_REVIEW — python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ce9ba9d812b1d94e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 73 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['django'\] |
| Thời gian xử lý | 663 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5a5666c4a17ec4fcd303b235f08e60d60877852e9dcd84c0f40495c134cf4a82 |

**Thông báo của scanner**

> Avoid using insecure deserialization library, backed by \`pickle\`, \`\_pickle\`, \`cpickle\`, \`dill\`, \`shelve\`, or \`yaml\`, which are known to lead to remote code execution vulnerabilities\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legal\_firm\/case\_operations\.py\:68; sink legal\_firm\/case\_operations\.py\:73; đường source–sink legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:71 → legal\_firm\/case\_operations\.py\:73 → legal\_firm\/case\_operations\.py\:73; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.11. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f3789a02e96c7be46e5cb9423d521fae8119f83cc9d895cd139a2c2bd3138783 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | accounts\/views\.py |
| Dòng | 70 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=notifications\_list; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:notifications\_list@69', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@70'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 01594da6823d265dcf411cdcfdfaa1484cb00cfd92763f15b10a76be7d0fd501 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 10\-130\.

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

### 5.12. MANUAL\_REVIEW — python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0c9b9f82d86b3075 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password |
| File | cases\/management\/commands\/seed\_minimal\.py |
| Dòng | 35 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-521\: Weak Password Requirements'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/\#module\-django\.contrib\.auth\.password\_validation'\]; technology=\['django'\] |
| Thời gian xử lý | 895 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8572654adf42e2fe00cb72b695e5e9c552e5747ce4b0863bdfeba82b2f9b2c40 |

**Thông báo của scanner**

> The password on 'user' is being set without validating the password\. Call django\.contrib\.auth\.password\_validation\.validate\_password\(\) with validation functions before setting the password\. See https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/ for more information\.

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

### 5.13. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 11da400b26c4935b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 177 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 442 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 16f1d53bb28774b0415a79a044e60320e384f43e19f6003bd9b8a01656cbbe94 |

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

### 5.14. MANUAL\_REVIEW — python\.django\.security\.audit\.avoid\-mark\-safe\.avoid\-mark\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 344948cec58684d7 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.avoid\-mark\-safe\.avoid\-mark\-safe |
| File | cases\/templatetags\/cases\_extras\.py |
| Dòng | 28 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/utils\/\#django\.utils\.safestring\.mark\_safe', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/utils\/\#django\.utils\.html\.format\_html'\]; technology=\['django'\] |
| Thời gian xử lý | 1089 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 307a896d1b5a502d0b62594b36440a58f109f2cfabd329e195a9c529d3eb1faa |

**Thông báo của scanner**

> 'mark\_safe\(\)' is used to mark a string as "safe" for HTML output\. This disables escaping and could therefore subject the content to XSS attacks\. Use 'django\.utils\.html\.format\_html\(\)' to build HTML for rendering instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source cases\/templatetags\/cases\_extras\.py\:19; sink cases\/templatetags\/cases\_extras\.py\:28; đường source–sink cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:19 → cases\/templatetags\/cases\_extras\.py\:20 → cases\/templatetags\/cases\_extras\.py\:24 → cases\/templatetags\/cases\_extras\.py\:27 → cases\/templatetags\/cases\_extras\.py\:27; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.15. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3a74b571c5185185 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/accounts\/password\_change\.html |
| Dòng | 12 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 390 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 94ed3a018593905cbe3b56f2052702145c6521f77188577e8574fefe3f04f8ef |

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

### 5.16. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 40a423bc63433cb3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/cases\/client\_form\.html |
| Dòng | 11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 413 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2ed17cf26e1463b30b464c93ba082a01cf3ef8e7bbb5815dabe508700b1d8229 |

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

### 5.17. MANUAL\_REVIEW — python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 47468ac65f7a3ddc |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.csrf\-exempt\.no\-csrf\-exempt |
| File | integrations\/api\_views\.py |
| Dòng | 29–41 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-352\: Cross\-Site Request Forgery \(CSRF\)'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['django'\] |
| Thời gian xử lý | 741 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | db2c3885a9c5962e20c24269861f85614309a970221723a4739789072130a5e2 |

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

### 5.18. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 491e5656f3773b16 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/accounts\/password\_reset\_confirm\.html |
| Dòng | 13 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 464 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8d49683873f2eb5d6595c606217aa4d3a699085e8cd2fddbbb201bc622823764 |

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

### 5.19. MANUAL\_REVIEW — python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 51d5966db87aa871 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 32 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/http\/shortcuts\/\#render', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/security\/\#cross\-site\-scripting\-xss\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 698 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7f319ba88d4324dae65178edb236a752001d83f78cacbaffbae34269e7ec74f7 |

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

### 5.20. MANUAL\_REVIEW — python\.lang\.security\.audit\.eval\-detected\.eval\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 63e619b0203cf1e5 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.eval\-detected\.eval\-detected |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 87 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 583 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e89dd46972d58f9bac1abd7764a590a8e14ead3c48285cd560cb017a246545cc |

**Thông báo của scanner**

> Detected the use of eval\(\)\. eval\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legal\_firm\/case\_operations\.py\:21; sink legal\_firm\/case\_operations\.py\:87; đường source–sink legal\_firm\/case\_operations\.py\:21 → legal\_firm\/case\_operations\.py\:84 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:87 → legal\_firm\/case\_operations\.py\:87; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.21. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8cf2357c7de20a0a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href |
| File | templates\/accounts\/notifications\.html |
| Dòng | 15 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss\#\:\~\:text\=javascript\:%20URI', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.1\/ref\/templates\/builtins\/\#url', 'https\:\/\/github\.com\/pugjs\/pug\/issues\/2952', 'https\:\/\/content\-security\-policy\.com\/'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 512 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 69a19a98016981af013cb5dee896027807b3e230d3ee1d0c1d423300dc5ec77b |

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

### 5.22. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9c933c1c86c1d9c2 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 73 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 630 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0872df0eb6835db062a6aa106f039047edd1a2825b69d7e48f88a8a1889e571e |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legal\_firm\/case\_operations\.py\:68; sink legal\_firm\/case\_operations\.py\:73; đường source–sink legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:68 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:70 → legal\_firm\/case\_operations\.py\:71 → legal\_firm\/case\_operations\.py\:73 → legal\_firm\/case\_operations\.py\:73; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.23. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ab36f46117ca1cba |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/cases\/document\_form\.html |
| Dòng | 11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 477 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e7af323c01f45ca188c25a1abb6099864e98ef7922fcd5c9e6208af7a5785406 |

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

### 5.24. MANUAL\_REVIEW — python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c1d7e827a92bf449 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password |
| File | cases\/management\/commands\/seed\_demo\.py |
| Dòng | 175 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-521\: Weak Password Requirements'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/\#module\-django\.contrib\.auth\.password\_validation'\]; technology=\['django'\] |
| Thời gian xử lý | 1074 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | af80508c5a5da60d341b8d19a30b8ccc719b15318d2cbc4c0e5c1563fe2f898b |

**Thông báo của scanner**

> The password on 'user' is being set without validating the password\. Call django\.contrib\.auth\.password\_validation\.validate\_password\(\) with validation functions before setting the password\. See https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/ for more information\.

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

### 5.25. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c4b4be7343ed73ae |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/accounts\/user\_create\.html |
| Dòng | 11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 436 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9843c6ce894472499fc35fafdf72879fda639c674f81f183728d894d322b577a |

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

### 5.26. MANUAL\_REVIEW — python\.django\.security\.injection\.code\.user\-eval\.user\-eval

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c775b835c1d4651e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.code\.user\-eval\.user\-eval |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 86–87 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nedbatchelder\.com\/blog\/201206\/eval\_really\_is\_dangerous\.html', 'https\:\/\/owasp\.org\/www\-community\/attacks\/Code\_Injection'\]; technology=\['django'\] |
| Thời gian xử lý | 646 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9d17fa07739e4e0fc8d70887065c1532481d12bbbc068bec46adc5ec08fc4e99 |

**Thông báo của scanner**

> Found user data in a call to 'eval'\. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system\. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legal\_firm\/case\_operations\.py\:21; sink legal\_firm\/case\_operations\.py\:87; đường source–sink legal\_firm\/case\_operations\.py\:21 → legal\_firm\/case\_operations\.py\:84 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:86 → legal\_firm\/case\_operations\.py\:87 → legal\_firm\/case\_operations\.py\:87; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.27. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cd4f4b8fdfbd454b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/cases\/firm\_settings\.html |
| Dòng | 11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 479 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 90539ddf14d2e6973b5d1f05b6e1438a21212b2d71f03a7519c46e8df25ab8ef |

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

### 5.28. MANUAL\_REVIEW — python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d93aab13c39c8123 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie |
| File | legal\_firm\/case\_operations\.py |
| Dòng | 95 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-614\: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/request\-response\/\#django\.http\.HttpResponse\.set\_cookie', 'https\:\/\/semgrep\.dev\/blog\/2020\/bento\-check\-keeping\-cookies\-safe\-in\-flask\/', 'https\:\/\/bento\.dev\/checks\/flask\/secure\-set\-cookie\/'\]; technology=\['django'\] |
| Thời gian xử lý | 651 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9b8080a21f94ee7b75ab050dbc8440eabfee5cd7c9f7a1b7c838d0c28755d0e2 |

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

### 5.29. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | eb0a8b06787b7ab4 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | templates\/cases\/matter\_form\.html |
| Dòng | 11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 436 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 32d14100286ea8b3bffd030557135e8375221175d089e6f8b5dcf00c09afe294 |

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

## 6. Lỗi scanner
- Không có lỗi scanner.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
