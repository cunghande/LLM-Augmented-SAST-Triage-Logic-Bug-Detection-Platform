# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 15 |
| Triage thành công | 15 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 7\.249643 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 15 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 1db5ba7c\-6d6d\-4de2\-8d50\-05d6d93f3dc4 |
| Repository | repository |
| Repository identifier | vc\-codex\-high\-seeded\-v2\-legal\-case\-django |
| Commit | de226f147618ddffcc69e5f1a81ae8c7fc83a84f |
| Trạng thái working tree | dirty |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 16\.91067 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-24T02\:39\:37\.001877\+00\:00 |
| Kết thúc | 2026\-08\-24T02\:39\:44\.251520\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=c83989507e509269b03551f9589b5fba8ea58fd4f31cf2757ad35f2218b2e919

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 1662e45dd0030de31f222809e68467ce3decb999a68e4335270fa0343c093ede | module2\.logic\.missing\-authz\-idor | cases\/views\.py\:211 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 5507b72324349491 | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context | legalcase\/case\_operations\.py\:191 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 63a5ce1fe01c17619df2ab08db510f67cf176a0cfefd5abd9b68f1fee38514f5 | module2\.logic\.business\-rule\-bypass | legalcase\/case\_operations\.py\:59 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 733da4878f26f17991e79cd718f4e3a8e0f4d9329f742cc321d1968ca38091b3 | module2\.logic\.business\-rule\-bypass | cases\/views\.py\:885 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | b6dbcc3aec63728e | python\.django\.security\.nan\-injection\.nan\-injection | legalcase\/case\_operations\.py\:21 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | df08efdf312c15b4 | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization | legalcase\/case\_operations\.py\:73 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | MEDIUM | 0345b6a895de9662 | python\.django\.security\.django\-using\-request\-post\-after\-is\-valid\.django\-using\-request\-post\-after\-is\-valid | cases\/views\.py\:435 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | MEDIUM | 1110e1490b05d3d9 | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | legalcase\/case\_operations\.py\:192 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | MEDIUM | 2186d6beee56581f | python\.django\.security\.injection\.code\.user\-eval\.user\-eval | legalcase\/case\_operations\.py\:86–87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | MEDIUM | 2b7f7606c10ea731 | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format | legalcase\/case\_operations\.py\:32 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | MEDIUM | 4cb5c4d84fd27c43 | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password | cases\/management\/commands\/seed\_legal\_data\.py\:87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | MEDIUM | 5a4eadc2aa21d95e | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | legalcase\/case\_operations\.py\:73 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | 909ca512b407fb77 | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href | cases\/templates\/cases\/form\_page\.html\:9 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | MEDIUM | ba69fa4e7714e169 | python\.lang\.security\.audit\.eval\-detected\.eval\-detected | legalcase\/case\_operations\.py\:87 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | MEDIUM | e28afad269a2f09e | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie | legalcase\/case\_operations\.py\:95 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1662e45dd0030de31f222809e68467ce3decb999a68e4335270fa0343c093ede |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | cases\/views\.py |
| Dòng | 211 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=accept\_invite; entrypoint\_exposed=True; guards=\['invite\.role', 'role', 'role\.client'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:accept\_invite@210', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@211'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 20 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 97841aeb6489ec515401f5116663a10823ec7fe3783af1f2e40a9e01689c6641 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 151\-271\.

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

### 5.2. MANUAL\_REVIEW — python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5507b72324349491 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context |
| File | legalcase\/case\_operations\.py |
| Dòng | 191 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-295\: Improper Certificate Validation'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\-security', 'https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection'\]; technology=\['python'\] |
| Thời gian xử lý | 499 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 736dcaeb43ed2d6b982e75e2094ee00017690d1135a42173173a49165f06a136 |

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

### 5.3. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 63a5ce1fe01c17619df2ab08db510f67cf176a0cfefd5abd9b68f1fee38514f5 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | legalcase\/case\_operations\.py |
| Dòng | 59 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=case\_delta\_137; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unvalidated\_domain\_value\_operation; source\_kind=http\_request\_parameter; trace=\['entrypoint\:case\_delta\_137@50', 'source\:http\_request\_parameter', 'sink\:unvalidated\_domain\_value\_operation@59'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 15 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d4e54dfbf3faccdc45d0ae25f49ab843cc45ecfebb1254eb749ae335ba03fcf5 |

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

### 5.4. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 733da4878f26f17991e79cd718f4e3a8e0f4d9329f742cc321d1968ca38091b3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | cases\/views\.py |
| Dòng | 885 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=admin\_practice\_areas; entrypoint\_exposed=True; guards=\['require\_role'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:admin\_practice\_areas@877', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@885'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 16 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0bf1fcb253a663de58b4dcf3b3d2eb742b68b3a01d76374e86506a840cb9a7cd |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 825\-945\.

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

### 5.5. MANUAL\_REVIEW — python\.django\.security\.nan\-injection\.nan\-injection

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b6dbcc3aec63728e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.nan\-injection\.nan\-injection |
| File | legalcase\/case\_operations\.py |
| Dòng | 21 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; references=\['https\:\/\/discuss\.python\.org\/t\/nan\-breaks\-min\-max\-and\-sorting\-functions\-a\-solution\/2868', 'https\:\/\/blog\.bitdiscovery\.com\/2021\/12\/python\-nan\-injection\/'\]; technology=\['django'\] |
| Thời gian xử lý | 697 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | af40600e5e473f26a5b54c61a8db8bb2b0824be95f4839fb39862ed992de0e8c |

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

### 5.6. MANUAL\_REVIEW — python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | df08efdf312c15b4 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization |
| File | legalcase\/case\_operations\.py |
| Dòng | 73 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['django'\] |
| Thời gian xử lý | 846 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9447f465a8e68e91f95fd177fedfb13036cca30318d225f73916ec4078d09f41 |

**Thông báo của scanner**

> Avoid using insecure deserialization library, backed by \`pickle\`, \`\_pickle\`, \`cpickle\`, \`dill\`, \`shelve\`, or \`yaml\`, which are known to lead to remote code execution vulnerabilities\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legalcase\/case\_operations\.py\:68; sink legalcase\/case\_operations\.py\:73; đường source–sink legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:71 → legalcase\/case\_operations\.py\:73 → legalcase\/case\_operations\.py\:73; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.7. MANUAL\_REVIEW — python\.django\.security\.django\-using\-request\-post\-after\-is\-valid\.django\-using\-request\-post\-after\-is\-valid

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0345b6a895de9662 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-using\-request\-post\-after\-is\-valid\.django\-using\-request\-post\-after\-is\-valid |
| File | cases\/views\.py |
| Dòng | 435 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-20\: Improper Input Validation; references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/ref\/forms\/api\/\#accessing\-clean\-data'\]; technology=\['django'\] |
| Thời gian xử lý | 1021 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 692c3a4a6c5619833f206dfb0ea360965d73199e5353490da830564ade85d6f2 |

**Thông báo của scanner**

> Use form\.cleaned\_data\[\] instead of request\.POST\[\] after form\.is\_valid\(\) has been executed to only access sanitized data

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

### 5.8. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1110e1490b05d3d9 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | legalcase\/case\_operations\.py |
| Dòng | 192 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 491 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | cc5259571a5c77112d2993c89b84dadcef1251e076f3ebc48472dbcc180fb17d |

**Thông báo của scanner**

> Detected a dynamic value being used with urllib\. urllib supports 'file\:\/\/' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files\. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink legalcase\/case\_operations\.py\:192; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.9. MANUAL\_REVIEW — python\.django\.security\.injection\.code\.user\-eval\.user\-eval

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2186d6beee56581f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.code\.user\-eval\.user\-eval |
| File | legalcase\/case\_operations\.py |
| Dòng | 86–87 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/nedbatchelder\.com\/blog\/201206\/eval\_really\_is\_dangerous\.html', 'https\:\/\/owasp\.org\/www\-community\/attacks\/Code\_Injection'\]; technology=\['django'\] |
| Thời gian xử lý | 660 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2b9b501daa112dfa7401752363c7fb1b0d7d7448ed1f4feb6608fab667c74029 |

**Thông báo của scanner**

> Found user data in a call to 'eval'\. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system\. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legalcase\/case\_operations\.py\:21; sink legalcase\/case\_operations\.py\:87; đường source–sink legalcase\/case\_operations\.py\:21 → legalcase\/case\_operations\.py\:84 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:87 → legalcase\/case\_operations\.py\:87; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.10. MANUAL\_REVIEW — python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2b7f7606c10ea731 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.raw\-html\-format\.raw\-html\-format |
| File | legalcase\/case\_operations\.py |
| Dòng | 32 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/http\/shortcuts\/\#render', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.2\/topics\/security\/\#cross\-site\-scripting\-xss\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 631 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2e908fc747ddb5b327e85fa26459768153f51730097739fea70ffe62346aac85 |

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

### 5.11. MANUAL\_REVIEW — python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4cb5c4d84fd27c43 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password |
| File | cases\/management\/commands\/seed\_legal\_data\.py |
| Dòng | 87 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-521\: Weak Password Requirements'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/\#module\-django\.contrib\.auth\.password\_validation'\]; technology=\['django'\] |
| Thời gian xử lý | 957 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 56ecfeb7b6d3df6b11806dbf55064b43228924cb2fa6b053f9a0dbfadd8eab45 |

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

### 5.12. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5a4eadc2aa21d95e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | legalcase\/case\_operations\.py |
| Dòng | 73 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 645 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 32b93bc21019bea6a1dabca56807fba30c2a6467fbe66a461b39a8d3cd5f1ac6 |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legalcase\/case\_operations\.py\:68; sink legalcase\/case\_operations\.py\:73; đường source–sink legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:68 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:70 → legalcase\/case\_operations\.py\:71 → legalcase\/case\_operations\.py\:73 → legalcase\/case\_operations\.py\:73; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.13. MANUAL\_REVIEW — generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 909ca512b407fb77 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.html\-templates\.security\.var\-in\-href\.var\-in\-href |
| File | cases\/templates\/cases\/form\_page\.html |
| Dòng | 9 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss\#\:\~\:text\=javascript\:%20URI', 'https\:\/\/docs\.djangoproject\.com\/en\/3\.1\/ref\/templates\/builtins\/\#url', 'https\:\/\/github\.com\/pugjs\/pug\/issues\/2952', 'https\:\/\/content\-security\-policy\.com\/'\]; technology=\['html\-templates'\] |
| Thời gian xử lý | 20 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 955cf8b72c052f20c171b768fe0ef9d264d0700df6e9241b6f5ed4ca9fd62771 |

**Thông báo của scanner**

> Detected a template variable used in an anchor tag with the 'href' attribute\. This allows a malicious actor to input the 'javascript\:' URI and is subject to cross\- site scripting \(XSS\) attacks\. If using Flask, use 'url\_for\(\)' to safely generate a URL\. If using Django, use the 'url' filter to safely generate a URL\. If using Mustache, use a URL encoding library, or prepend a slash '\/' to the variable for relative links \(\`href\="\/\{\{link\}\}"\`\)\. You may also consider setting the Content Security Policy \(CSP\) header\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-12, đã bị cắt bớt\.

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

### 5.14. MANUAL\_REVIEW — python\.lang\.security\.audit\.eval\-detected\.eval\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ba69fa4e7714e169 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.eval\-detected\.eval\-detected |
| File | legalcase\/case\_operations\.py |
| Dòng | 87 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 474 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | dce3d34b5201605f34c4535205c81c96cbd2c6540883a8422fb65808d4afb8f1 |

**Thông báo của scanner**

> Detected the use of eval\(\)\. eval\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source legalcase\/case\_operations\.py\:21; sink legalcase\/case\_operations\.py\:87; đường source–sink legalcase\/case\_operations\.py\:21 → legalcase\/case\_operations\.py\:84 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:86 → legalcase\/case\_operations\.py\:87 → legalcase\/case\_operations\.py\:87; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.15. MANUAL\_REVIEW — python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e28afad269a2f09e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.secure\-cookies\.django\-secure\-set\-cookie |
| File | legalcase\/case\_operations\.py |
| Dòng | 95 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-614\: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/ref\/request\-response\/\#django\.http\.HttpResponse\.set\_cookie', 'https\:\/\/semgrep\.dev\/blog\/2020\/bento\-check\-keeping\-cookies\-safe\-in\-flask\/', 'https\:\/\/bento\.dev\/checks\/flask\/secure\-set\-cookie\/'\]; technology=\['django'\] |
| Thời gian xử lý | 101 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8e60f0f089f3b5afa4caeebbf560a11b8e076458fdf4a4ca9b7d936c2224db30 |

**Thông báo của scanner**

> Django cookies should be handled securely by setting secure\=True, httponly\=True, and samesite\='Lax' in response\.set\_cookie\(\.\.\.\)\. If your situation calls for different settings, explicitly disable the setting\. If you want to send the cookie over http, set secure\=False\. If you want to let client\-side JavaScript read the cookie, set httponly\=False\. If you want to attach cookies to requests for external sites, set samesite\=None\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source không áp dụng; sink legalcase\/case\_operations\.py\:95; đường source–sink không yêu cầu cho cơ chế này; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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
