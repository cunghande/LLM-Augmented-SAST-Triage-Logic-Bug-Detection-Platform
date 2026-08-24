# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 19 |
| Triage thành công | 19 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 4\.483949 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 19 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 5690d0b1\-be10\-4c10\-9951\-fdb4a7fcc156 |
| Repository | repository |
| Repository identifier | vc\-kimi\-code\-seeded\-v2\-fintech\-lending\-fastapi |
| Commit | 50a3098d1779c4fc1c71d5fe5253566f59b6f9f6 |
| Trạng thái working tree | dirty |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 18\.726435 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-24T02\:51\:12\.949176\+00\:00 |
| Kết thúc | 2026\-08\-24T02\:51\:17\.433125\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=61d58dc0bbd4da78f5a9d9e91510835fe5223c5006fe21c41692425d370c1454

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 17010e85fa044381dc89c000fb1315b7d37284075da6e9d5dd1a9ae93b305f02 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/applications\.py\:65 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 205664f6229c5641befe2faa4a8b0982b05e66513afa92ee4ade9049c4707841 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/documents\.py\:55 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 28aa0b880e1ec3841900b6674ab2f012564d5caf425bf561f93ba42a3c1862a2 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/messages\.py\:29 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 363eeed330142adb6362f4b4cbf24d00c993d7aef060178e943921664de07f1b | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/documents\.py\:30 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | 36cd7bb9e148b0c5b57cddfebee2a2ca90239dc9cd870d37eea4832d0437f682 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/admin\.py\:26 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | 661fe63fe8d4de3d0a9faea9712932e1784afba93b13d063d893f53edc1f9c5d | module2\.logic\.missing\-authz\-idor | backend\/app\/loan\_operations\.py\:25 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | HIGH | 70216533bc393446e64ef7c99081f99d6252e042081daef494da33b6dc6a9498 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/api\_keys\.py\:21 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 88ea1b2df85e03d684859e878ef46a49a53042800598d83ddb898fb4fb035aa8 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/api\_keys\.py\:53 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | HIGH | 8ad18e4f636301f8cbd0c7efc7e014d68435d1a5f22ac62624813fb112639bc8 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/notes\.py\:34 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | HIGH | 8d80bc5ab84aa22feef7e3413c44b8ec2d8a6dc30afa613b4a260f5d30a5d611 | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/users\.py\:33 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | HIGH | a12be4619075f923 | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context | backend\/app\/loan\_operations\.py\:144 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | HIGH | a4b680532d430bd56c5d8007eefc4be27fbb4c39c3c217b83447048064dc8364 | module2\.logic\.missing\-authz\-idor | backend\/app\/routers\/auth\.py\:76 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | HIGH | b35b5735b66e5327863aa450a1fbc25602b7ce76cd47446da6b1f5ed6c730658 | module2\.logic\.business\-rule\-bypass | backend\/app\/loan\_operations\.py\:49 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | HIGH | bb030d1ce4cd845dd62d23f3ddd56803d9502816971189b49559b187f27a5d3b | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/audit\.py\:42 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | HIGH | bf36bf228bf93bf76f20ae84fe7999c3ba89e7ef65d0c2cd79be6b1e0ff2876b | module2\.logic\.business\-rule\-bypass | backend\/app\/routers\/admin\.py\:59 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 16 | MANUAL\_REVIEW | HIGH | f333b8cfd46eea277624c67688641c8d7f95f475a0d86c630ade6ffb5db72c86 | module2\.logic\.missing\-authz\-idor | backend\/app\/routers\/api\_keys\.py\:84 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 17 | MANUAL\_REVIEW | MEDIUM | 184adc28160c0a1b | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | backend\/app\/loan\_operations\.py\:40 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 18 | MANUAL\_REVIEW | MEDIUM | 34169d38faf8270b | python\.lang\.security\.audit\.eval\-detected\.eval\-detected | backend\/app\/loan\_operations\.py\:66 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 19 | MANUAL\_REVIEW | MEDIUM | c42b7ee72c0d4de8 | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | backend\/app\/loan\_operations\.py\:145 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 17010e85fa044381dc89c000fb1315b7d37284075da6e9d5dd1a9ae93b305f02 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/applications\.py |
| Dòng | 65 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_applications; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'userrole', 'userrole\.admin', 'userrole\.borrower', 'userrole\.support\_specialist', 'userrole\.underwriter'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_applications@28', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@65'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 27 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 66463ed260faaa634d144a2f6b014fc3f28760638db0817fdae1fc89af3939be |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 5\-125\.

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
| Finding ID | 205664f6229c5641befe2faa4a8b0982b05e66513afa92ee4ade9049c4707841 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/documents\.py |
| Dòng | 55 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_documents; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'userrole', 'userrole\.admin', 'userrole\.borrower', 'userrole\.support\_specialist', 'userrole\.underwriter'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_documents@34', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@55'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 27 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7698f12792f848dbe62de6e1780a6275561a97460f08a4ac13b881cad576b806 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-115\.

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

### 5.3. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 28aa0b880e1ec3841900b6674ab2f012564d5caf425bf561f93ba42a3c1862a2 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/messages\.py |
| Dòng | 29 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_messages; entrypoint\_exposed=True; guards=\['app\.borrower\_profile\.user\_id', 'current\_user', 'current\_user\.id', 'current\_user\.role', 'userrole', 'userrole\.borrower', 'userrole\.support\_specialist'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_messages@16', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@29'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 25 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7c0a0984f1d466a94bb75928e70e94206d368f3b842ad219c57af64de6c2e3a9 |

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

### 5.4. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 363eeed330142adb6362f4b4cbf24d00c993d7aef060178e943921664de07f1b |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/documents\.py |
| Dòng | 30 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_document\_types; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_document\_types@29', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@30'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 29 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 609e9d604f2c540eb35246f9535ef4da0cc6e901823a2c65a2a31c7313203f14 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-90\.

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

### 5.5. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 36cd7bb9e148b0c5b57cddfebee2a2ca90239dc9cd870d37eea4832d0437f682 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/admin\.py |
| Dòng | 26 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_products; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'userrole', 'userrole\.admin'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_products@23', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@26'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 31 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6c1a6c24bb6aa58bc4535feaf8ffd57fa0c4ca54c7c1454321e47a41d1ea1817 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-86\.

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
| Finding ID | 661fe63fe8d4de3d0a9faea9712932e1784afba93b13d063d893f53edc1f9c5d |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 25 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=lendfolio\_marker\_097; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:lendfolio\_marker\_097@23', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@25'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 24 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4f2f0a1eaf31973647d729270095c82ae6933c1b924a9fdff5de9d37cad36be9 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-85\.

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

### 5.7. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 70216533bc393446e64ef7c99081f99d6252e042081daef494da33b6dc6a9498 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/api\_keys\.py |
| Dòng | 21 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_api\_keys; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_api\_keys@20', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@21'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 32 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0561a876757853c207490734158bd3e646e9e82fdafa74a2066088cbb7102064 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-81\.

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
| Finding ID | 88ea1b2df85e03d684859e878ef46a49a53042800598d83ddb898fb4fb035aa8 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/api\_keys\.py |
| Dòng | 53 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_webhooks; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_webhooks@52', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@53'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 29 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | ae9164ff9c1ad1d9a0dad41d9f3487d3c0db1801e2c3871867721d43ed7c0354 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-91\.

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
| Finding ID | 8ad18e4f636301f8cbd0c7efc7e014d68435d1a5f22ac62624813fb112639bc8 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/notes\.py |
| Dòng | 34 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_notes; entrypoint\_exposed=True; guards=\['app\.borrower\_profile\.user\_id', 'current\_user', 'current\_user\.id', 'current\_user\.role', 'userrole', 'userrole\.borrower'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_notes@25', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@34'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 27 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | cd00859ee38d49ce3211e382476849eb34a8dd11ff13c1bd5ce92f7a54df9d1b |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-62\.

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

### 5.10. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8d80bc5ab84aa22feef7e3413c44b8ec2d8a6dc30afa613b4a260f5d30a5d611 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/users\.py |
| Dòng | 33 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_users; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'role', 'userrole', 'userrole\.admin'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_users@13', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@33'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 38 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0eab5c0ea465992c719331dfeba730a50646e7125c2e12e8f837efb7d3ee5eef |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-93\.

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

### 5.11. MANUAL\_REVIEW — python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a12be4619075f923 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 144 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-295\: Improper Certificate Validation'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\-security', 'https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection'\]; technology=\['python'\] |
| Thời gian xử lý | 809 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 39b543bea02ef840de40422be6f73bad189b206ff5174ca893b2b6458aa9e476 |

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

### 5.12. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a4b680532d430bd56c5d8007eefc4be27fbb4c39c3c217b83447048064dc8364 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routers\/auth\.py |
| Dòng | 76 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=password\_reset\_confirm; entrypoint\_exposed=True; guards=\['user', 'user\.password\_reset\_expires'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:password\_reset\_confirm@75', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@76'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 34 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 434bc26aeecccc719cef7009464f50a49a52cc204711ecf888ced881be9ac8fd |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 16\-84\.

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

### 5.13. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b35b5735b66e5327863aa450a1fbc25602b7ce76cd47446da6b1f5ed6c730658 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 49 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=loan\_delta\_140; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unvalidated\_domain\_value\_operation; source\_kind=http\_request\_body; trace=\['entrypoint\:loan\_delta\_140@45', 'source\:http\_request\_body', 'sink\:unvalidated\_domain\_value\_operation@49'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 28 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e1d4ad0686238b765134a77fc243b419d29c6f3fdd7d4b8fab13979e31adfb9d |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-109\.

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

### 5.14. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | bb030d1ce4cd845dd62d23f3ddd56803d9502816971189b49559b187f27a5d3b |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/audit\.py |
| Dòng | 42 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_audit\_logs; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'user\_id', 'userrole', 'userrole\.admin'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_pagination\_parameter; source\_kind=http\_route\_parameter; trace=\['entrypoint\:list\_audit\_logs@15', 'source\:http\_route\_parameter', 'sink\:unbounded\_pagination\_parameter@42'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 28 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a3b7bbdb63c17ac9013348b615f617e1c950f9f7b9e6b75434244ae8a19b23dc |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-52\.

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

### 5.15. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | bf36bf228bf93bf76f20ae84fe7999c3ba89e7ef65d0c2cd79be6b1e0ff2876b |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routers\/admin\.py |
| Dòng | 59 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_document\_types; entrypoint\_exposed=True; guards=\['current\_user', 'current\_user\.role', 'userrole', 'userrole\.admin'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_document\_types@56', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@59'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 32 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e609fc34abc0098604bdee102fd51efd316edd9e8d0496ede758c5a7400b118a |

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

### 5.16. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f333b8cfd46eea277624c67688641c8d7f95f475a0d86c630ade6ffb5db72c86 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routers\/api\_keys\.py |
| Dòng | 84 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=get\_application\_status\_api; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:get\_application\_status\_api@82', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@84'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 41 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 17e241d4749ce98576036d8b68eb5753c73c12022773a26a28227ebe7c93e666 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 24\-91\.

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

### 5.17. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 184adc28160c0a1b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 40 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 977 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 087b0e7178873694fe05662814d6ee294c485231e166c13ec8ff944104caf8cb |

**Thông báo của scanner**

> Detected a dynamic value being used with urllib\. urllib supports 'file\:\/\/' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files\. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink backend\/app\/loan\_operations\.py\:40; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.18. MANUAL\_REVIEW — python\.lang\.security\.audit\.eval\-detected\.eval\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 34169d38faf8270b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.eval\-detected\.eval\-detected |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 66 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 1035 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 21fde0f74f2110aecf6b55ee08423064e2d174ed9b2507ca3d0f43acf97d3f28 |

**Thông báo của scanner**

> Detected the use of eval\(\)\. eval\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink backend\/app\/loan\_operations\.py\:66; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.19. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c42b7ee72c0d4de8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | backend\/app\/loan\_operations\.py |
| Dòng | 145 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 995 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 159944b6e91508c28c2fd7f6f946e1ae897c10afd7e99e873a177b32a61b389a |

**Thông báo của scanner**

> Detected a dynamic value being used with urllib\. urllib supports 'file\:\/\/' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files\. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink backend\/app\/loan\_operations\.py\:145; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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
