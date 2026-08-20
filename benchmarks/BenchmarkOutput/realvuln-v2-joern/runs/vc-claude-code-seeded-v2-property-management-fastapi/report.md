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
| Thời gian toàn run (giây) | 5\.026791 |

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
| Run ID | d4411d31\-c66f\-4766\-bbe4\-1cbc2c3f6e99 |
| Repository | vc\-claude\-code\-seeded\-v2\-property\-management\-fastapi |
| Repository identifier | vc\-claude\-code\-seeded\-v2\-property\-management\-fastapi |
| Commit | 001737a4c9f94ab57bec0635509b8a745a3d0482 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 20\.536512 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:56\:56\.401278\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:57\:01\.428069\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=8501ce32b1a5ae0b03f06fa0254ba706562c5bfc9538f429d17871d07ceadc0f

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 0fabca946eed124e4d2109c4d6f922100ffa63f93cbd5201a596de15095b5755 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/properties\.py\:84 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 0fe219c6f5e2a99161f8514a0b9493559818934d732112758a5c861d20e2c214 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/auth\.py\:170 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 1dff60d711c79272d1e204edca418f4947b2972017dfb33d576748074ccb91a0 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/users\.py\:119 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 35a26f7a658bedcbfe3a130d8a2b3cc8072d87a174cc889e6a47f4552042c9aa | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/audit\.py\:34 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | 53aadb27e82ebc3d4eb8baf156c14fcb181c7eb0712500b98f127f21fdf7ddd3 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/tickets\.py\:215 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | 57fc78bd8837cc74f679d6784cddab556c1567c4d95b816c78e81bd50bf6f249 | module2\.logic\.business\-rule\-bypass | backend\/app\/routes\/integrations\.py\:22 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | HIGH | 5f46fa2b6e02dab0 | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context | backend\/app\/tenant\_operations\.py\:129 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 66dc8769369576b819726f2cffa1b9e63ed42b7426829e544c37729afcac89d1 | module2\.logic\.missing\-authz\-idor | backend\/app\/tenant\_operations\.py\:25 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | HIGH | 70aa01f7441827cfb0dad14d65c9af2351b0239dd1d65766a238154b36e3a714 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/tickets\.py\:168 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | HIGH | a07e5a7e0aa8f790bf7b1c6206cd978571ece45567df87c810a38094dd62b6f6 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/properties\.py\:170 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | HIGH | a48b7f6f6dd6fe4fbd7ca2f9d3b09746f98feef24548e536e919810f37fea4c5 | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/imports\_exports\.py\:208 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | HIGH | b9c579d4cdcaacbef58215b45970fc003dc9d47820b7381034421b385a676fd3 | module2\.logic\.business\-rule\-bypass | backend\/app\/routes\/integrations\.py\:57 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | HIGH | d26e5612ec32d696514aa602c54f912b3c02be125a43b84e40df043fff1ac8ed | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/properties\.py\:97 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | HIGH | d8931e41f7277b30426e0bed85fe24782c02b45bdca13019c070be402679b7de | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/tickets\.py\:220 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | HIGH | e14932b572c31220b75f1c01d2bd0eec2647ddca161caf0531439feb07632f4e | module2\.logic\.missing\-authz\-idor | backend\/app\/routes\/inspections\.py\:84 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 16 | MANUAL\_REVIEW | HIGH | fc2ab9ec95aa327cc7ddb86cd2c27213ec8e65172ada409323894a6b0cd45098 | module2\.logic\.business\-rule\-bypass | backend\/app\/routes\/audit\.py\:39 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 17 | MANUAL\_REVIEW | MEDIUM | 00299cffac55c426 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | backend\/app\/tenant\_operations\.py\:66 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 18 | MANUAL\_REVIEW | MEDIUM | 509b9c2018893c2a | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | backend\/app\/tenant\_operations\.py\:40 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 19 | MANUAL\_REVIEW | MEDIUM | d0f53d2b0153c20e | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected | backend\/app\/tenant\_operations\.py\:130 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0fabca946eed124e4d2109c4d6f922100ffa63f93cbd5201a596de15095b5755 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/properties\.py |
| Dòng | 84 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=update\_property; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:update\_property@83', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@84'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 56ccf1fda16a5a621160404f127659213b916e560a847fec19126bf03f3f20ba |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 24\-144\.

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

### 5.2. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0fe219c6f5e2a99161f8514a0b9493559818934d732112758a5c861d20e2c214 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/auth\.py |
| Dòng | 170 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=reset\_complete; entrypoint\_exposed=True; guards=\['user', 'user\.is\_active'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:reset\_complete@168', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@170'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7ca4a6fad6289cbb0d92963ec5a5e498ee06cfe312aa2b041946335f947fd55f |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 110\-184\.

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

### 5.3. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1dff60d711c79272d1e204edca418f4947b2972017dfb33d576748074ccb91a0 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/users\.py |
| Dòng | 119 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=assign\_manager\_properties; entrypoint\_exposed=True; guards=\['role', 'role\.property\_manager', 'target\.role'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:assign\_manager\_properties@115', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@119'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f30084c176f5280f518d4d956f523e5c8313919f69561f4da256e91c6154eb88 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 59\-140\.

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

### 5.4. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 35a26f7a658bedcbfe3a130d8a2b3cc8072d87a174cc889e6a47f4552042c9aa |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/audit\.py |
| Dòng | 34 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=list\_audit; entrypoint\_exposed=True; guards=\['actor\_id'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:list\_audit@19', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@34'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6b1f53a62fb728fbb29022f1887db9428faababf0c0a0efeada22e94db55251f |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-39\.

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
| Finding ID | 53aadb27e82ebc3d4eb8baf156c14fcb181c7eb0712500b98f127f21fdf7ddd3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/tickets\.py |
| Dòng | 215 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=assign\_ticket; entrypoint\_exposed=True; guards=\['role', 'role\.maintenance\_worker', 'target\.role', 'user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:assign\_ticket@214', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@215'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 5 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 102b3e1b652dfed4c627d7aee6b53514d03f9a5edba2733997c062b0b419ceb7 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 155\-271, đã bị cắt bớt\.

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

### 5.6. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 57fc78bd8837cc74f679d6784cddab556c1567c4d95b816c78e81bd50bf6f249 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routes\/integrations\.py |
| Dòng | 22 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_keys; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_keys@21', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@22'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c36ac680c2dc9b917d0918cd60ad93a85974fff09f48df70b34190fb4f0d5795 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-82\.

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

### 5.7. MANUAL\_REVIEW — python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5f46fa2b6e02dab0 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.unverified\-ssl\-context\.unverified\-ssl\-context |
| File | backend\/app\/tenant\_operations\.py |
| Dòng | 129 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-295\: Improper Certificate Validation'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\-security', 'https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection'\]; technology=\['python'\] |
| Thời gian xử lý | 1077 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 10f426fc3b8f1c5fd1d853351aec3e0148a7b999c3bac24a84f0209873de6b1e |

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

### 5.8. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 66dc8769369576b819726f2cffa1b9e63ed42b7426829e544c37729afcac89d1 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/tenant\_operations\.py |
| Dòng | 25 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=tenant\_ledger\_tile\_025; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:tenant\_ledger\_tile\_025@23', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@25'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 244833e0cb31e66f196c534aaeac382e8c0a3a994a77c0bd5203fd6fe246e7f1 |

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

### 5.9. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 70aa01f7441827cfb0dad14d65c9af2351b0239dd1d65766a238154b36e3a714 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/tickets\.py |
| Dòng | 168 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=update\_ticket; entrypoint\_exposed=True; guards=\['user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:update\_ticket@167', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@168'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | fb15e01d48b42d50f777bbe0a0d16c243aab75f2f1914e5ba64789437b7f0351 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 108\-228, đã bị cắt bớt\.

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

### 5.10. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a07e5a7e0aa8f790bf7b1c6206cd978571ece45567df87c810a38094dd62b6f6 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/properties\.py |
| Dòng | 170 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=delete\_unit; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:delete\_unit@169', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@170'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 285c186bb8c5f752735b8f19d60eb76c3131e5a4194a18390c1323c3173f1a20 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 110\-177\.

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

### 5.11. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a48b7f6f6dd6fe4fbd7ca2f9d3b09746f98feef24548e536e919810f37fea4c5 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/imports\_exports\.py |
| Dòng | 208 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=export\_rent\_roll; entrypoint\_exposed=True; guards=\['user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:export\_rent\_roll@196', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@208'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9b1ccd75d5e0e41f616a96a0cf684033fd9b164a992aed68dc0bb24d5c0ff72b |

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

### 5.12. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b9c579d4cdcaacbef58215b45970fc003dc9d47820b7381034421b385a676fd3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routes\/integrations\.py |
| Dòng | 57 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_webhooks; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_collection\_query; source\_kind=http\_endpoint; trace=\['entrypoint\:list\_webhooks@56', 'source\:http\_endpoint', 'sink\:unbounded\_collection\_query@57'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 907d82cdb30d1738d3166d222670888b38e68ece4e9e2466347a2b2c658ea348 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-84\.

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

### 5.13. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d26e5612ec32d696514aa602c54f912b3c02be125a43b84e40df043fff1ac8ed |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/properties\.py |
| Dòng | 97 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=delete\_property; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:delete\_property@96', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@97'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | aa58ebcbea31c1ab258ab0b122048f7b9a91240ea6b3301e772062e802d8d1fc |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 37\-157\.

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

### 5.14. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d8931e41f7277b30426e0bed85fe24782c02b45bdca13019c070be402679b7de |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/tickets\.py |
| Dòng | 220 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=assign\_ticket; entrypoint\_exposed=True; guards=\['role', 'role\.maintenance\_worker', 'target\.role', 'user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:assign\_ticket@214', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@220'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 54d7b072c5ce77c55b40e3aac034166d3015e63b6f4f1eabfa3989083fbb1192 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 160\-271, đã bị cắt bớt\.

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

### 5.15. MANUAL\_REVIEW — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e14932b572c31220b75f1c01d2bd0eec2647ddca161caf0531439feb07632f4e |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | backend\/app\/routes\/inspections\.py |
| Dòng | 84 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=get\_inspection; entrypoint\_exposed=True; guards=\['user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:get\_inspection@83', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@84'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8767419f64e182989183f1584c7ae9da043d069ea5690cb945318c9080f7d173 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 24\-112\.

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

### 5.16. MANUAL\_REVIEW — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | fc2ab9ec95aa327cc7ddb86cd2c27213ec8e65172ada409323894a6b0cd45098 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | backend\/app\/routes\/audit\.py |
| Dòng | 39 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=list\_audit; entrypoint\_exposed=True; guards=\['actor\_id'\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unvalidated\_domain\_value\_operation; source\_kind=http\_route\_parameter; trace=\['entrypoint\:list\_audit@19', 'source\:http\_route\_parameter', 'sink\:unvalidated\_domain\_value\_operation@39'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 884 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 57d55d67d78d124ac004631e633841ca04f03a7b02dd294dfb93364b54ec72a5 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

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

### 5.17. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 00299cffac55c426 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | backend\/app\/tenant\_operations\.py |
| Dòng | 66 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 364 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 54594fcd59775942adfade562022176de54b7b8a5b6f6904b7164c273581be06 |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink backend\/app\/tenant\_operations\.py\:66; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.18. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 509b9c2018893c2a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | backend\/app\/tenant\_operations\.py |
| Dòng | 40 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 1651 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | db2a441a9b7c018a58f8b8db0670dfab78286a55fe14042c85103309aba7d3ba |

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

### 5.19. MANUAL\_REVIEW — python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d0f53d2b0153c20e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.dynamic\-urllib\-use\-detected\.dynamic\-urllib\-use\-detected |
| File | backend\/app\/tenant\_operations\.py |
| Dòng | 130 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-939\: Improper Authorization in Handler for Custom URL Scheme'\]; owasp=A01\:2017 \- Injection; references=\['https\:\/\/cwe\.mitre\.org\/data\/definitions\/939\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 907 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 3ec7feae7bbaee7aaefea10ae6be28620d0e744cb992ccef3d6d203bb2692a46 |

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

## 6. Lỗi scanner
- Không có lỗi scanner.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
