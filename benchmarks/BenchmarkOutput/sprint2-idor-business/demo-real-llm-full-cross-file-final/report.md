# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 30 |
| Triage thành công | 30 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 192\.054875 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 5 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 25 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 52510782\-7400\-4257\-8535\-b0c843a0e85d |
| Repository | realvuln\-damn\-vulnerable\-graphql\-application |
| Repository identifier | realvuln\-damn\-vulnerable\-graphql\-application |
| Commit | a961308c02d1fb462b192681c336b0739e432da7 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | real\-modal\-qwen |
| Model | Qwen\/Qwen3\-14B\-AWQ |
| Prompt version | triage\-prompt\-v14 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v3 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 18\.473118 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-24T07\:28\:34\.334720\+00\:00 |
| Kết thúc | 2026\-08\-24T07\:31\:46\.389595\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v3; SEMGREP=local\-sha256\:12585eff45ce0a7481b2118bbfdf04141da09764c93763b0b2a783f759598279
- Hash artifact: gitleaks=8f8588dd47129b4b4d2706c4642379c15324ee0a4c5bc6e2fc2c4189be31da5a; semgrep=e1c11e83e36f5b2eae13848a3305f43cc54322490c1ba81627fec67c3098c70f

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 0aa62f4516ca52b4b561d1b4df69bda7be124f21d7abf4a4b82bf5eb03f3b477 | module2\.joern\.cross\-file\.open | core\/helpers\.py\:25 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | b9c2c2700a95ebfb3ca89ba13faa782df7a004ebca6eaab5ce96aaee5b99a339 | module2\.joern\.cross\-file\.popen | core\/helpers\.py\:9 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 3 | MANUAL\_REVIEW | MEDIUM | 2b3efd03176b0f1f | python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie | core\/views\.py\:395 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 4 | MANUAL\_REVIEW | UNKNOWN | 0100ad1a66ac6ba3 | jwt | tests\/test\_auth\.py\:52 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 5 | MANUAL\_REVIEW | UNKNOWN | 22ae0f2635374ab5 | jwt | tests\/test\_auth\.py\:34 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / HIGH — Cao |
| 6 | LIKELY\_TP | HIGH | 17373daa63cd1c1744d2285cde1dbe1fdbbb2d3840da929df558e8f36850f30e | module2\.logic\.missing\-authz\-idor | core\/views\.py\:148 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 7 | LIKELY\_TP | HIGH | 2ee037f8d2c481a78d2c819c7b4b8521924099929646cbfe55ff6a45fdb61a3e | module2\.logic\.missing\-authz\-idor | core\/views\.py\:432–439 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 8 | LIKELY\_TP | HIGH | 38902d1947295055e119fd0ca00c4ac43288f68e7e044401d63c8750d67e5270 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:427–429 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 9 | LIKELY\_TP | HIGH | 4509a4fcad6dc1a393c759594496e37ebed5c8508f1dbc17eb1280d2f74dd514 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:286 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 10 | LIKELY\_TP | HIGH | 606cda247250d9778f17f5406deed54007e3fbdb54b911a94acc8b531dead12f | module2\.logic\.missing\-authz\-idor | core\/views\.py\:359 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 11 | LIKELY\_TP | HIGH | 60cc34cc2d8bdb25bd2d1243a776e62e28140cc1e28757659dfe2d11d38af969 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:374 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 12 | LIKELY\_TP | HIGH | 683ab1af62094cbfb54db1e55369db185435271d7433d17555b447bf808693ea | module2\.logic\.missing\-authz\-idor | core\/views\.py\:330 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 13 | LIKELY\_TP | HIGH | 68a441732ffba8f6b5fb04abe10316ae460a4deb9d059fa4aebb0a6cc87d8970 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:328 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 14 | LIKELY\_TP | HIGH | 754582b0f9960f625fbc7d335262ed661c6a8daa9971fa17da2e20e5a51f8cc7 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:358 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 15 | LIKELY\_TP | HIGH | 7822766dc01c98fecd8fd4651e41d72a2cb55613c8696343d8308a26eb211885 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:234 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 16 | LIKELY\_TP | HIGH | 7bc45c81712441ea | python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode | core\/helpers\.py\:21 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 17 | LIKELY\_TP | HIGH | 7d43b147766a1e1fa289558ae6a78f9cb9c7606d93eacb1ace4d1cee68921d99 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:141 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 18 | LIKELY\_TP | HIGH | 9ef4790047b69ce96f96377a4753fd3d5149fd1a52d56a9519576477a821e8ce | module2\.logic\.missing\-authz\-idor | core\/views\.py\:305 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 19 | LIKELY\_TP | HIGH | b18f9c6f4cb21405fb532866237af6cd43a504d6e7e13f68cb79535f6213efb0 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:167 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 20 | LIKELY\_TP | HIGH | b2f87e5b281f2aef97f9634521a7c762ae1447f10d0019b99c5f341924587e65 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:295 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 21 | LIKELY\_TP | HIGH | b7c58bf36fb6d03cdb96ffe99dc1f35a541fa4f1182d41cb0508c778b858b7f9 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:149 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 22 | LIKELY\_TP | HIGH | c682776851bc1af066a2a08cc5a173f8c6ed44ccea64185111ef5a80f71cd6a1 | module2\.logic\.business\-rule\-bypass | core\/views\.py\:322 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 23 | LIKELY\_TP | HIGH | c9f34e40a416b19368388bd3afc949cd296285c1969abace7fe8c6a67d55d5ec | module2\.logic\.missing\-authz\-idor | core\/views\.py\:385–389 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 24 | LIKELY\_TP | HIGH | ca541deff9dfeac95f6b847fe75164a152f7eb8f168ffc62a7c38562265dafc9 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:320 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 25 | LIKELY\_TP | HIGH | cc73ea5755c9f468361fcc21af6b5c223d9252ce7780b3645109cdced83ff030 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:317 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 26 | LIKELY\_TP | HIGH | cd034c12ee3adc79 | python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text | core\/views\.py\:320 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 27 | LIKELY\_TP | HIGH | d1d9209f24b72e912de8d9193b7a63b94b1974e2e2cf599a8eec2077b2b6e2fe | module2\.logic\.missing\-authz\-idor | core\/views\.py\:303 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 28 | LIKELY\_TP | HIGH | dece44b5e58c620f41e1e746deb0f673b449a5e30f00443eb42bb9688b3c1609 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:380–383 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 29 | LIKELY\_TP | HIGH | f4a81b98668488397030960ee48429905d6eb8652ff2ce2119eea0f4d3750ab1 | module2\.logic\.missing\-authz\-idor | core\/views\.py\:442–451 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 30 | LIKELY\_TP | MEDIUM | fad4ef183220aacc | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | app\.py\:14 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.joern\.cross\-file\.open

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0aa62f4516ca52b4b561d1b4df69bda7be124f21d7abf4a4b82bf5eb03f3b477 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.open — Joern cross\-file source\-to\-sink path |
| File | core\/helpers\.py |
| Dòng | 25 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 2234 ms |
| Thời gian provider | 2078 ms |
| SHA-256 đầu vào triage | fb396952f273f20b7aa44b6488ea90fa2480de622b88ea57fe43f43685ed9cc7 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source core\/views\.py\:185; sink core\/helpers\.py\:25; đường source–sink core\/views\.py\:185 → core\/views\.py\:185 → core\/views\.py\:185 → core\/views\.py\:186 → core\/helpers\.py\:23 → core\/helpers\.py\:25 → core\/helpers\.py\:25; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — cross\_file**

- File đi qua: core\/views\.py; core\/helpers\.py
- Bước 1: `method\_parameter\_in` `filename` tại `core\/views\.py\:185`
- Bước 2: `identifier` `filename` tại `core\/views\.py\:185`
- Bước 3: `method\_parameter\_in` `filename` tại `core\/views\.py\:185`
- Bước 4: `identifier` `filename` tại `core\/views\.py\:186`
- Bước 5: `method\_parameter\_in` `filename` tại `core\/helpers\.py\:23`
- Bước 6: `call` `&lt;operator&gt;\.addition` tại `core\/helpers\.py\:25`
- Bước 7: `call` `open` tại `core\/helpers\.py\:25`

**Đường 2 — cross\_file**

- File đi qua: core\/views\.py; core\/helpers\.py
- Bước 1: `method\_parameter\_in` `filename` tại `core\/views\.py\:185`
- Bước 2: `identifier` `filename` tại `core\/views\.py\:186`
- Bước 3: `method\_parameter\_in` `filename` tại `core\/helpers\.py\:23`
- Bước 4: `call` `&lt;operator&gt;\.addition` tại `core\/helpers\.py\:25`
- Bước 5: `call` `open` tại `core\/helpers\.py\:25`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: JOERN\_SECURITY\_CONTROL\_NOT\_FOUND
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tồn tại một đường dẫn từ nguồn đến điểm nguy hiểm qua nhiều tệp, nhưng không có thông tin cụ thể về tham số nguy hiểm hoặc giá trị đầu vào\. Cần xem xét lại để xác minh tính nguy hiểm\.

**Bằng chứng LLM sử dụng**

- Đường dẫn từ nguồn đến điểm nguy hiểm được xác định là hoàn chỉnh\.
- Nguồn được xác định là tham số đầu vào từ endpoint, do người dùng kiểm soát\.
- Không có thông tin cụ thể về tham số nguy hiểm trong hàm open\(\) được cung cấp\.
- Không có kiểm soát an ninh nào được phát hiện trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin cụ thể về tham số nguy hiểm trong hàm open\(\) không được cung cấp\.
- Không có thông tin về giá trị đầu vào cụ thể được truyền vào hàm open\(\)\.

**Giả định LLM đã sử dụng**

- Giả sử rằng tham số truyền vào hàm open\(\) có thể là nguy hiểm nếu không được kiểm soát đúng cách\.
- Giả sử rằng không có kiểm soát an ninh nào được thực hiện trước khi gọi hàm open\(\)\.

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

### 5.2. MANUAL\_REVIEW — module2\.joern\.cross\-file\.popen

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b9c2c2700a95ebfb3ca89ba13faa782df7a004ebca6eaab5ce96aaee5b99a339 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.popen — Joern cross\-file source\-to\-sink path |
| File | core\/helpers\.py |
| Dòng | 9 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 2040 ms |
| Thời gian provider | 1876 ms |
| SHA-256 đầu vào triage | f13ed47f6598d6d44538ef967aa7532f861cb7419ae46ef6c1a353a6828d2b0c |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source core\/views\.py\:209; sink core\/helpers\.py\:9; đường source–sink core\/views\.py\:209 → core\/views\.py\:209 → core\/views\.py\:209 → core\/views\.py\:210 → core\/views\.py\:210 → core\/views\.py\:210 → core\/security\.py\:41 → core\/security\.py\:45 → core\/security\.py\:45 → core\/security\.py\:45; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — cross\_file**

- File đi qua: core\/views\.py; core\/security\.py; core\/helpers\.py
- Bước 1: `method\_parameter\_in` `path` tại `core\/views\.py\:209`
- Bước 2: `identifier` `path` tại `core\/views\.py\:209`
- Bước 3: `method\_parameter\_in` `path` tại `core\/views\.py\:209`
- Bước 4: `identifier` `path` tại `core\/views\.py\:210`
- Bước 5: `call` `&lt;operator&gt;\.formattedValue` tại `core\/views\.py\:210`
- Bước 6: `call` `&lt;operator&gt;\.formatString` tại `core\/views\.py\:210`
- Bước 7: `method\_parameter\_in` `cmd` tại `core\/security\.py\:41`
- Bước 8: `identifier` `cmd` tại `core\/security\.py\:45`
- Bước 9: `call` `replace` tại `core\/security\.py\:45`
- Bước 10: `identifier` `tmp0` tại `core\/security\.py\:45`
- Bước 11: `identifier` `tmp0` tại `core\/security\.py\:45`
- Bước 12: `call` `replace` tại `core\/security\.py\:45`
- Bước 13: `method\_return` `METHOD\_RETURN` tại `core\/security\.py\:41`
- Bước 14: `call` `strip\_dangerous\_characters` tại `core\/views\.py\:210`
- Bước 15: `identifier` `url` tại `core\/views\.py\:210`
- Bước 16: `identifier` `url` tại `core\/views\.py\:211`
- Bước 17: `call` `&lt;operator&gt;\.formattedValue` tại `core\/views\.py\:211`
- Bước 18: `call` `&lt;operator&gt;\.formatString` tại `core\/views\.py\:211`
- Bước 19: `method\_parameter\_in` `cmd` tại `core\/helpers\.py\:8`
- Bước 20: `identifier` `cmd` tại `core\/helpers\.py\:9`
- Bước 21: `identifier` `os` tại `core\/helpers\.py\:9`
- Bước 22: `call` `popen` tại `core\/helpers\.py\:9`

**Đường 2 — cross\_file**

- File đi qua: core\/views\.py; core\/security\.py; core\/helpers\.py
- Bước 1: `method\_parameter\_in` `path` tại `core\/views\.py\:209`
- Bước 2: `identifier` `path` tại `core\/views\.py\:210`
- Bước 3: `call` `&lt;operator&gt;\.formattedValue` tại `core\/views\.py\:210`
- Bước 4: `call` `&lt;operator&gt;\.formatString` tại `core\/views\.py\:210`
- Bước 5: `method\_parameter\_in` `cmd` tại `core\/security\.py\:41`
- Bước 6: `identifier` `cmd` tại `core\/security\.py\:45`
- Bước 7: `call` `replace` tại `core\/security\.py\:45`
- Bước 8: `identifier` `tmp0` tại `core\/security\.py\:45`
- Bước 9: `identifier` `tmp0` tại `core\/security\.py\:45`
- Bước 10: `call` `replace` tại `core\/security\.py\:45`
- Bước 11: `method\_return` `METHOD\_RETURN` tại `core\/security\.py\:41`
- Bước 12: `call` `strip\_dangerous\_characters` tại `core\/views\.py\:210`
- Bước 13: `identifier` `url` tại `core\/views\.py\:210`
- Bước 14: `identifier` `url` tại `core\/views\.py\:211`
- Bước 15: `call` `&lt;operator&gt;\.formattedValue` tại `core\/views\.py\:211`
- Bước 16: `call` `&lt;operator&gt;\.formatString` tại `core\/views\.py\:211`
- Bước 17: `method\_parameter\_in` `cmd` tại `core\/helpers\.py\:8`
- Bước 18: `identifier` `cmd` tại `core\/helpers\.py\:9`
- Bước 19: `identifier` `os` tại `core\/helpers\.py\:9`
- Bước 20: `call` `popen` tại `core\/helpers\.py\:9`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: JOERN\_SECURITY\_CONTROL\_NOT\_FOUND
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một đường dẫn từ tham số đầu vào của endpoint đến lệnh os\.popen mà không có biện pháp kiểm soát hiệu quả\. Đầu vào người dùng có thể ảnh hưởng trực tiếp đến lệnh được thực thi, gây nguy hiểm\.

**Bằng chứng LLM sử dụng**

- Đầu vào người dùng được truyền từ endpoint \(core\/views\.py, dòng 209\) đến hàm run\_cmd trong core\/helpers\.py \(dòng 9\)\.
- Không có biện pháp kiểm soát \(guard\) nào được xác nhận trong toàn bộ chuỗi gọi hàm\.
- Lệnh os\.popen được gọi trực tiếp với tham số có thể bị nhiễm độc \(cmd\), không có mã hóa hoặc kiểm tra an toàn\.
- Đường dẫn taint được xác nhận hoàn chỉnh và không bị gián đoạn bởi bất kỳ giá trị cố định nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có mã kiểm soát an toàn nào được áp dụng trước khi gọi os\.popen\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Model TP opinion lacks deterministic rule\-mechanism support\.
- **Lý do policy:**
  - Structured evidence does not safely support automatic TP classification\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.3. MANUAL\_REVIEW — python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie

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
| Metadata an toàn | category=security; confidence=HIGH; cwe=CWE\-614\: Sensitive Cookie in HTTPS Session Without Secure Attribute; technology=\['flask'\] |
| Thời gian xử lý | 1901 ms |
| Thời gian provider | 1718 ms |
| SHA-256 đầu vào triage | ade551b27421ece5caba2e7138a046038818f821b55e1cb952243183fd9985e3 |

**Thông báo của scanner**

> Flask response cookie is set without secure\=True\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source không áp dụng; sink core\/views\.py\:395; đường source–sink không yêu cầu cho cơ chế này; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Evidence Source-to-Sink chi tiết

Chưa có đường source-to-sink hoàn chỉnh được Joern chứng minh.

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến cookie không được thiết lập với secure\=True, nhưng không có bằng chứng cho thấy cookie chứa thông tin nhạy cảm hoặc được truyền qua HTTPS\. Không có nguồn dữ liệu người dùng được xác định trong đoạn mã liên quan\.

**Bằng chứng LLM sử dụng**

- Không có giá trị cookie nào được thiết lập từ nguồn người dùng \(request\) trong đoạn mã\.
- Cookie được thiết lập với giá trị cố định \('graphiql\:disable'\) và không có tham số nào được truyền từ người dùng\.
- Không có bằng chứng cho thấy cookie chứa thông tin nhạy cảm hoặc được sử dụng trong môi trường HTTPS\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử cookie được thiết lập với giá trị cố định không chứa thông tin nhạy cảm\.
- Giả sử không có tham số người dùng nào ảnh hưởng đến giá trị cookie\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Model FP opinion lacks deterministic benign\-path support\.
- **Lý do policy:**
  - Structured evidence does not safely support FP candidate status\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.4. MANUAL\_REVIEW — jwt

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
| Thời gian xử lý | 1737 ms |
| Thời gian provider | 1735 ms |
| SHA-256 đầu vào triage | cd3dafb968775c0caa8595de2f1a7cbd583ee831327a99280bcf8f7cf57d807e |

**Thông báo của scanner**

> Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-64\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một JWT trong mã nguồn, nhưng không có bằng chứng rõ ràng cho thấy nó là một bí mật nhạy cảm hoặc được truyền qua đầu vào người dùng\. Mã đang ở trong tập tin kiểm thử và có thể không liên quan đến bảo mật thực tế\.

**Bằng chứng LLM sử dụng**

- JWT được tìm thấy trong tập tin kiểm thử, không phải trong mã sản phẩm\.
- Không có bằng chứng cho thấy JWT được truyền từ đầu vào người dùng hoặc được lưu trữ như một bí mật nhạy cảm\.
- Không có thông tin về cách JWT được tạo hoặc sử dụng trong ứng dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về cách JWT được tạo hoặc sử dụng trong ứng dụng\.
- Không có bằng chứng cho thấy JWT được truyền từ đầu vào người dùng\.

**Giả định LLM đã sử dụng**

- JWT có thể là một phần của tập tin kiểm thử và không liên quan đến bảo mật thực tế\.
- Không có bằng chứng cho thấy JWT là một bí mật nhạy cảm\.

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

### 5.5. MANUAL\_REVIEW — jwt

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
| Thời gian xử lý | 1969 ms |
| Thời gian provider | 1964 ms |
| SHA-256 đầu vào triage | a9d5d6de6fe29f907579803c64abda17e4696c124435d927764d9c91d0b922ba |

**Thông báo của scanner**

> Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-64\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một JWT trong mã nguồn, nhưng không có bằng chứng rõ ràng cho thấy nó là một điểm yếu bảo mật\. Mã nguồn đang chạy các kiểm tra và không có bằng chứng về việc JWT được sử dụng để truy cập trái phép\. Cần xem xét thêm ngữ cảnh thực thi\.

**Bằng chứng LLM sử dụng**

- JWT được tìm thấy trong một tệp kiểm tra \(test\_auth\.py\), không phải trong mã sản phẩm\.
- JWT không được truyền qua bất kỳ đầu vào nào từ người dùng hoặc API bên ngoài\.
- Không có bằng chứng cho thấy JWT được sử dụng để xác thực hoặc truy cập tài nguyên nhạy cảm trong mã nguồn\.
- Mã nguồn đang thực hiện các kiểm tra xác minh, không phải là mã sản phẩm đang chạy\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về cách JWT được tạo hoặc sử dụng trong ứng dụng\.
- Không có bằng chứng cho thấy JWT được truyền qua các API hoặc đầu vào người dùng\.

**Giả định LLM đã sử dụng**

- JWT được tìm thấy trong tệp kiểm tra có thể là giả lập hoặc không liên quan đến bảo mật thực tế\.
- Không có bằng chứng cho thấy JWT được sử dụng để xác thực hoặc truy cập tài nguyên nhạy cảm\.

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

### 5.6. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 17373daa63cd1c1744d2285cde1dbe1fdbbb2d3840da929df558e8f36850f30e |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 148 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=mutate; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:mutate@140', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@148'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1887 ms |
| Thời gian provider | 1884 ms |
| SHA-256 đầu vào triage | f14d8cc6a1def4bc322b1c466023cdaf313500f35f3babf3703417c6084c80ba |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 88\-208\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `mutate` tại `core\/views\.py\:148`
- Bước 2: `sink` `mutate` tại `core\/views\.py\:148`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm mutate, nơi tham số id từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn đối tượng Paste mà không có kiểm tra xác thực chủ thể hoặc thuê bao\. Điều này cho phép người dùng truy cập hoặc sửa đổi đối tượng không thuộc về họ\.

**Bằng chứng LLM sử dụng**

- Tham số id từ http\_route\_parameter được truyền trực tiếp vào Paste\.query\.filter\_by\(id\=id\) mà không có kiểm tra xác thực\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng người dùng chỉ có thể truy cập hoặc sửa đổi đối tượng mà họ sở hữu\.
- Đoạn mã cho phép người dùng thay đổi nội dung của đối tượng Paste mà không kiểm tra quyền truy cập\.
- Không có bất kỳ cơ chế nào để ràng buộc đối tượng được yêu cầu với chủ thể đã xác thực\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.7. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2ee037f8d2c481a78d2c819c7b4b8521924099929646cbfe55ff6a45fdb61a3e |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 432–439 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=start\_over; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=privileged\_endpoint\_without\_authorization; source\_kind=http\_or\_graphql\_endpoint; trace=\['entrypoint\:start\_over@432', 'source\:http\_or\_graphql\_endpoint', 'sink\:privileged\_endpoint\_without\_authorization@432'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 4551 ms |
| Thời gian provider | 4548 ms |
| SHA-256 đầu vào triage | 563b24e7dfa6fe58f795e2e5b31ff73be1f9a6acee28caec62b68831b1a52b2e |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 372\-499\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `start\_over` tại `core\/views\.py\:432`
- Bước 2: `sink` `start\_over` tại `core\/views\.py\:434`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một điểm cuối được phơi bày \(exposed HTTP endpoint\) truy cập trực tiếp đến một điểm nhạy cảm \(privileged operation\) mà không có kiểm soát xác thực nào trong hàm chứa\. Điều này cho phép người dùng không được xác thực thực hiện hành động nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Điểm nguồn \(source\) là một endpoint HTTP\/GraphQL được xác định là do người dùng kiểm soát \(user\-controlled\)\.
- Điểm đích \(sink\) là một hàm gọi \`helpers\.initialize\(\)\` mà không có kiểm soát xác thực nào được phát hiện trong hàm chứa\.
- Không có kiểm soát xác thực nào được tìm thấy trong hàm \`start\_over\(\)\` trước khi gọi đến \`helpers\.initialize\(\)\`\.
- Một đường dẫn đầy đủ từ điểm nguồn đến điểm đích được xác nhận là hoàn chỉnh và không có kiểm soát nào được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được áp dụng trong hàm \`start\_over\(\)\` trước khi gọi đến \`helpers\.initialize\(\)\`\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.8. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 38902d1947295055e119fd0ca00c4ac43288f68e7e044401d63c8750d67e5270 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 427–429 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=audit; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=privileged\_endpoint\_without\_authorization; source\_kind=http\_or\_graphql\_endpoint; trace=\['entrypoint\:audit@427', 'source\:http\_or\_graphql\_endpoint', 'sink\:privileged\_endpoint\_without\_authorization@427'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3403 ms |
| Thời gian provider | 3400 ms |
| SHA-256 đầu vào triage | f9c3a0150d7d736b00da6345fad6bf24a33505e90823a6b3cf0239a8a9b58df9 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 367\-489\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `audit` tại `core\/views\.py\:427`
- Bước 2: `sink` `audit` tại `core\/views\.py\:428`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng xác thực thiếu \(missing authz idor\) trong hàm 'audit' khi một endpoint HTTP\/GraphQL không được kiểm soát quyền truy cập trước khi thực hiện thao tác nhạy cảm\. Không có kiểm soát xác thực nào được phát hiện trong hàm chứa, dẫn đến khả năng truy cập trái phép\.

**Bằng chứng LLM sử dụng**

- Endpoint 'audit' được xác định là nguồn gốc \(source\) và có thể bị người dùng kiểm soát \(user\-controlled\)\.
- Hàm 'audit' gọi đến 'Audit\.query\.order\_by' mà không có kiểm soát xác thực \(authorization guard\) nào được áp dụng\.
- Không có kiểm soát xác thực nào được tìm thấy trong hàm 'audit' để đảm bảo người dùng được xác thực và có quyền truy cập\.
- Đường dẫn từ nguồn đến điểm nhạy cảm \(sink\) được xác nhận hoàn chỉnh và không có kiểm soát nào được áp dụng\.
- Phân tích tĩnh xác nhận rằng không có kiểm soát xác thực nào được áp dụng cho điểm nhạy cảm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được áp dụng trong hàm 'audit' để xác minh quyền truy cập của người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.9. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4509a4fcad6dc1a393c759594496e37ebed5c8508f1dbc17eb1280d2f74dd514 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 286 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_me; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_me@283', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@286'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1802 ms |
| Thời gian provider | 1799 ms |
| SHA-256 đầu vào triage | 5549faabad5a20f26c0efd7f08dd49da0eb349e2c4d564b1635e395fa433df8e |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 226\-346\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_me` tại `core\/views\.py\:286`
- Bước 2: `sink` `resolve\_me` tại `core\/views\.py\:286`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một tham số từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn đối tượng mà không có kiểm soát xác thực hoặc xác quyền\. Điều này có thể cho phép người dùng truy cập đối tượng không thuộc về họ\.

**Bằng chứng LLM sử dụng**

- Tham số 'token' từ đường dẫn HTTP được truyền trực tiếp vào hàm 'get\_identity' mà không có kiểm tra xác quyền\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng 'token' thuộc về người dùng hiện tại hoặc được xác thực\.
- Đối tượng được truy vấn là 'UserObject' dựa trên giá trị 'identity' mà không có kiểm tra xác quyền\.
- Không có bất kỳ điều kiện nào được áp dụng để giới hạn truy cập theo chủ thể hoặc thuê bao\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác quyền nào được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.10. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 606cda247250d9778f17f5406deed54007e3fbdb54b911a94acc8b531dead12f |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 359 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_read\_and\_burn; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_read\_and\_burn@357', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@359'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1932 ms |
| Thời gian provider | 1930 ms |
| SHA-256 đầu vào triage | 2fc77631643b3e77d0d8b46ebdc417d62ce9b18a229f43d6078c62565a784957 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 299\-419\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_read\_and\_burn` tại `core\/views\.py\:359`
- Bước 2: `sink` `resolve\_read\_and\_burn` tại `core\/views\.py\:359`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một tham số từ đường dẫn HTTP được sử dụng trực tiếp trong truy vấn cơ sở dữ liệu mà không có kiểm soát xác thực hoặc xác quyền đối với đối tượng cụ thể\. Điều này có thể cho phép người dùng không được ủy quyền truy cập hoặc thay đổi dữ liệu nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào truy vấn 'Paste\.query\.filter\_by\(id\=id, burn\=True\)' mà không có kiểm tra xác quyền\.
- Không có kiểm soát nào được phát hiện để đảm bảo rằng 'id' thuộc về người dùng hiện tại hoặc được ủy quyền\.
- Cơ chế truy vấn cơ sở dữ liệu không được giới hạn theo chủ thể hoặc thuê bao, dẫn đến rủi ro truy cập không được ủy quyền\.
- Không có bất kỳ điều kiện kiểm tra nào được áp dụng trước khi truy vấn cơ sở dữ liệu\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác quyền hoặc xác thực nào được áp dụng trước khi truy vấn cơ sở dữ liệu\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.11. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 60cc34cc2d8bdb25bd2d1243a776e62e28140cc1e28757659dfe2d11d38af969 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 374 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_users; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_users@370', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@374'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1862 ms |
| Thời gian provider | 1860 ms |
| SHA-256 đầu vào triage | 478d7420908501e2cd42b4d1da46984c30627c72f8e4b04702db82a3d776de02 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 314\-434\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_users` tại `core\/views\.py\:374`
- Bước 2: `sink` `resolve\_users` tại `core\/views\.py\:374`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_users\. Tham số 'id' từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn đối tượng mà không có kiểm tra xác thực hoặc giới hạn theo chủ sở hữu hoặc thuê bao\. Điều này cho phép người dùng truy cập đối tượng không được phép\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào hàm filter\_by mà không có kiểm tra xác thực\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng 'id' thuộc về người dùng hiện tại hoặc được xác thực\.
- Đường dẫn truy vấn từ nguồn 'http\_route\_parameter' đến 'object\_lookup\_without\_subject\_scope' được xác nhận hoàn toàn\.
- Không có cơ chế kiểm soát nào được phát hiện trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực hoặc kiểm tra chủ sở hữu được thực hiện trong đoạn mã\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.12. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 683ab1af62094cbfb54db1e55369db185435271d7433d17555b447bf808693ea |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 330 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_paste; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_paste@324', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@330'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1962 ms |
| Thời gian provider | 1960 ms |
| SHA-256 đầu vào triage | b90e2f57b2f554edba193972a6739d8c7e0a68d8314eec767d675f0dace198a0 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 270\-390\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_paste` tại `core\/views\.py\:330`
- Bước 2: `sink` `resolve\_paste` tại `core\/views\.py\:330`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_paste\. Tham số 'id' từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn đối tượng mà không có kiểm tra xác thực hoặc giới hạn theo chủ sở hữu hoặc thuê bao\. Điều này cho phép người dùng truy cập các đối tượng không được phép\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào hàm query\.filter\_by mà không có kiểm tra xác thực\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng 'id' thuộc về người dùng hiện tại hoặc được giới hạn theo thuê bao\.
- Đường dẫn từ tham số HTTP đến hàm truy vấn không bị chặn bởi bất kỳ điều kiện nào\.
- Phân tích tĩnh xác nhận rằng 'id' là nguồn dữ liệu do người dùng kiểm soát và trực tiếp ảnh hưởng đến truy vấn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực hoặc giới hạn theo chủ sở hữu được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.13. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 68a441732ffba8f6b5fb04abe10316ae460a4deb9d059fa4aebb0a6cc87d8970 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 328 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_paste; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_paste@324', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@328'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1947 ms |
| Thời gian provider | 1944 ms |
| SHA-256 đầu vào triage | 8bbea50606f57e68234104f8c2f03d9e4b4c7c2daa61d7fbdbb15ef46eea6af2 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 268\-388\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_paste` tại `core\/views\.py\:328`
- Bước 2: `sink` `resolve\_paste` tại `core\/views\.py\:328`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_paste\. Tham số title từ URL được sử dụng trực tiếp để truy vấn đối tượng mà không có kiểm tra xác thực hoặc giới hạn theo chủ sở hữu hoặc thuê bao\. Điều này cho phép người dùng truy cập đối tượng không được phép\.

**Bằng chứng LLM sử dụng**

- Tham số title từ URL \(http\_route\_parameter\) được truyền trực tiếp vào query\.filter\_by mà không có kiểm tra xác thực\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng người dùng chỉ có thể truy cập đối tượng mà họ sở hữu hoặc được phép truy cập\.
- Đường dẫn từ source đến sink là hoàn chỉnh và không có bất kỳ kiểm soát nào được áp dụng để giới hạn truy cập\.
- Các điều kiện kiểm tra xác thực và kiểm soát đối tượng không được thực hiện\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực hoặc kiểm soát đối tượng được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.14. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 754582b0f9960f625fbc7d335262ed661c6a8daa9971fa17da2e20e5a51f8cc7 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 358 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_read\_and\_burn; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_read\_and\_burn@357', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@358'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2004 ms |
| Thời gian provider | 2001 ms |
| SHA-256 đầu vào triage | 6e5c5b7bf09ad5ae533da0e4644ef278bfe30bbe669f8fddff5fc985fca7f0a3 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 298\-418\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_read\_and\_burn` tại `core\/views\.py\:358`
- Bước 2: `sink` `resolve\_read\_and\_burn` tại `core\/views\.py\:358`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một tham số từ đường dẫn HTTP được sử dụng trực tiếp trong truy vấn cơ sở dữ liệu mà không có kiểm soát xác thực hoặc xác quyền đối với đối tượng cụ thể\. Điều này có thể cho phép người dùng không được ủy quyền truy cập hoặc thay đổi dữ liệu nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào truy vấn 'Paste\.query\.filter\_by\(id\=id, burn\=True\)' mà không có kiểm tra xác quyền\.
- Không có kiểm soát nào được phát hiện để đảm bảo rằng 'id' thuộc về người dùng hiện tại hoặc được ủy quyền\.
- Cơ chế truy vấn cơ sở dữ liệu không được giới hạn theo chủ thể hoặc thuê bao, dẫn đến rủi ro truy cập không được ủy quyền\.
- Không có bất kỳ điều kiện kiểm tra nào được áp dụng trước khi truy vấn cơ sở dữ liệu\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác quyền hoặc xác thực nào được áp dụng trước khi truy vấn cơ sở dữ liệu\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.15. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7822766dc01c98fecd8fd4651e41d72a2cb55613c8696343d8308a26eb211885 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 234 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=mutate; entrypoint\_exposed=True; guards=\['user'\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:mutate@233', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@234'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2269 ms |
| Thời gian provider | 2266 ms |
| SHA-256 đầu vào triage | 047edd478e24bd526f028394ede318319bbf9b0dcb9276d68db51e54e0bb1354 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 174\-294\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `mutate` tại `core\/views\.py\:234`
- Bước 2: `guard` `mutate` tại `core\/views\.py\:234`
- Bước 3: `sink` `mutate` tại `core\/views\.py\:234`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm mutate, nơi thông tin người dùng được truy xuất trực tiếp từ tham số đường dẫn HTTP mà không có kiểm soát quyền truy cập theo chủ thể hoặc thuê bao\. Điều này cho phép người dùng không được ủy quyền truy cập hoặc sửa đổi tài nguyên của người dùng khác\.

**Bằng chứng LLM sử dụng**

- Tham số 'password' từ đường dẫn HTTP được sử dụng trực tiếp trong truy vấn 'User\.query\.filter\_by' mà không có kiểm tra quyền truy cập\.
- Không có kiểm soát rõ ràng nào được áp dụng để ràng buộc đối tượng được truy xuất với chủ thể đã xác thực\.
- Đường dẫn từ nguồn đến điểm truy cập \(sink\) hoàn chỉnh và không có điểm kiểm soát hiệu quả nào được phát hiện\.
- Các điều kiện rủi ro như độ nhạy dữ liệu, khả năng khai thác và mức độ tiếp cận đều cao\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát quyền truy cập nào được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.16. LIKELY\_TP — python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7bc45c81712441ea |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.jwt\.security\.unverified\-jwt\-decode\.unverified\-jwt\-decode |
| File | core\/helpers\.py |
| Dòng | 21 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=HIGH; cwe=CWE\-287\: Improper Authentication; technology=\['jwt'\] |
| Thời gian xử lý | 2085 ms |
| Thời gian provider | 1789 ms |
| SHA-256 đầu vào triage | e964daf98ee4f0010ec97a8e9347bf674ada10eb2bcedcfd2c747dbae9fd0106 |

**Thông báo của scanner**

> JWT signature verification is explicitly disabled\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source không áp dụng; sink core\/helpers\.py\:21; đường source–sink không yêu cầu cho cơ chế này; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Evidence Source-to-Sink chi tiết

Chưa có đường source-to-sink hoàn chỉnh được Joern chứng minh.

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Quy tắc phát hiện rằng việc xác thực chữ ký JWT đã bị tắt một cách rõ ràng\. Điều này có thể dẫn đến việc xử lý các token JWT không an toàn, vì không có kiểm tra xác thực chữ ký\. Không có biện pháp kiểm soát nào được áp dụng để đảm bảo tính toàn vẹn của token\.

**Bằng chứng LLM sử dụng**

- Hàm \`get\_identity\` gọi \`decode\(token, options\=\{'verify\_signature'\: False, 'verify\_exp'\: False\}\)\` cho thấy việc xác thực chữ ký và thời gian hết hạn của JWT bị tắt\.
- Không có kiểm tra hoặc biện pháp bảo vệ nào được áp dụng trước khi giải mã token\.
- Không có giá trị mặc định an toàn hoặc kiểm soát hiệu quả nào được áp dụng để đảm bảo tính toàn vẹn của token\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng \`token\` được truyền vào hàm \`get\_identity\` là một giá trị có thể bị tấn công \(attacker\-controlled\)\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.17. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7d43b147766a1e1fa289558ae6a78f9cb9c7606d93eacb1ace4d1cee68921d99 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 141 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=mutate; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:mutate@140', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@141'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1943 ms |
| Thời gian provider | 1941 ms |
| SHA-256 đầu vào triage | 29d60ee4d2c9425a5f81fd98f3003aeff639924e80521cb7179d293fa95ee603 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 81\-201\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `mutate` tại `core\/views\.py\:141`
- Bước 2: `sink` `mutate` tại `core\/views\.py\:141`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm mutate\. Một tham số đường dẫn HTTP \(id\) được sử dụng trực tiếp để truy vấn đối tượng Paste mà không có kiểm tra xác thực chủ thể hoặc thuê bao\. Điều này cho phép người dùng không được ủy quyền truy cập hoặc sửa đổi đối tượng không thuộc về họ\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào hàm filter\_by của truy vấn Paste\.query\.
- Không có kiểm tra xác thực chủ thể hoặc thuê bao trước khi truy vấn hoặc cập nhật đối tượng\.
- Đường dẫn từ tham số HTTP đến điểm truy vấn đối tượng là hoàn chỉnh và không bị chặn bởi bất kỳ điều kiện nào\.
- Không có cơ chế kiểm soát xác thực nào được phát hiện trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được thực hiện trong các hàm khác hoặc middleware không được hiển thị trong đoạn mã\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.18. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9ef4790047b69ce96f96377a4753fd3d5149fd1a52d56a9519576477a821e8ce |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 305 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_search; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_search@298', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@305'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2219 ms |
| Thời gian provider | 2217 ms |
| SHA-256 đầu vào triage | 9d3d76c7917b156f31ea9aa6b4d430cf299798305d6785fd4486080b963afca6 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 245\-365\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_search` tại `core\/views\.py\:305`
- Bước 2: `sink` `resolve\_search` tại `core\/views\.py\:305`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_search\. Tham số 'keyword' từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn dữ liệu người dùng mà không có kiểm tra quyền truy cập\. Điều này cho phép người dùng truy cập dữ liệu của người khác nếu họ biết ID\.

**Bằng chứng LLM sử dụng**

- Tham số 'keyword' từ http\_route\_parameter được truyền trực tiếp vào truy vấn User\.query\.filter mà không có kiểm tra quyền\.
- Không có kiểm soát hoặc xác thực đối tượng nào được thực hiện trước khi truy vấn dữ liệu người dùng\.
- Đường dẫn từ 'keyword' đến 'User\.query\.filter' được xác nhận hoàn chỉnh và không có điểm kiểm soát nào được áp dụng\.
- Các yếu tố rủi ro như độ nhạy dữ liệu, khả năng khai thác và mức độ tiếp cận đều cao\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực đối tượng nào được thực hiện trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.19. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b18f9c6f4cb21405fb532866237af6cd43a504d6e7e13f68cb79535f6213efb0 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 167 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=mutate; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:mutate@164', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@167'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1979 ms |
| Thời gian provider | 1977 ms |
| SHA-256 đầu vào triage | 23304e212f6703b1a93271b7ac36f6b268f7ef1c95802e7ecd161f236140f49b |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 107\-227\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `mutate` tại `core\/views\.py\:167`
- Bước 2: `sink` `mutate` tại `core\/views\.py\:167`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm mutate, nơi tham số id từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn và xóa đối tượng Paste mà không có kiểm tra ủy quyền\. Không có cơ chế kiểm soát ủy quyền nào được áp dụng cho tham số id trước khi truy vấn\.

**Bằng chứng LLM sử dụng**

- Tham số id từ http\_route\_parameter được truyền trực tiếp vào Paste\.query\.filter\_by\(id\=id\) mà không có kiểm tra ủy quyền\.
- Không có cơ chế kiểm soát ủy quyền nào được áp dụng cho tham số id trước khi truy vấn\.
- Không có bất kỳ điều kiện kiểm tra nào được áp dụng để xác thực quyền truy cập của người dùng trước khi thực hiện thao tác xóa\.
- Đoạn mã cho thấy một lỗ hổng IDOR rõ ràng, cho phép người dùng truy cập hoặc xóa đối tượng không thuộc về họ\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có cơ chế kiểm soát ủy quyền nào được áp dụng cho tham số id trước khi truy vấn\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.20. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b2f87e5b281f2aef97f9634521a7c762ae1447f10d0019b99c5f341924587e65 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 295 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_me; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_me@283', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@295'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1893 ms |
| Thời gian provider | 1891 ms |
| SHA-256 đầu vào triage | 0236180857dba74cae8072825886548e2c7d3efa6fb894f43a18acb2d2e50b22 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 235\-355\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_me` tại `core\/views\.py\:295`
- Bước 2: `sink` `resolve\_me` tại `core\/views\.py\:295`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một tham số từ đường dẫn HTTP được sử dụng trực tiếp trong truy vấn cơ sở dữ liệu mà không có kiểm soát xác thực hoặc xác quyền đối với đối tượng cụ thể\. Điều này có thể cho phép người dùng không được ủy quyền truy cập hoặc sửa đổi dữ liệu của người khác\.

**Bằng chứng LLM sử dụng**

- Tham số 'identity' được lấy từ http\_route\_parameter và được gán trực tiếp vào truy vấn 'query\.filter\_by\(username\=identity\)' mà không có kiểm tra xác quyền\.
- Không có kiểm soát nào được phát hiện để đảm bảo rằng 'identity' thuộc về người dùng hiện tại hoặc được ủy quyền\.
- Đường dẫn từ nguồn đến điểm nguy hiểm hoàn chỉnh và không có điểm kiểm soát nào được áp dụng\.
- Các yếu tố rủi ro như độ nhạy dữ liệu, khả năng khai thác và mức độ tiếp cận đều cao\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác quyền hoặc xác thực nào được áp dụng cho đối tượng được truy vấn\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.21. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b7c58bf36fb6d03cdb96ffe99dc1f35a541fa4f1182d41cb0508c778b858b7f9 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 149 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=mutate; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:mutate@140', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@149'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1877 ms |
| Thời gian provider | 1875 ms |
| SHA-256 đầu vào triage | 609024bf71d268720ae4f1ddcf5496273904c70f3984acec6f5e23e3b70223ca |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 89\-209\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `mutate` tại `core\/views\.py\:149`
- Bước 2: `sink` `mutate` tại `core\/views\.py\:149`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm mutate\. Một tham số đường dẫn HTTP \(id\) được sử dụng trực tiếp để truy vấn đối tượng Paste mà không có kiểm tra xác thực chủ thể hoặc thuê bao\. Điều này cho phép người dùng không được ủy quyền truy cập hoặc sửa đổi đối tượng không thuộc về họ\.

**Bằng chứng LLM sử dụng**

- Tham số 'id' từ đường dẫn HTTP được truyền trực tiếp vào hàm filter\_by của truy vấn Paste\.query\.
- Không có kiểm tra xác thực chủ thể hoặc thuê bao trước khi truy vấn hoặc cập nhật đối tượng\.
- Đường dẫn từ tham số HTTP đến điểm truy vấn đối tượng là hoàn chỉnh và không bị chặn bởi bất kỳ điều kiện nào\.
- Không có cơ chế kiểm soát xác thực nào được phát hiện trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được thực hiện trong các hàm khác hoặc middleware không được hiển thị trong đoạn mã\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.22. LIKELY\_TP — module2\.logic\.business\-rule\-bypass

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c682776851bc1af066a2a08cc5a173f8c6ed44ccea64185111ef5a80f71cd6a1 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.business\-rule\-bypass — Bounded AST candidate for business rule bypass |
| File | core\/views\.py |
| Dòng | 322 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-840; entrypoint=resolve\_pastes; entrypoint\_exposed=True; guards=\[\]; logic\_class=business\_rule\_bypass; remediation=Recompute trusted values on the server and enforce domain and resource bounds before the operation\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.0, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.35; sink\_kind=unbounded\_pagination\_parameter; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_pastes@314', 'source\:http\_route\_parameter', 'sink\:unbounded\_pagination\_parameter@322'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1880 ms |
| Thời gian provider | 1878 ms |
| SHA-256 đầu vào triage | 7774fa19427f92f4904e8d173a2810e10d1ee1fa47a3214553914b48693d901d |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a business rule bypass pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 262\-382\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_pastes` tại `core\/views\.py\:314`
- Bước 2: `sink` `resolve\_pastes` tại `core\/views\.py\:322`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng có thể dẫn đến việc truy vấn không giới hạn do tham số 'limit' được truyền từ đầu vào HTTP mà không có kiểm soát nào trên phía máy chủ\. Điều này cho phép người tấn công truy vấn một lượng dữ liệu lớn, gây ra rủi ro về việc tiêu tốn tài nguyên\.

**Bằng chứng LLM sử dụng**

- Tham số 'limit' được lấy từ tham số HTTP và truyền trực tiếp đến hàm 'limit\(\)' mà không có kiểm tra giới hạn\.
- Không có kiểm soát nào được áp dụng để giới hạn giá trị của 'limit' trước khi truy vấn\.
- Có thể xảy ra việc truy vấn một lượng lớn dữ liệu nếu 'limit' được đặt thành một giá trị rất lớn\.
- Không có cơ chế kiểm tra hoặc giới hạn nào được áp dụng cho tham số 'limit' trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát nào được áp dụng cho tham số 'limit' trong đoạn mã\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.23. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c9f34e40a416b19368388bd3afc949cd296285c1969abace7fe8c6a67d55d5ec |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 385–389 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_delete\_all\_pastes; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=privileged\_endpoint\_without\_authorization; source\_kind=http\_or\_graphql\_endpoint; trace=\['entrypoint\:resolve\_delete\_all\_pastes@385', 'source\:http\_or\_graphql\_endpoint', 'sink\:privileged\_endpoint\_without\_authorization@385'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 3297 ms |
| Thời gian provider | 3294 ms |
| SHA-256 đầu vào triage | 6158ff7aa1fd3fe05659740da33bf0f4db37813954a0ed81c186a1e18ede7498 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 325\-449\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_delete\_all\_pastes` tại `core\/views\.py\:385`
- Bước 2: `sink` `resolve\_delete\_all\_pastes` tại `core\/views\.py\:387`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Đoạn mã cho thấy một điểm cuối được phơi bày \(exposed endpoint\) thực hiện một thao tác đặc quyền \(privileged operation\) mà không có kiểm soát xác thực nào\. Không có bất kỳ cơ chế kiểm soát nào được phát hiện trong hàm chứa, cho phép người dùng không được xác thực thực hiện hành động xóa tất cả các bản ghi\. Điều này là một lỗ hổng xác thực thiếu \(missing authz idor\)\.

**Bằng chứng LLM sử dụng**

- Điểm cuối được phơi bày \(exposed endpoint\) là 'resolve\_delete\_all\_pastes' và có thể được truy cập bởi người dùng không được xác thực\.
- Không có cơ chế kiểm soát xác thực nào được phát hiện trong hàm 'resolve\_delete\_all\_pastes' trước khi thực hiện thao tác xóa \(Paste\.query\.delete\(\)\)\.
- Thao tác xóa \(Paste\.query\.delete\(\)\) là một thao tác đặc quyền \(privileged operation\) và không có kiểm soát nào để xác minh quyền của người dùng\.
- Đường dẫn từ điểm cuối đến thao tác đặc quyền là hoàn chỉnh và không có bất kỳ kiểm soát nào được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có cơ chế kiểm soát xác thực nào được áp dụng trong hàm 'resolve\_delete\_all\_pastes' trước khi thực hiện thao tác xóa\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.24. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ca541deff9dfeac95f6b847fe75164a152f7eb8f168ffc62a7c38562265dafc9 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 320 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_pastes; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_pastes@314', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@320'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1929 ms |
| Thời gian provider | 1927 ms |
| SHA-256 đầu vào triage | 8d60954d5f104023786bcf27b16d860cd5f9cc00a763d11fc357ab30eb9d4200 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 260\-380\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_pastes` tại `core\/views\.py\:320`
- Bước 2: `sink` `resolve\_pastes` tại `core\/views\.py\:320`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_pastes\. Tham số 'filter' được truyền từ http\_route\_parameter và được sử dụng trực tiếp trong truy vấn mà không có kiểm soát quyền truy cập theo chủ thể hoặc thuê bao\. Không có cơ chế kiểm tra quyền truy cập nào được áp dụng trước khi truy vấn dữ liệu\.

**Bằng chứng LLM sử dụng**

- Tham số 'filter' được lấy từ http\_route\_parameter, cho thấy nó có thể bị kiểm soát bởi người dùng\.
- Tham số 'filter' được sử dụng trực tiếp trong truy vấn 'result\.filter' mà không có kiểm tra quyền truy cập\.
- Không có cơ chế kiểm soát quyền truy cập nào được áp dụng trước khi truy vấn dữ liệu\.
- Đường dẫn từ nguồn đến điểm nguy hiểm hoàn chỉnh và không có điểm kiểm soát nào được phát hiện\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có cơ chế kiểm soát quyền truy cập nào được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.25. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cc73ea5755c9f468361fcc21af6b5c223d9252ce7780b3645109cdced83ff030 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 317 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_pastes; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_pastes@314', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@317'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 1883 ms |
| Thời gian provider | 1881 ms |
| SHA-256 đầu vào triage | 80d83d4deef92c0f83a633dbf933e8a17dbf794b4607cd4844764a400e55f826 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 257\-377\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_pastes` tại `core\/views\.py\:317`
- Bước 2: `sink` `resolve\_pastes` tại `core\/views\.py\:317`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_pastes\. Tham số 'public' từ URL được sử dụng trực tiếp trong truy vấn cơ sở dữ liệu mà không có kiểm soát quyền truy cập theo chủ thể hoặc thuê bao\. Điều này cho phép người dùng không được ủy quyền truy cập dữ liệu nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Tham số 'public' được lấy từ http\_route\_parameter, tức là được người dùng kiểm soát\.
- Tham số 'public' được truyền trực tiếp vào query\.filter\_by mà không có kiểm tra quyền truy cập\.
- Không có kiểm soát quyền truy cập \(authorization guard\) nào được áp dụng cho truy vấn này\.
- Đường dẫn từ nguồn đến điểm nguy hiểm hoàn chỉnh và không bị chặn bởi bất kỳ điều kiện nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát quyền truy cập nào được áp dụng cho truy vấn cơ sở dữ liệu\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.26. LIKELY\_TP — python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cd034c12ee3adc79 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.audit\.avoid\-sqlalchemy\-text\.avoid\-sqlalchemy\-text |
| File | core\/views\.py |
| Dòng | 320 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2972 ms |
| Thời gian provider | 1922 ms |
| SHA-256 đầu vào triage | eaa53c1142e0f5e0258ca2377f19ba818b0dd1e8439df01a586f524a969b05e7 |

**Thông báo của scanner**

> SQLAlchemy text\(\) receives a dynamically constructed SQL expression\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source core\/views\.py\:314; sink core\/views\.py\:320; đường source–sink core\/views\.py\:314 → core\/views\.py\:320 → core\/views\.py\:320 → core\/views\.py\:320 → core\/views\.py\:320; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `method\_parameter\_in` `filter` tại `core\/views\.py\:314`
- Bước 2: `identifier` `filter` tại `core\/views\.py\:320`
- Bước 3: `call` `&lt;operator&gt;\.tupleLiteral` tại `core\/views\.py\:320`
- Bước 4: `call` `&lt;operator&gt;\.modulo` tại `core\/views\.py\:320`
- Bước 5: `call` `text` tại `core\/views\.py\:320`

**Đường 2 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `method\_parameter\_in` `filter` tại `core\/views\.py\:314`
- Bước 2: `identifier` `filter` tại `core\/views\.py\:314`
- Bước 3: `method\_parameter\_in` `filter` tại `core\/views\.py\:314`
- Bước 4: `identifier` `filter` tại `core\/views\.py\:320`
- Bước 5: `call` `&lt;operator&gt;\.tupleLiteral` tại `core\/views\.py\:320`
- Bước 6: `call` `&lt;operator&gt;\.modulo` tại `core\/views\.py\:320`
- Bước 7: `call` `text` tại `core\/views\.py\:320`

**Call chain / entrypoint**

- `resolve\_pastes` tại `core\/views\.py:314`
- `resolve\_pastes&lt;metaClassAdapter&gt;` tại `core\/views\.py:314`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: JOERN\_SECURITY\_CONTROL\_NOT\_FOUND
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một cuộc gọi đến hàm text\(\) trong SQLAlchemy với tham số được xây dựng động từ đầu vào người dùng\. Không có biện pháp kiểm soát hiệu quả nào được áp dụng để ngăn chặn việc truyền đầu vào không an toàn vào truy vấn SQL\.

**Bằng chứng LLM sử dụng**

- Đầu vào người dùng được truyền vào tham số 'filter' của hàm resolve\_pastes\.
- Tham số 'filter' được sử dụng trực tiếp trong chuỗi SQL được tạo bằng cách sử dụng toán tử modulo \(%\) mà không có bất kỳ biện pháp kiểm tra hoặc mã hóa nào\.
- Không có biện pháp kiểm soát nào được áp dụng để ngăn chặn việc truyền đầu vào không an toàn vào truy vấn SQL\.
- Đường dẫn taint hoàn chỉnh được xác định từ đầu vào người dùng đến tham số của hàm text\(\) trong truy vấn SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Đầu vào người dùng được coi là không an toàn và có thể chứa các ký tự đặc biệt có thể gây ra lỗi SQL injection\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.27. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d1d9209f24b72e912de8d9193b7a63b94b1974e2e2cf599a8eec2077b2b6e2fe |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 303 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_search; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=object\_lookup\_without\_subject\_scope; source\_kind=http\_route\_parameter; trace=\['entrypoint\:resolve\_search@298', 'source\:http\_route\_parameter', 'sink\:object\_lookup\_without\_subject\_scope@303'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2182 ms |
| Thời gian provider | 2180 ms |
| SHA-256 đầu vào triage | a563a0f8ac2691e754b083cd4fb614946d11aeaae2ae81f59153ac06a25b8c49 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 243\-363\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_search` tại `core\/views\.py\:303`
- Bước 2: `sink` `resolve\_search` tại `core\/views\.py\:303`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng IDOR \(Insecure Direct Object Reference\) trong hàm resolve\_search\. Tham số 'keyword' từ đường dẫn HTTP được sử dụng trực tiếp để truy vấn cơ sở dữ liệu mà không có kiểm tra xác thực hoặc giới hạn theo chủ sở hữu hoặc thuê bao\. Điều này cho phép người dùng truy cập dữ liệu không được phép\.

**Bằng chứng LLM sử dụng**

- Tham số 'keyword' từ http\_route\_parameter được truyền trực tiếp vào chuỗi truy vấn SQL mà không có kiểm tra xác thực\.
- Không có kiểm soát nào được áp dụng để đảm bảo rằng người dùng chỉ có thể truy cập dữ liệu thuộc về họ\.
- Cơ sở dữ liệu được truy cập thông qua Paste\.query\.filter\(Paste\.title\.like\(search\)\) mà không có kiểm tra xác thực\.
- Không có cơ chế xác thực hoặc kiểm soát đối tượng nào được áp dụng cho truy vấn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được áp dụng trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.28. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dece44b5e58c620f41e1e746deb0f673b449a5e30f00443eb42bb9688b3c1609 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 380–383 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=resolve\_audits; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=privileged\_endpoint\_without\_authorization; source\_kind=http\_or\_graphql\_endpoint; trace=\['entrypoint\:resolve\_audits@380', 'source\:http\_or\_graphql\_endpoint', 'sink\:privileged\_endpoint\_without\_authorization@380'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2014 ms |
| Thời gian provider | 2011 ms |
| SHA-256 đầu vào triage | 04399999c56d161f36c100167971c6df9c6796312b84342415165ba8bce55669 |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 320\-443\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `resolve\_audits` tại `core\/views\.py\:380`
- Bước 2: `sink` `resolve\_audits` tại `core\/views\.py\:381`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một điểm cuối được phơi bày \(exposed HTTP\/GraphQL endpoint\) truy cập trực tiếp đến một hoạt động đặc quyền \(Audit\.query\.all\) mà không có kiểm soát xác thực nào trong hàm chứa\. Điều này cho phép người dùng không được xác thực hoặc có quyền hạn thấp truy cập dữ liệu nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Điểm nguồn \(source\) là một endpoint HTTP\/GraphQL được xác định là do người dùng kiểm soát \(user\_controlled\: true\)\.
- Điểm đích \(sink\) là Audit\.query\.all, một hoạt động đặc quyền không có kiểm soát xác thực \(privileged\_endpoint\_without\_authorization\)\.
- Không có kiểm soát xác thực nào được phát hiện trong hàm resolve\_audits, nơi endpoint và hoạt động đặc quyền nằm trong cùng một hàm\.
- Đường dẫn taint hoàn chỉnh \(taint\_path\_complete\: true\) từ điểm nguồn đến điểm đích được xác nhận\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được thực hiện trong hàm resolve\_audits trước khi truy cập Audit\.query\.all\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.29. LIKELY\_TP — module2\.logic\.missing\-authz\-idor

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f4a81b98668488397030960ee48429905d6eb8652ff2ce2119eea0f4d3750ab1 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.logic\.missing\-authz\-idor — Bounded AST candidate for missing authz idor |
| File | core\/views\.py |
| Dòng | 442–451 |
| Severity | HIGH |
| Metadata an toàn | analysis\_complete=True; analysis\_scope=bounded\_python\_ast; component=\.; cwe=CWE\-639; entrypoint=difficulty; entrypoint\_exposed=True; guards=\[\]; logic\_class=missing\_authz\_idor; remediation=Bind the requested object to the authenticated subject or tenant before reading or mutating it\.; risk\_factors=\{'severity'\: 4\.0, 'reachability'\: 5\.0, 'exposure'\: 4\.5, 'data\_sensitivity'\: 4\.5, 'exploitability'\: 4\.0\}; risk\_level=CRITICAL; risk\_score=4\.45; sink\_kind=privileged\_endpoint\_without\_authorization; source\_kind=http\_or\_graphql\_endpoint; trace=\['entrypoint\:difficulty@442', 'source\:http\_or\_graphql\_endpoint', 'sink\:privileged\_endpoint\_without\_authorization@442'\]; validation\_checklist=\['Add a negative authorization or boundary test for the exact sink\.', 'Add a positive test for the intended authorized or bounded flow\.', 'Review the complete source\-to\-guard\-to\-sink trace\.'\] |
| Thời gian xử lý | 2448 ms |
| Thời gian provider | 2446 ms |
| SHA-256 đầu vào triage | e9fce80c63f126c15e9d08c57485f88f9f46515a8d132d81bf368d826d14ffad |

**Thông báo của scanner**

> A bounded source\-to\-guard\-to\-sink trace matched a missing authz idor pattern\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 382\-511\.

#### Evidence Source-to-Sink chi tiết

**Đường 1 — same\_file**

- File đi qua: core\/views\.py
- Bước 1: `source` `difficulty` tại `core\/views\.py\:442`
- Bước 2: `sink` `difficulty` tại `core\/views\.py\:449`

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Một điểm cuối được phơi bày \(exposed endpoint\) đã truy cập trực tiếp đến một điểm nhạy cảm \(privileged operation\) mà không có kiểm soát xác thực nào\. Không có cơ chế kiểm soát nào được phát hiện trong hàm chứa, cho phép người dùng không được xác thực thay đổi cài đặt hệ thống\.

**Bằng chứng LLM sử dụng**

- Điểm cuối \(endpoint\) được phơi bày và có thể truy cập được bởi người dùng không xác thực\.
- Không có kiểm soát xác thực nào được phát hiện trong hàm chứa để xác minh quyền truy cập\.
- Điểm nhạy cảm \(helpers\.set\_mode\) được gọi trực tiếp từ điểm cuối mà không có kiểm tra xác thực\.
- Không có cơ chế kiểm soát nào được áp dụng để giới hạn quyền truy cập đến điểm nhạy cảm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát xác thực nào được áp dụng trong hàm chứa\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Không
- **Lý do escalation:** Không có
- **Lý do policy:**
  - LLM đánh giá LIKELY\_TP với độ tin cậy HIGH\.

#### Reviewer nên làm gì tiếp theo

- Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\.
- Đánh giá khả năng khai thác và tác động trước khi tạo ticket khắc phục\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.30. LIKELY\_TP — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Có khả năng là lỗ hổng thật

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | fad4ef183220aacc |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | app\.py |
| Dòng | 14 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=CWE\-798\: Use of Hard\-coded Credentials; technology=\['flask'\] |
| Thời gian xử lý | 127814 ms |
| Thời gian provider | 127806 ms |
| SHA-256 đầu vào triage | 3291848593e5634d8ac20a86ab5aacf63eb493928d6bbd1b461ab2dae50f0c62 |

**Thông báo của scanner**

> Flask SECRET\_KEY is assigned a hardcoded string literal\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-37\.

#### Evidence Source-to-Sink chi tiết

Chưa có đường source-to-sink hoàn chỉnh được Joern chứng minh.

- Trạng thái evidence: complete
- Source resolved: True
- Sink resolved: True
- Taint path complete: True
- Reachability resolved: True
- Giới hạn: Không có
- Còn thiếu: Không có

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v14

**Kết luận ngắn gọn**

> Tìm thấy khóa bí mật được đặt cứng trong Flask, cụ thể là giá trị 'dvga' được gán cho app\.config\['SECRET\_KEY'\]\. Điều này là một lỗ hổng bảo mật vì khóa bí mật nên được lưu trữ an toàn và không nên được đặt cứng trong mã nguồn\. Không có biện pháp kiểm soát nào được phát hiện để ngăn chặn việc sử dụng khóa này\.

**Bằng chứng LLM sử dụng**

- Khóa bí mật 'dvga' được gán trực tiếp cho app\.config\['SECRET\_KEY'\] mà không có bất kỳ biện pháp kiểm soát nào\.
- Không có mã nào trong đoạn mã liên quan đến việc thay đổi hoặc kiểm tra giá trị của khóa bí mật trước khi sử dụng\.
- Không có mã nào trong đoạn mã liên quan đến việc mã hóa hoặc bảo vệ khóa bí mật trước khi lưu trữ hoặc sử dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có mã nào khác trong ứng dụng kiểm tra hoặc thay đổi giá trị của khóa bí mật\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** LIKELY\_TP — Có khả năng là lỗ hổng thật
- **Policy version:** conservative\-policy\-v2
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
- Không có lỗi scanner.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
