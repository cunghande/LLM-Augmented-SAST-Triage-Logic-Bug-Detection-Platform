# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 46 |
| Triage thành công | 46 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 240\.522734 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 46 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | defc279b\-46a1\-4a75\-8967\-a0707f48cb69 |
| Repository | realvuln\-vulpy |
| Repository identifier | realvuln\-vulpy |
| Commit | 5249cc8b05a1c37f6b2f757b1cf16a509c327122 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | UNVERIFIED |
| Provider | real\-modal\-qwen |
| Model | Qwen\/Qwen3\-14B\-AWQ |
| Prompt version | triage\-prompt\-v10 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 31\.892008 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | triage\-resume |
| Bắt đầu | 2026\-08\-13T02\:46\:38\.784484\+00\:00 |
| Kết thúc | 2026\-08\-13T02\:50\:39\.307218\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS
- Thành công: SEMGREP; GITLEAKS
- Phiên bản: GITLEAKS=null; SEMGREP=1\.150\.0
- Cấu hình: GITLEAKS=artifact\-provided; SEMGREP=artifact\-provided
- Hash artifact: gitleaks=21ab839157f531ef0c1a56e6cb6c9c039e77fab6b3a0466ab2146f4231071ff4; semgrep=126d7e40da54fbcd8a367cd6cc57f3126389cd69c39303cb6eb92214d5dc18e0

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 1d51027f2fd7ae27 | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | good\/vulpy\-ssl\.py\:13 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 2 | MANUAL\_REVIEW | HIGH | 2ff8687baced64a3 | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | bad\/vulpy\-ssl\.py\:13 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 3 | MANUAL\_REVIEW | HIGH | 37168578a5da911e | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | bad\/libuser\.py\:25 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 4 | MANUAL\_REVIEW | HIGH | 3a538d0b1299c950 | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | bad\/vulpy\.py\:16 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 5 | MANUAL\_REVIEW | HIGH | 3d074bbedf508cb6 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | good\/libuser\.py\:61 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 6 | MANUAL\_REVIEW | HIGH | 3e28cd3bc1488c0a | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | bad\/db\.py\:19 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 7 | MANUAL\_REVIEW | HIGH | 3e57f3d950fdb970 | python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret | good\/libapi\.py\:20–24 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 40c9d7d3a56360a1 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | bad\/libuser\.py\:53 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 9 | MANUAL\_REVIEW | HIGH | 526bda8607e646a0 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | bad\/db\_init\.py\:20 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 10 | MANUAL\_REVIEW | HIGH | cac70591fb5ef7f6 | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | good\/vulpy\.py\:17 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 11 | MANUAL\_REVIEW | HIGH | de021710eb4d5f15 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | bad\/libuser\.py\:12 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 12 | MANUAL\_REVIEW | MEDIUM | 011a9b72f1e1a683 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/user\.create\.html\:8–18 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | 0cca474c7a5e2b43 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/user\.login\.mfa\.html\:8–18 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | MEDIUM | 1e377e28b39f02b6 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/posts\.view\.html\:13–17 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | MEDIUM | 1e6174273681af15 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | bad\/db\.py\:19 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 16 | MANUAL\_REVIEW | MEDIUM | 2c54f5c2ed58b42d | html\.security\.audit\.missing\-integrity\.missing\-integrity | good\/templates\/csp\.html\:29 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 17 | MANUAL\_REVIEW | MEDIUM | 3091de9ca806ff17 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | bad\/libuser\.py\:12 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 18 | MANUAL\_REVIEW | MEDIUM | 332b8bb925671889 | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly | good\/vulpy\-ssl\.py\:29 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 19 | MANUAL\_REVIEW | MEDIUM | 3986cd03b14e7ba8 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/user\.login\.html\:8–16 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 20 | MANUAL\_REVIEW | MEDIUM | 43b2d60924f0e88a | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/welcome\.html\:7–11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 21 | MANUAL\_REVIEW | MEDIUM | 4d631987ca4dca77 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | good\/libuser\.py\:61 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 22 | MANUAL\_REVIEW | MEDIUM | 53960e892b8ff2f9 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/user\.create\.html\:8–18 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 23 | MANUAL\_REVIEW | MEDIUM | 56fb83c98d255d16 | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly | bad\/vulpy\.py\:55 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 24 | MANUAL\_REVIEW | MEDIUM | 648e8b5e57eb598d | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | good\/vulpy\-ssl\.py\:29 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 25 | MANUAL\_REVIEW | MEDIUM | 73dbb58826611650 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/user\.login\.html\:8–16 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 26 | MANUAL\_REVIEW | MEDIUM | 746dbb65ec7558b7 | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | good\/vulpy\.py\:53 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 27 | MANUAL\_REVIEW | MEDIUM | a0616e58cf6898bf | html\.security\.audit\.missing\-integrity\.missing\-integrity | bad\/templates\/csp\.html\:29 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 28 | MANUAL\_REVIEW | MEDIUM | a666b540485fb6f8 | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | bad\/vulpy\.py\:55 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 29 | MANUAL\_REVIEW | MEDIUM | a9c1f13b8c6abf07 | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly | good\/vulpy\.py\:53 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 30 | MANUAL\_REVIEW | MEDIUM | ab9b82a9aff35e69 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/user\.chpasswd\.html\:8–18 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 31 | MANUAL\_REVIEW | MEDIUM | ace5bb7a6af8ac22 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/posts\.view\.html\:13–17 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 32 | MANUAL\_REVIEW | MEDIUM | adf665360aa247f9 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/welcome\.html\:7–11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 33 | MANUAL\_REVIEW | MEDIUM | c266773e399a7a26 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/mfa\.enable\.html\:8–14 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 34 | MANUAL\_REVIEW | MEDIUM | ca4e3b3919147486 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/user\.login\.mfa\.html\:8–18 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 35 | MANUAL\_REVIEW | MEDIUM | dbf58e57323ff6a8 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | bad\/libuser\.py\:53 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 36 | MANUAL\_REVIEW | MEDIUM | dcfb79a96144daf2 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | bad\/templates\/user\.chpasswd\.html\:8–16 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 37 | MANUAL\_REVIEW | MEDIUM | dd6307aab57330b7 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | bad\/libuser\.py\:25 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 38 | MANUAL\_REVIEW | MEDIUM | de759a4a995eb2b7 | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token | good\/templates\/mfa\.enable\.html\:8–14 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 39 | MANUAL\_REVIEW | MEDIUM | f29e3127da6ed974 | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly | bad\/vulpy\-ssl\.py\:29 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 40 | MANUAL\_REVIEW | MEDIUM | f86cd02ab143c2cd | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | bad\/vulpy\-ssl\.py\:29 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 41 | MANUAL\_REVIEW | MEDIUM | ff69c30538379b32 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | bad\/db\_init\.py\:20 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 42 | MANUAL\_REVIEW | LOW | b53fb9ac34ad38c6 | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http | good\/httpbrute\.py\:22 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 43 | MANUAL\_REVIEW | LOW | cf6b240882b17e33 | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http | bad\/api\_post\.py\:16 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 44 | MANUAL\_REVIEW | LOW | d45148c24594cd09 | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http | bad\/api\_post\.py\:30 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 45 | MANUAL\_REVIEW | LOW | fdfc85de4c5baf6e | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http | bad\/api\_list\.py\:10 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |
| 46 | MANUAL\_REVIEW | UNKNOWN | e87f90af6848dff4 | generic\-api\-key | good\/libsession\.py\:9 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / LOW — Thấp |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1d51027f2fd7ae27 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | good\/vulpy\-ssl\.py |
| Dòng | 13 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 2080 ms |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source good\/vulpy\-ssl\.py\:13; sink chưa xác định; đường source–sink good\/vulpy\-ssl\.py\:13; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện biến \`SECRET\_KEY\` được đặt cứng trong mã nguồn, nhưng giá trị này không được sử dụng trong bất kỳ điểm nhạy cảm nào\. Giá trị \`SECRET\_KEY\` được gán là một hằng số cục bộ và không ảnh hưởng đến bất kỳ hoạt động bảo mật nào\. Do đó, đây là một báo cáo sai dương\.

**Bằng chứng LLM sử dụng**

- Biến \`SECRET\_KEY\` được gán giá trị \`'aaaaaaa'\` là một hằng số cục bộ, không đến từ đầu vào người dùng\.
- Không có điểm nhạy cảm \(sink\) nào được xác định trong mã nguồn sử dụng giá trị \`SECRET\_KEY\`\.
- Phân tích taint path cho thấy giá trị \`SECRET\_KEY\` không đạt đến bất kỳ điểm nhạy cảm nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có điểm nhạy cảm nào trong mã nguồn phụ thuộc vào giá trị \`SECRET\_KEY\`\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.2. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2ff8687baced64a3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | bad\/vulpy\-ssl\.py |
| Dòng | 13 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 2293 ms |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source bad\/vulpy\-ssl\.py\:13; sink chưa xác định; đường source–sink bad\/vulpy\-ssl\.py\:13; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện biến \`SECRET\_KEY\` được đặt cứng trong mã nguồn, nhưng giá trị này không được sử dụng trong bất kỳ điểm nhạy cảm nào\. Giá trị \`SECRET\_KEY\` được gán là một hằng số cục bộ và không ảnh hưởng đến bất kỳ hoạt động bảo mật nào\. Do đó, đây là một báo cáo sai dương\.

**Bằng chứng LLM sử dụng**

- Biến \`SECRET\_KEY\` được gán giá trị \`'aaaaaaa'\` là một hằng số cục bộ, không đến từ đầu vào người dùng\.
- Không có điểm nhạy cảm \(sink\) nào được xác định trong mã nguồn sử dụng giá trị \`SECRET\_KEY\`\.
- Phân tích taint path cho thấy giá trị \`SECRET\_KEY\` không đạt đến bất kỳ điểm nhạy cảm nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có điểm nhạy cảm nào trong mã nguồn phụ thuộc vào giá trị \`SECRET\_KEY\`\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.3. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 37168578a5da911e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | bad\/libuser\.py |
| Dòng | 25 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2166 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/libuser\.py\:25; sink bad\/libuser\.py\:25; đường source–sink bad\/libuser\.py\:25; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tuy có sử dụng chuỗi SQL thô, nhưng đầu vào không được kiểm soát bởi người dùng\. Giá trị cuối cùng được ghi đè bằng hằng số an toàn, không có lỗ hổng SQL Injection\.

**Bằng chứng LLM sử dụng**

- Đầu vào username và password được truyền vào như tham số, nhưng không có bằng chứng cho thấy chúng được kiểm soát bởi người dùng\.
- Câu lệnh SQL được xây dựng bằng cách sử dụng chuỗi thô, nhưng không có tham số nào được thay thế bằng giá trị đầu vào không an toàn\.
- Không có bằng chứng cho thấy giá trị đầu vào được sử dụng trực tiếp trong chuỗi SQL\.
- Các tham số được truyền vào như một tuple, nhưng không có tham số nào được thay thế bằng giá trị đầu vào không an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng username và password không phải là đầu vào từ người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.4. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3a538d0b1299c950 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | bad\/vulpy\.py |
| Dòng | 16 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 2542 ms |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện biến \`SECRET\_KEY\` được đặt cứng trong mã nguồn Flask\. Điều này là một lỗ hổng bảo mật vì giá trị bí mật nên được lưu trữ trong biến môi trường hoặc tệp cấu hình thay vì mã nguồn\. Mã nguồn không có bất kỳ biện pháp kiểm soát nào để ngăn chặn việc sử dụng giá trị cố định này\.

**Bằng chứng LLM sử dụng**

- Biến \`SECRET\_KEY\` được gán giá trị cố định \`'aaaaaaa'\` trong mã nguồn\.
- Không có kiểm soát bảo mật nào được áp dụng để thay thế giá trị này bằng giá trị từ môi trường hoặc tệp cấu hình\.
- Thông báo lỗi từ scanner xác nhận việc phát hiện biến \`SECRET\_KEY\` được đặt cứng\.
- Không có giá trị thay thế hoặc kiểm tra điều kiện nào được thực hiện trước khi gán giá trị cho \`SECRET\_KEY\`\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng giá trị \`'aaaaaaa'\` là một khóa bí mật nhạy cảm và không nên được lưu trữ trong mã nguồn\.
- Giả sử rằng không có cơ chế nào trong mã nguồn để tải khóa bí mật từ môi trường hoặc tệp cấu hình\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.5. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3d074bbedf508cb6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | good\/libuser\.py |
| Dòng | 61 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2063 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source good\/libuser\.py\:61; sink good\/libuser\.py\:61; đường source–sink good\/libuser\.py\:61; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy rằng giá trị đầu vào không được kiểm soát bởi người dùng không được sử dụng trong truy vấn SQL\. Thay vào đó, giá trị được truyền dưới dạng tham số an toàn trong tuple, và không có dấu hiệu của việc nối chuỗi SQL nguy hiểm\.

**Bằng chứng LLM sử dụng**

- Giá trị 'username' được truyền dưới dạng tham số trong tuple \(username,\) khi thực thi truy vấn SQL\.
- Không có dấu hiệu của việc nối chuỗi SQL nguy hiểm hoặc sử dụng chuỗi thô \(raw SQL\) không an toàn\.
- Taint path không cho thấy giá trị đầu vào người dùng ảnh hưởng đến truy vấn SQL\.
- Các tham số được truyền dưới dạng tuple, đảm bảo rằng chúng được xử lý an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'username' không phải là giá trị đầu vào người dùng không được kiểm soát\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.6. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3e28cd3bc1488c0a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | bad\/db\.py |
| Dòng | 19 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2470 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/db\.py\:19; sink bad\/db\.py\:19; đường source–sink bad\/db\.py\:19; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tuy có sử dụng chuỗi SQL thô, nhưng giá trị đầu vào không đến từ nguồn bị kiểm soát bởi người tấn công\. Giá trị được sử dụng là hằng số cục bộ và không có bất kỳ cơ chế nào cho phép đầu vào từ người dùng\. Do đó, đây là một lỗi giả dương\.

**Bằng chứng LLM sử dụng**

- Giá trị đầu vào \(u, p, 0\) là các hằng số cục bộ, không đến từ bất kỳ nguồn nào bị kiểm soát bởi người tấn công\.
- Không có bất kỳ điều kiện nào trong mã cho phép đầu vào từ người dùng ảnh hưởng đến chuỗi SQL\.
- Câu lệnh SQL được xây dựng bằng cách sử dụng các giá trị hằng số, không có tham số được truyền vào từ bên ngoài\.
- Không có cơ chế nào trong mã cho phép đầu vào từ người dùng ảnh hưởng đến giá trị được sử dụng trong câu lệnh SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có bất kỳ nguồn nào bị kiểm soát bởi người tấn công được sử dụng trong mã\.
- Không có bất kỳ điều kiện nào trong mã cho phép đầu vào từ người dùng ảnh hưởng đến giá trị được sử dụng trong câu lệnh SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.7. MANUAL\_REVIEW — python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3e57f3d950fdb970 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret |
| File | good\/libapi\.py |
| Dòng | 20–24 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-522\: Insufficiently Protected Credentials'\]; owasp=\['A02\:2017 \- Broken Authentication', 'A04\:2021 \- Insecure Design', 'A06\:2025 \- Insecure Design'\]; references=\['https\:\/\/semgrep\.dev\/blog\/2020\/hardcoded\-secrets\-unverified\-tokens\-and\-other\-common\-jwt\-mistakes\/'\]; technology=\['jwt'\] |
| Thời gian xử lý | 2351 ms |

**Thông báo của scanner**

> Hardcoded JWT secret or private key is used\. This is a Insufficiently Protected Credentials weakness\: https\:\/\/cwe\.mitre\.org\/data\/definitions\/522\.html Consider using an appropriate security mechanism to protect the credentials \(e\.g\. keeping secrets in environment variables\)

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một khóa bí mật JWT được mã hóa cứng trong mã nguồn\. Tuy nhiên, không có thông tin đầy đủ để xác định liệu khóa này có được sử dụng cho mục đích bảo mật hay không\. Cần xem xét thêm ngữ cảnh sử dụng khóa này\.

**Bằng chứng LLM sử dụng**

- Khóa bí mật được khai báo là '&lt;REDACTED\_SECRET&gt;', có thể là một giá trị cố định\.
- Khóa được sử dụng trong hàm 'jwt\.encode' và 'jwt\.decode' để tạo và xác thực token\.
- Không có thông tin về việc khóa này được lưu trữ an toàn hay được bảo vệ bằng cơ chế nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về cách khóa được sử dụng trong ứng dụng\.
- Không có thông tin về việc khóa có được bảo vệ bằng biến môi trường hay không\.

**Giả định LLM đã sử dụng**

- Khóa được khai báo là một giá trị cố định, có thể là một mật khẩu hoặc khóa riêng tư\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.8. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 40c9d7d3a56360a1 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | bad\/libuser\.py |
| Dòng | 53 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2818 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/mod\_user\.py\:70; sink bad\/libuser\.py\:53; đường source–sink bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:72 → bad\/mod\_user\.py\:72 → bad\/mod\_user\.py\:76 → bad\/libuser\.py\:59 → bad\/mod\_user\.py\:76; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng chuỗi SQL thô với đầu vào không đáng tin cậy, dẫn đến nguy cơ lỗ hổng SQL Injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng\. Đường dẫn từ nguồn đến điểm nguy hiểm được xác nhận đầy đủ\.

**Bằng chứng LLM sử dụng**

- Đầu vào người dùng được truyền trực tiếp vào chuỗi SQL thô thông qua phương thức \.format\(\), không sử dụng tham số được chuẩn bị\.
- Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn SQL Injection\.
- Đường dẫn taint từ nguồn người dùng đến điểm nguy hiểm được xác nhận đầy đủ\.
- Cú pháp SQL thô được sử dụng mà không có bất kỳ cơ chế bảo vệ nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Đầu vào người dùng được coi là không đáng tin cậy\.
- Không có cơ chế kiểm soát an toàn nào được áp dụng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.9. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 526bda8607e646a0 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | bad\/db\_init\.py |
| Dòng | 20 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 2259 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/db\_init\.py\:20; sink bad\/db\_init\.py\:20; đường source–sink bad\/db\_init\.py\:20; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tuy có sử dụng chuỗi SQL thô, nhưng giá trị đầu vào không đến từ nguồn bị kiểm soát bởi người dùng\. Giá trị được sử dụng là hằng số cục bộ và không có bất kỳ tham số nào được truyền từ bên ngoài\. Do đó, không có nguy cơ SQL Injection\.

**Bằng chứng LLM sử dụng**

- Giá trị 'u' và 'p' được lấy từ danh sách cục bộ, không đến từ đầu vào người dùng\.
- Câu lệnh SQL được xây dựng bằng cách sử dụng chuỗi thô và tuple chứa các giá trị cục bộ, không có tham số được truyền từ bên ngoài\.
- Không có nguồn bị kiểm soát bởi người dùng nào được xác định trong chuỗi taint\.
- Phân tích xác minh cục bộ đã chứng minh rằng giá trị đầu vào không thể đến từ nguồn bị kiểm soát bởi người dùng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Danh sách 'users' chứa các giá trị cố định và không bị ảnh hưởng bởi đầu vào người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.10. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cac70591fb5ef7f6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | good\/vulpy\.py |
| Dòng | 17 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 2465 ms |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện biến \`SECRET\_KEY\` được đặt cứng trong mã nguồn, nhưng không có thông tin đầy đủ để xác định liệu đây có phải là lỗ hổng bảo mật hay không\. Cần xem xét thêm ngữ cảnh cụ thể về cách \`SECRET\_KEY\` được sử dụng và có hay không các biện pháp bảo vệ khác\.

**Bằng chứng LLM sử dụng**

- Biến \`SECRET\_KEY\` được gán giá trị cố định trong mã nguồn\.
- Không có thông tin về việc \`SECRET\_KEY\` được sử dụng trong các hoạt động nhạy cảm như xác thực, mã hóa, hoặc lưu trữ dữ liệu bảo mật\.
- Không có kiểm soát bảo mật rõ ràng hoặc việc sử dụng biến môi trường để thay thế giá trị này\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về cách \`SECRET\_KEY\` được sử dụng trong ứng dụng\.
- Không có thông tin về việc có hay không các biện pháp bảo vệ như kiểm tra giá trị, mã hóa, hoặc xác thực\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc đặt \`SECRET\_KEY\` cố định có thể gây rủi ro bảo mật nếu nó được sử dụng cho các mục đích nhạy cảm\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.11. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | de021710eb4d5f15 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | bad\/libuser\.py |
| Dòng | 12 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 3326 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/mod\_user\.py\:16; sink bad\/libuser\.py\:12; đường source–sink bad\/mod\_user\.py\:16 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:20 → bad\/libuser\.py\:5 → bad\/libuser\.py\:12 → bad\/libuser\.py\:12; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy việc nối chuỗi SQL không an toàn bằng cách sử dụng phương thức format\(\) với đầu vào không đáng tin cậy\. Điều này có thể dẫn đến lỗ hổng SQL Injection\. SQLAlchemy không sử dụng prepared statement hoặc các phương pháp an toàn khác\.

**Bằng chứng LLM sử dụng**

- Đầu vào username và password được truyền vào hàm login\(\) và được sử dụng trực tiếp trong truy vấn SQL mà không có bất kỳ biện pháp bảo vệ nào\.
- Các truy vấn SQL được xây dựng bằng cách sử dụng phương thức format\(\) với các giá trị đầu vào không được kiểm tra hoặc xử lý\.
- Không có cơ chế kiểm soát an toàn như prepared statement hoặc SQL Expression Language được sử dụng\.
- Đường dẫn taint hoàn chỉnh từ đầu vào người dùng đến truy vấn SQL được xác nhận\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng username và password là đầu vào không đáng tin cậy từ người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.12. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 011a9b72f1e1a683 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/user\.create\.html |
| Dòng | 8–18 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2364 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form thủ công trong Django template\. Tuy nhiên, không có thông tin đầy đủ về việc liệu form này có thực sự xử lý dữ liệu nhạy cảm hay không, cũng như không có bằng chứng về việc liệu có cơ chế bảo vệ nào được áp dụng trong quá trình xử lý yêu cầu\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc liệu form này có thực sự xử lý dữ liệu nhạy cảm hay không\.
- Không có bằng chứng về việc liệu có cơ chế bảo vệ nào được áp dụng trong quá trình xử lý yêu cầu\.
- Không thể xác định được liệu có tồn tại một đường dẫn taint hoàn chỉnh từ nguồn người dùng đến điểm nguy hiểm hay không\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về liệu form này có xử lý dữ liệu nhạy cảm hay không\.
- Thông tin về cơ chế bảo vệ được áp dụng trong quá trình xử lý yêu cầu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu CSRF token có thể là một lỗ hổng bảo mật nếu form này xử lý dữ liệu nhạy cảm\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.13. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0cca474c7a5e2b43 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/user\.login\.mfa\.html |
| Dòng | 8–18 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2449 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form thủ công trong Django template\. Tuy nhiên, không có thông tin đầy đủ để xác định liệu form này có thực sự tiếp nhận dữ liệu từ người dùng hay không, cũng như không có thông tin về các biện pháp bảo mật được áp dụng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc form có xử lý dữ liệu đầu vào từ người dùng hay không\.
- Không có thông tin về các biện pháp bảo mật như CSRF token hoặc các kiểm tra bảo mật khác được áp dụng\.
- Không thể xác định được liệu form này có thể bị tấn công CSRF hay không do thiếu thông tin về cách xử lý dữ liệu\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách xử lý dữ liệu đầu vào trong form\.
- Thông tin về các biện pháp bảo mật được áp dụng trong template\.
- Thông tin về các hàm hoặc logic xử lý form trong backend\.

**Giả định LLM đã sử dụng**

- Giả sử rằng form này có thể nhận dữ liệu từ người dùng\.
- Giả sử rằng không có biện pháp bảo mật nào được áp dụng ngoài việc thiếu CSRF token\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.14. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1e377e28b39f02b6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/posts\.view\.html |
| Dòng | 13–17 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2247 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form được tạo thủ công trong Django template\. Tuy nhiên, không thể xác định chắc chắn liệu form này có thực sự gửi dữ liệu nhạy cảm hay không, cũng như không có thông tin về cách xử lý form trong view\. Do đó, cần xem xét thêm\.

**Bằng chứng LLM sử dụng**

- Form được tạo thủ công trong template mà không có csrf\_token\.
- Không có thông tin về cách xử lý form trong view, không thể xác định liệu form này có thực sự nhạy cảm hay không\.
- Không có thông tin về các kiểm soát bảo mật liên quan đến CSRF trong đoạn mã được cung cấp\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách xử lý form trong view\.
- Thông tin về các kiểm soát bảo mật CSRF được áp dụng trong ứng dụng\.

**Giả định LLM đã sử dụng**

- Form này có thể gửi dữ liệu nhạy cảm, nhưng không có bằng chứng rõ ràng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.15. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1e6174273681af15 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | bad\/db\.py |
| Dòng | 19 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 2533 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/db\.py\:19; sink bad\/db\.py\:19; đường source–sink bad\/db\.py\:19; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi SQL injection có thể, nhưng không có dữ liệu người dùng được truyền vào truy vấn SQL\. Truy vấn SQL được xây dựng từ các hằng số cục bộ, không có nguồn dữ liệu người dùng\. Do đó, không có nguy cơ SQL injection\.

**Bằng chứng LLM sử dụng**

- Truy vấn SQL được xây dựng từ các hằng số cục bộ như 'admin', '123456', 'john', 'Password', 'tim', 'Vaider2', và 0\.
- Không có giá trị nào từ request, form, hoặc bất kỳ nguồn nào được kiểm soát bởi người dùng được sử dụng trong truy vấn SQL\.
- Các giá trị được sử dụng trong truy vấn SQL là cố định và không phụ thuộc vào đầu vào từ người dùng\.
- Phân tích taint\_path cho thấy không có nguồn dữ liệu người dùng nào đạt đến tham số nguy hiểm trong truy vấn SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có giá trị nào từ request, form, hoặc bất kỳ nguồn nào được kiểm soát bởi người dùng được sử dụng trong truy vấn SQL\.
- Các giá trị được sử dụng trong truy vấn SQL là cố định và không phụ thuộc vào đầu vào từ người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.16. MANUAL\_REVIEW — html\.security\.audit\.missing\-integrity\.missing\-integrity

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2c54f5c2ed58b42d |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | html\.security\.audit\.missing\-integrity\.missing\-integrity |
| File | good\/templates\/csp\.html |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-353\: Missing Support for Integrity Check'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A08\_2021\-Software\_and\_Data\_Integrity\_Failures'\]; technology=\['html'\] |
| Thời gian xử lý | 2176 ms |

**Thông báo của scanner**

> This tag is missing an 'integrity' subresource integrity attribute\. The 'integrity' attribute allows for the browser to verify that externally hosted files \(for example from a CDN\) are delivered without unexpected manipulation\. Without this attribute, if an attacker can modify the externally hosted resource, this could lead to XSS and other types of attacks\. To prevent this, include the base64\-encoded cryptographic hash of the resource \(file\) you’re telling the browser to fetch in the 'integrity' attribute for all externally hosted files\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện thiếu thuộc tính 'integrity' cho tài nguyên bên ngoài là hợp lệ, nhưng không có thông tin đầy đủ để xác định liệu tài nguyên được tải từ CDN hay không\. Không có bằng chứng cụ thể cho thấy tài nguyên đó có thể bị thay đổi bởi người tấn công\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc tài nguyên được tải từ CDN hay không\.
- Không có bằng chứng cho thấy tài nguyên có thể bị thay đổi bởi người tấn công\.
- Không có thông tin về việc thuộc tính 'integrity' có được thêm vào hay không\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về nguồn tài nguyên được tải \(CDN hay không\)\.
- Thông tin về việc tài nguyên có thể bị thay đổi bởi người tấn công hay không\.

**Giả định LLM đã sử dụng**

- Tài nguyên được tải từ CDN có thể bị thay đổi bởi người tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.17. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3091de9ca806ff17 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | bad\/libuser\.py |
| Dòng | 12 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 3391 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/mod\_user\.py\:16; sink bad\/libuser\.py\:12; đường source–sink bad\/mod\_user\.py\:16 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:17 → bad\/mod\_user\.py\:20 → bad\/libuser\.py\:5 → bad\/libuser\.py\:12 → bad\/libuser\.py\:12; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được xây dựng bằng cách sử dụng phương thức format\(\) với các tham số username và password, có thể bị tấn công SQL injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn việc này\.

**Bằng chứng LLM sử dụng**

- Các tham số username và password được truyền vào từ bên ngoài, có thể bị kiểm soát bởi người dùng\.
- Các tham số này được sử dụng trực tiếp trong truy vấn SQL mà không được tham số hóa\.
- Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn SQL injection\.
- Đường dẫn taint hoàn chỉnh từ nguồn người dùng đến điểm nguy hiểm trong truy vấn SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng username và password được truyền vào từ các nguồn không an toàn như request\.form hoặc request\.args\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.18. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 332b8bb925671889 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly |
| File | good\/vulpy\-ssl\.py |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 2310 ms |

**Thông báo của scanner**

> top\-level app\.run\(\.\.\.\) is ignored by flask\. Consider putting app\.run\(\.\.\.\) behind a guard, like inside a function

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink good\/vulpy\-ssl\.py\:29; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc cảnh báo về việc sử dụng app\.run\(\) ở cấp độ cao có thể không phải là lỗ hổng\. Trong đoạn mã, app\.run\(\) được gọi với các tham số cụ thể và không có bằng chứng cho thấy nó bị bỏ qua bởi Flask\. Ngoài ra, không có luồng taint nào được xác định từ đầu vào người dùng đến app\.run\(\)\.

**Bằng chứng LLM sử dụng**

- app\.run\(\) được gọi với các tham số cụ thể \(debug\=True, host\='127\.0\.1\.1', ssl\_context\=\('\/tmp\/acme\.cert', '\/tmp\/acme\.key'\)\) và không có bằng chứng cho thấy nó bị bỏ qua\.
- Không có luồng taint nào được xác định từ đầu vào người dùng đến app\.run\(\)\.
- Không có nguồn đầu vào người dùng nào được xác định trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có luồng taint nào từ đầu vào người dùng đến app\.run\(\) trong đoạn mã\.
- app\.run\(\) không bị bỏ qua bởi Flask trong ngữ cảnh này\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.19. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3986cd03b14e7ba8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/user\.login\.html |
| Dòng | 8–16 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2305 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu csrf\_token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu có tồn tại lỗ hổng CSRF thực sự hay không\. Cần xem xét thêm các yếu tố bảo mật khác và kiểm tra xem form có được bảo vệ bằng các cơ chế CSRF khác không\.

**Bằng chứng LLM sử dụng**

- Form được tạo thủ công trong template nhưng không có csrf\_token được chỉ định\.
- Không có thông tin về việc form này có được bảo vệ bằng các cơ chế CSRF khác \(ví dụ\: middleware hoặc decorator\)\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về việc form này có được xử lý bởi các middleware hoặc decorator bảo vệ CSRF hay không\.
- Không có thông tin về cách form này được xử lý trong view, liệu có sử dụng hàm như csrf\_exempt hay không\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu csrf\_token trong template có thể dẫn đến lỗ hổng CSRF, nhưng cần kiểm tra thêm các yếu tố bảo mật khác\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.20. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 43b2d60924f0e88a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/welcome\.html |
| Dòng | 7–11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2420 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu form này có phải là 'manually\-created' hay không\. Không có bằng chứng cụ thể về việc nguồn dữ liệu hoặc lỗ hổng được xác định rõ ràng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc form được tạo thủ công hay không\.
- Không có bằng chứng về việc nguồn dữ liệu hoặc lỗ hổng được xác định rõ ràng\.
- Không có thông tin về việc có kiểm soát bảo mật nào được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách form được tạo \(tự động hay thủ công\)\.
- Thông tin về việc có kiểm soát bảo mật nào được áp dụng\.
- Thông tin về nguồn dữ liệu và lỗ hổng cụ thể\.

**Giả định LLM đã sử dụng**

- Giả sử rằng form trong template có thể là 'manually\-created', nhưng không có bằng chứng rõ ràng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.21. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4d631987ca4dca77 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | good\/libuser\.py |
| Dòng | 61 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 2120 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source good\/libuser\.py\:61; sink good\/libuser\.py\:61; đường source–sink good\/libuser\.py\:61; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được định dạng, nhưng giá trị đầu vào không đến từ nguồn do người dùng kiểm soát\. Giá trị được sử dụng trong truy vấn là một hằng số cục bộ, không có bất kỳ tham số nào đến từ đầu vào người dùng\. Do đó, không có nguy cơ SQL injection\.

**Bằng chứng LLM sử dụng**

- Truy vấn SQL được thực thi với các tham số cố định như \('', '', 0, 0, ''\) không đến từ đầu vào người dùng\.
- Không có giá trị nào từ request hoặc đầu vào người dùng được truyền vào truy vấn SQL\.
- Các tham số trong truy vấn SQL là các hằng số cục bộ, không bị nhiễm taint từ nguồn người dùng\.
- Đoạn mã không sử dụng bất kỳ giá trị nào từ request\.form, request\.args, hoặc các nguồn tương tự\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có giá trị nào từ request hoặc đầu vào người dùng được truyền vào truy vấn SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.22. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 53960e892b8ff2f9 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/user\.create\.html |
| Dòng | 8–18 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2215 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form thủ công trong Django template\. Tuy nhiên, không có thông tin đầy đủ về việc liệu form này có thực sự xử lý dữ liệu nhạy cảm hay không, cũng như không có bằng chứng về việc liệu có cơ chế bảo vệ nào được áp dụng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc liệu form này có xử lý dữ liệu nhạy cảm hay không\.
- Không có bằng chứng về việc liệu có cơ chế bảo vệ CSRF nào được áp dụng\.
- Không thể xác định được liệu có tồn tại một đường dẫn taint hoàn chỉnh từ nguồn người dùng đến điểm nguy hiểm hay không\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về liệu form này có xử lý dữ liệu nhạy cảm hay không\.
- Thông tin về cơ chế bảo vệ CSRF có thể đã được áp dụng\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu CSRF token có thể là một lỗ hổng nếu form này xử lý dữ liệu nhạy cảm\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.23. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 56fb83c98d255d16 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly |
| File | bad\/vulpy\.py |
| Dòng | 55 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 2293 ms |

**Thông báo của scanner**

> top\-level app\.run\(\.\.\.\) is ignored by flask\. Consider putting app\.run\(\.\.\.\) behind a guard, like inside a function

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink bad\/vulpy\.py\:55; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc cảnh báo về việc sử dụng app\.run\(\) ở cấp độ cao không phải là lỗ hổng bảo mật\. Trong ngữ cảnh này, app\.run\(\) được gọi với các tham số cụ thể và không có bất kỳ nguồn đầu vào nào từ người dùng\. Do đó, đây là một giả dương\.

**Bằng chứng LLM sử dụng**

- app\.run\(\) được gọi với các tham số cố định \(debug\=True, host\='127\.0\.1\.1', port\=5000, extra\_files\='csp\.txt'\) không phụ thuộc vào đầu vào người dùng\.
- Không có nguồn đầu vào từ người dùng nào được truyền vào app\.run\(\) hoặc các tham số liên quan\.
- Không có cơ chế bảo mật nào bị bỏ qua hoặc không được kiểm soát trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có mã khác ngoài đoạn mã được cung cấp ảnh hưởng đến app\.run\(\) hoặc các tham số của nó\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.24. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 648e8b5e57eb598d |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | good\/vulpy\-ssl\.py |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 2195 ms |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink good\/vulpy\-ssl\.py\:29; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy cờ debug\=True được bật trong ứng dụng Flask\. Điều này có thể gây rò rỉ thông tin nhạy cảm khi triển khai vào môi trường sản xuất\. Không có biện pháp kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ này\.

**Bằng chứng LLM sử dụng**

- Cờ debug\=True được bật trong phương thức app\.run\(\) tại dòng 29\.
- Không có kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ debug\.
- Thông báo lỗi từ scanner cho thấy cờ debug\=True có thể gây rò rỉ thông tin nhạy cảm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát an ninh nào được thực hiện để vô hiệu hóa cờ debug\.
- Không có giá trị mặc định hoặc cấu hình môi trường nào được sử dụng để thiết lập cờ debug\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.25. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 73dbb58826611650 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/user\.login\.html |
| Dòng | 8–16 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2333 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu csrf\_token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu có tồn tại lỗ hổng CSRF thực sự hay không\. Cần xem xét thêm các yếu tố bảo mật khác và kiểm tra xem form có được bảo vệ bằng các cơ chế CSRF khác không\.

**Bằng chứng LLM sử dụng**

- Form được tạo thủ công trong template nhưng không có csrf\_token được chỉ định\.
- Không có thông tin về việc form này có được bảo vệ bằng các cơ chế CSRF khác \(ví dụ\: middleware hoặc decorator\)\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về việc form này có được bảo vệ bằng các cơ chế CSRF khác \(ví dụ\: middleware hoặc decorator\)\.
- Không có thông tin về cách xử lý form trong view, liệu có sử dụng hàm như csrf\_exempt hay không\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu csrf\_token trong template có thể dẫn đến lỗ hổng CSRF, nhưng cần kiểm tra thêm các cơ chế bảo vệ khác\.
- Giả sử rằng form này có thể bị tấn công CSRF nếu không được bảo vệ đầy đủ\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.26. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 746dbb65ec7558b7 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | good\/vulpy\.py |
| Dòng | 53 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 2199 ms |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink good\/vulpy\.py\:53; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy cờ debug\=True được bật trong ứng dụng Flask\. Điều này có thể gây rò rỉ thông tin nhạy cảm khi triển khai vào môi trường sản xuất\. Không có biện pháp kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ này\.

**Bằng chứng LLM sử dụng**

- Cờ debug\=True được bật trong lệnh app\.run\(debug\=True, host\='127\.0\.1\.1', port\=5001, extra\_files\='csp\.txt'\)
- Không có kiểm soát an ninh nào được xác nhận để vô hiệu hóa hoặc kiểm tra giá trị của cờ debug\.
- Thông báo lỗi từ scanner xác nhận rằng việc bật cờ debug trong môi trường sản xuất là không an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát an ninh nào được thực hiện để kiểm tra hoặc vô hiệu hóa cờ debug\.
- Không có giá trị mặc định hoặc cấu hình môi trường nào được sử dụng để thiết lập cờ debug\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.27. MANUAL\_REVIEW — html\.security\.audit\.missing\-integrity\.missing\-integrity

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a0616e58cf6898bf |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | html\.security\.audit\.missing\-integrity\.missing\-integrity |
| File | bad\/templates\/csp\.html |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-353\: Missing Support for Integrity Check'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A08\_2021\-Software\_and\_Data\_Integrity\_Failures'\]; technology=\['html'\] |
| Thời gian xử lý | 2688 ms |

**Thông báo của scanner**

> This tag is missing an 'integrity' subresource integrity attribute\. The 'integrity' attribute allows for the browser to verify that externally hosted files \(for example from a CDN\) are delivered without unexpected manipulation\. Without this attribute, if an attacker can modify the externally hosted resource, this could lead to XSS and other types of attacks\. To prevent this, include the base64\-encoded cryptographic hash of the resource \(file\) you’re telling the browser to fetch in the 'integrity' attribute for all externally hosted files\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc phát hiện lỗi thiếu thuộc tính 'integrity' cho thẻ HTML, nhưng không có thông tin cụ thể về thẻ nào bị thiếu thuộc tính này\. Không thể xác định được nguồn và điểm cuối của lỗ hổng do thiếu thông tin trong đoạn mã được cung cấp\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về thẻ cụ thể nào bị thiếu thuộc tính 'integrity' trong đoạn mã được cung cấp\.
- Không có thông tin về nguồn dữ liệu hoặc điểm cuối \(sink\) liên quan đến lỗ hổng\.
- Không có bằng chứng về việc tài nguyên được tải từ CDN hoặc nguồn bên ngoài không được kiểm tra tính toàn vẹn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về thẻ HTML cụ thể bị thiếu thuộc tính 'integrity'\.
- Thông tin về nguồn tài nguyên bên ngoài và cách nó được sử dụng trong ứng dụng\.
- Thông tin về việc có hay không có thuộc tính 'integrity' được thêm vào trong đoạn mã\.

**Giả định LLM đã sử dụng**

- Thẻ HTML bị thiếu thuộc tính 'integrity' có thể là một thẻ script, link, hoặc img được tải từ CDN\.
- Tài nguyên được tải từ CDN có thể bị thay đổi bởi người tấn công nếu không có thuộc tính 'integrity'\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.28. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a666b540485fb6f8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | bad\/vulpy\.py |
| Dòng | 55 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 2197 ms |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink bad\/vulpy\.py\:55; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy cờ debug\=True được bật trong ứng dụng Flask\. Điều này có thể gây rò rỉ thông tin nhạy cảm khi triển khai vào môi trường sản xuất\. Không có biện pháp kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ này\.

**Bằng chứng LLM sử dụng**

- Cờ debug\=True được bật trong lệnh app\.run\(debug\=True, host\='127\.0\.1\.1', port\=5000, extra\_files\='csp\.txt'\)
- Không có kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ debug trong mã nguồn\.
- Thông báo lỗi từ scanner xác nhận rằng việc bật cờ debug trong Flask là một lỗ hổng cấu hình an ninh\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có cài đặt cấu hình môi trường hoặc biến môi trường nào được sử dụng để kiểm soát giá trị của cờ debug\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.29. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a9c1f13b8c6abf07 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly |
| File | good\/vulpy\.py |
| Dòng | 53 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 2368 ms |

**Thông báo của scanner**

> top\-level app\.run\(\.\.\.\) is ignored by flask\. Consider putting app\.run\(\.\.\.\) behind a guard, like inside a function

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink good\/vulpy\.py\:53; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc cảnh báo về việc sử dụng app\.run\(\) ở cấp độ cao có thể không chính xác trong trường hợp này\. Đoạn mã hiển thị rằng app\.run\(\) được gọi với các tham số cụ thể và không có bất kỳ lỗ hổng bảo mật nào liên quan đến việc chạy ứng dụng Flask trực tiếp\. Không có bằng chứng cho thấy việc gọi app\.run\(\) ở đây gây ra rủi ro bảo mật\.

**Bằng chứng LLM sử dụng**

- app\.run\(\) được gọi với các tham số cụ thể \(debug\=True, host\='127\.0\.1\.1', port\=5001, extra\_files\='csp\.txt'\) và không có bất kỳ điều kiện nào cho phép người dùng kiểm soát hành vi này\.
- Không có bằng chứng cho thấy app\.run\(\) được gọi từ một nguồn không an toàn hoặc có thể bị tấn công\.
- Không có lỗ hổng bảo mật liên quan đến việc chạy ứng dụng Flask trực tiếp được phát hiện trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có thông tin bổ sung về cách app\.run\(\) được gọi hoặc có thể bị kiểm soát bởi người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.30. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ab9b82a9aff35e69 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/user\.chpasswd\.html |
| Dòng | 8–18 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2129 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Không thể xác định được liệu có thiếu CSRF token trong form hay không do thông tin không đầy đủ\. Mã nguồn không hiển thị việc tạo form thủ công hoặc sử dụng csrf\_token\. Cần xem xét thêm các tệp liên quan để xác minh\.

**Bằng chứng LLM sử dụng**

- Mã nguồn không hiển thị việc tạo form thủ công hoặc sử dụng csrf\_token\.
- Không có thông tin về việc có hay không có CSRF token trong form được hiển thị\.
- Không thể xác định được liệu có lỗ hổng CSRF hay không do thiếu thông tin đầy đủ\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về cách form được tạo hoặc xử lý trong mã nguồn\.
- Không có thông tin về các tệp liên quan hoặc logic xử lý form\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu csrf\_token trong form là nguyên nhân gây ra cảnh báo\.
- Giả sử rằng mã nguồn hiển thị là toàn bộ mã liên quan đến form\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.31. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ace5bb7a6af8ac22 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/posts\.view\.html |
| Dòng | 13–17 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2186 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form được tạo thủ công trong Django template\. Tuy nhiên, không thể xác định chắc chắn liệu form này có thực sự gửi dữ liệu nhạy cảm hay không, cũng như không có thông tin về việc có hay không có các biện pháp bảo vệ khác\.

**Bằng chứng LLM sử dụng**

- Form được tạo thủ công trong template không chứa csrf\_token\.
- Không có thông tin về việc liệu form này có gửi dữ liệu nhạy cảm hay không\.
- Không có thông tin về các biện pháp bảo vệ CSRF khác được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về liệu form này có gửi dữ liệu nhạy cảm hay không\.
- Không có thông tin về các biện pháp bảo vệ CSRF khác được áp dụng\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu csrf\_token có thể gây ra lỗ hổng CSRF\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.32. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | adf665360aa247f9 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/welcome\.html |
| Dòng | 7–11 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2280 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu form này có phải là 'manually\-created' hay không\. Không có bằng chứng cụ thể về việc nguồn dữ liệu hoặc lỗ hổng được xác định rõ ràng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc form được tạo thủ công hay không\.
- Không có bằng chứng về việc nguồn dữ liệu hoặc lỗ hổng được xác định rõ ràng\.
- Không có thông tin về việc có kiểm soát bảo mật nào được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách form được tạo \(tự động hay thủ công\)\.
- Thông tin về việc có kiểm soát bảo mật nào được áp dụng\.
- Thông tin về nguồn dữ liệu và lỗ hổng cụ thể\.

**Giả định LLM đã sử dụng**

- Giả sử rằng form trong template có thể là 'manually\-created', nhưng không có bằng chứng rõ ràng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.33. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c266773e399a7a26 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/mfa\.enable\.html |
| Dòng | 8–14 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2398 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form thủ công trong Django template\. Tuy nhiên, không có thông tin đầy đủ về việc liệu form này có thực sự tiếp nhận dữ liệu từ người dùng hay không, cũng như không có thông tin về các kiểm soát bảo mật được áp dụng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc liệu form có xử lý dữ liệu người dùng hay không\.
- Không có thông tin về các kiểm soát bảo mật \(guards, validations, \.\.\.\) được áp dụng\.
- Không thể xác định được liệu có tồn tại một đường dẫn taint hoàn chỉnh từ nguồn người dùng đến điểm nguy hiểm hay không\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về việc liệu form có xử lý dữ liệu người dùng hay không\.
- Thông tin về các kiểm soát bảo mật được áp dụng\.
- Thông tin về đường dẫn taint hoàn chỉnh từ nguồn đến điểm nguy hiểm\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu CSRF token có thể là một lỗ hổng nếu form này thực sự xử lý dữ liệu người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.34. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ca4e3b3919147486 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/user\.login\.mfa\.html |
| Dòng | 8–18 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2033 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu form này có được tạo thủ công hay không\. Cần xem xét thêm mã nguồn để xác minh\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc form được tạo thủ công hay không\.
- Không có thông tin về việc có sử dụng \{% csrf\_token %\} trong mã HTML\.
- Không có thông tin về các kiểm soát bảo mật liên quan đến CSRF\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách form được tạo trong Django\.
- Thông tin về việc có sử dụng \{% csrf\_token %\} hay không\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu \{% csrf\_token %\} có thể là một lỗ hổng CSRF\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.35. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dbf58e57323ff6a8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | bad\/libuser\.py |
| Dòng | 53 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 3062 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/mod\_user\.py\:70; sink bad\/libuser\.py\:53; đường source–sink bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:70 → bad\/mod\_user\.py\:72 → bad\/mod\_user\.py\:72 → bad\/mod\_user\.py\:76 → bad\/libuser\.py\:59 → bad\/mod\_user\.py\:76; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được xây dựng bằng cách sử dụng phương thức format\(\) với giá trị đầu vào từ người dùng\. Điều này có thể dẫn đến lỗ hổng SQL injection nếu giá trị đầu vào không được kiểm tra đúng cách\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc này\.

**Bằng chứng LLM sử dụng**

- Giá trị 'password' được truyền từ mod\_user\.py vào libuser\.py và được sử dụng trực tiếp trong truy vấn SQL\.
- Truy vấn SQL được xây dựng bằng cách sử dụng phương thức format\(\) với giá trị 'password' không được tham số hóa\.
- Không có biện pháp kiểm tra hoặc xử lý đầu vào nào được áp dụng trước khi sử dụng giá trị 'password' trong truy vấn SQL\.
- Đường dẫn taint hoàn chỉnh cho thấy giá trị đầu vào người dùng ảnh hưởng trực tiếp đến truy vấn SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng giá trị 'password' được truyền từ mod\_user\.py là đầu vào từ người dùng\.
- Giả sử rằng không có biện pháp kiểm tra hoặc xử lý đầu vào nào được áp dụng trước khi sử dụng giá trị 'password' trong truy vấn SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.36. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dcfb79a96144daf2 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | bad\/templates\/user\.chpasswd\.html |
| Dòng | 8–16 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2218 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong template Django, nhưng không có thông tin đầy đủ để xác định liệu có tồn tại lỗ hổng thực sự hay không\. Cần xem xét thêm các yếu tố bảo mật khác và kiểm tra cách xử lý form trong ứng dụng\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc có hay không có CSRF token trong template được cung cấp\.
- Không có thông tin về cách xử lý form trong view hoặc middleware\.
- Không có thông tin về các biện pháp bảo mật khác được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách xử lý form trong view hoặc middleware\.
- Thông tin về các biện pháp bảo mật khác được áp dụng\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc thiếu CSRF token trong template có thể gây ra lỗ hổng CSRF\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.37. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dd6307aab57330b7 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | bad\/libuser\.py |
| Dòng | 25 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 2136 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/libuser\.py\:25; sink bad\/libuser\.py\:25; đường source–sink bad\/libuser\.py\:25; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tuy có sử dụng chuỗi SQL được định dạng, nhưng giá trị đầu vào không đến từ nguồn bị kiểm soát bởi người dùng\. Giá trị được sử dụng trong truy vấn SQL là một hằng số cục bộ, không có bất kỳ tham số nào được truyền từ bên ngoài\. Do đó, không có nguy cơ SQL injection\.

**Bằng chứng LLM sử dụng**

- Giá trị được sử dụng trong truy vấn SQL là một hằng số cục bộ, không đến từ nguồn bị kiểm soát bởi người dùng\.
- Không có tham số nào được truyền từ bên ngoài vào truy vấn SQL\.
- Các tham số được sử dụng trong truy vấn SQL là các giá trị cố định hoặc được xác định trong mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có tham số nào được truyền từ bên ngoài vào truy vấn SQL\.
- Giá trị được sử dụng trong truy vấn SQL là một hằng số cục bộ\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.38. MANUAL\_REVIEW — python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | de759a4a995eb2b7 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.django\-no\-csrf\-token\.django\-no\-csrf\-token |
| File | good\/templates\/mfa\.enable\.html |
| Dòng | 8–14 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=CWE\-352\: Cross\-Site Request Forgery \(CSRF\); references=\['https\:\/\/docs\.djangoproject\.com\/en\/4\.2\/howto\/csrf\/'\]; technology=\['django'\] |
| Thời gian xử lý | 2256 ms |

**Thông báo của scanner**

> Manually\-created forms in django templates should specify a csrf\_token to prevent CSRF attacks\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** MEDIUM — Trung bình
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi liên quan đến việc thiếu CSRF token trong form Django, nhưng không có thông tin đầy đủ để xác định liệu form này có phải là 'manually\-created' hay không\. Không có bằng chứng rõ ràng về việc nguồn dữ liệu hoặc lỗ hổng được xác định hoàn toàn\.

**Bằng chứng LLM sử dụng**

- Không có thông tin về việc form được tạo thủ công hay không\.
- Không có bằng chứng về việc nguồn dữ liệu hoặc lỗ hổng được xác định hoàn toàn\.
- Không có thông tin về việc có kiểm soát bảo mật nào được áp dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Thông tin về cách form được tạo \(tự động hay thủ công\)\.
- Thông tin về việc có kiểm soát bảo mật nào được áp dụng\.
- Thông tin về nguồn dữ liệu và lỗ hổng\.

**Giả định LLM đã sử dụng**

- Giả sử rằng form trong template có thể là 'manually\-created', nhưng không có bằng chứng rõ ràng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.39. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f29e3127da6ed974 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-security\-config\.avoid\_using\_app\_run\_directly |
| File | bad\/vulpy\-ssl\.py |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 2350 ms |

**Thông báo của scanner**

> top\-level app\.run\(\.\.\.\) is ignored by flask\. Consider putting app\.run\(\.\.\.\) behind a guard, like inside a function

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink bad\/vulpy\-ssl\.py\:29; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Quy tắc cảnh báo về việc sử dụng app\.run\(\) ở cấp độ cao có thể không phải là lỗ hổng\. Trong đoạn mã, app\.run\(\) được gọi với các tham số cụ thể và không có bằng chứng cho thấy nó bị bỏ qua bởi Flask\. Ngoài ra, không có luồng taint nào được xác định từ đầu vào người dùng đến app\.run\(\)\.

**Bằng chứng LLM sử dụng**

- app\.run\(\) được gọi với các tham số cụ thể \(debug\=True, host\='127\.0\.1\.1', ssl\_context\=\('\/tmp\/acme\.cert', '\/tmp\/acme\.key'\)\) và không có bằng chứng cho thấy nó bị bỏ qua\.
- Không có luồng taint nào được xác định từ đầu vào người dùng đến app\.run\(\)\.
- Không có nguồn đầu vào người dùng nào được xác định trong đoạn mã\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có luồng taint nào từ đầu vào người dùng đến app\.run\(\) trong đoạn mã\.
- app\.run\(\) không bị bỏ qua bởi Flask trong ngữ cảnh này\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.40. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f86cd02ab143c2cd |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | bad\/vulpy\-ssl\.py |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 2293 ms |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink bad\/vulpy\-ssl\.py\:29; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy cờ debug\=True được bật trong ứng dụng Flask\. Điều này có thể gây rò rỉ thông tin nhạy cảm khi triển khai vào môi trường sản xuất\. Không có biện pháp kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ này\.

**Bằng chứng LLM sử dụng**

- Cờ debug\=True được bật trong phương thức app\.run\(\) tại dòng 29\.
- Không có kiểm soát an ninh nào được xác nhận để vô hiệu hóa cờ debug\.
- Thông báo lỗi từ scanner cho thấy cờ debug\=True có thể gây rò rỉ thông tin nhạy cảm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có kiểm soát an ninh nào được thực hiện để vô hiệu hóa cờ debug\.
- Không có giá trị mặc định hoặc cấu hình môi trường nào được sử dụng để thiết lập cờ debug\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.41. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ff69c30538379b32 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | bad\/db\_init\.py |
| Dòng | 20 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 2239 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source bad\/db\_init\.py\:20; sink bad\/db\_init\.py\:20; đường source–sink bad\/db\_init\.py\:20; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy lỗi SQL injection có thể, nhưng giá trị đầu vào không đến từ người dùng\. Giá trị được sử dụng là hằng số cục bộ và không bị thay đổi bởi đầu vào người dùng\. Không có rủi ro bảo mật trong trường hợp này\.

**Bằng chứng LLM sử dụng**

- Giá trị 'u' và 'p' được lấy từ danh sách cục bộ, không đến từ đầu vào người dùng\.
- Câu lệnh SQL được xây dựng bằng cách sử dụng các giá trị hằng số và không có tham số động từ người dùng\.
- Không có giá trị đầu vào người dùng nào được truyền vào câu lệnh SQL\.
- Các giá trị được sử dụng trong câu lệnh SQL là cố định và không bị thay đổi bởi bất kỳ điều kiện nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Danh sách 'users' chứa các giá trị cố định và không bị thay đổi bởi đầu vào người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.42. MANUAL\_REVIEW — python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b53fb9ac34ad38c6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http |
| File | good\/httpbrute\.py |
| Dòng | 22 |
| Severity | LOW |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-319\: Cleartext Transmission of Sensitive Information'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A02\_2021\-Cryptographic\_Failures'\]; technology=\['requests'\] |
| Thời gian xử lý | 2375 ms |

**Thông báo của scanner**

> Detected a request using 'http\:\/\/'\. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information\. Use 'https\:\/\/' instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source good\/httpbrute\.py\:5; sink chưa xác định; đường source–sink good\/httpbrute\.py\:22 → good\/httpbrute\.py\:22; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một yêu cầu HTTP không được mã hóa, nhưng URL được xác định là một hằng số cục bộ không do người dùng kiểm soát\. Do đó, không có dữ liệu nhạy cảm nào được truyền qua giao thức không an toàn\. Việc sử dụng HTTP trong trường hợp này không gây rủi ro bảo mật\.

**Bằng chứng LLM sử dụng**

- URL được khai báo là một hằng số cục bộ \('http\:\/\/127\.0\.1\.1\:5000\/user\/login'\) và không được thiết lập từ bất kỳ nguồn nào do người dùng kiểm soát\.
- Không có dữ liệu nhạy cảm nào được truyền qua URL hoặc trong yêu cầu POST, chỉ là tên người dùng và mật khẩu cố định được sử dụng để thử brute\-force\.
- Không có cơ chế kiểm soát bảo mật nào được áp dụng để ngăn chặn việc truyền dữ liệu nhạy cảm qua HTTP\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- URL được sử dụng trong môi trường nội bộ \(127\.0\.1\.1\) và không truyền dữ liệu nhạy cảm ra ngoài mạng\.
- Mục đích của đoạn mã là thử brute\-force và không liên quan đến truyền thông tin nhạy cảm\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.43. MANUAL\_REVIEW — python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cf6b240882b17e33 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http |
| File | bad\/api\_post\.py |
| Dòng | 16 |
| Severity | LOW |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-319\: Cleartext Transmission of Sensitive Information'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A02\_2021\-Cryptographic\_Failures'\]; technology=\['requests'\] |
| Thời gian xử lý | 2987 ms |

**Thông báo của scanner**

> Detected a request using 'http\:\/\/'\. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information\. Use 'https\:\/\/' instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source bad\/api\_post\.py\:26; sink chưa xác định; đường source–sink bad\/api\_post\.py\:26; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Yêu cầu HTTP được phát hiện, nhưng không truyền dữ liệu nhạy cảm\. Dữ liệu nhạy cảm như mật khẩu được mã hóa và không được truyền qua HTTP\. API key được lưu trữ và sử dụng trong yêu cầu HTTP, nhưng không có bằng chứng cho thấy nó chứa thông tin nhạy cảm\.

**Bằng chứng LLM sử dụng**

- Yêu cầu HTTP được thực hiện để tạo API key, nhưng mật khẩu được truyền qua POST và không được lưu trữ trong HTTP\.
- API key được lưu trữ trong tệp và được sử dụng trong yêu cầu HTTP, nhưng không có bằng chứng cho thấy nó chứa thông tin nhạy cảm\.
- Không có dữ liệu nhạy cảm nào được truyền qua HTTP trong yêu cầu thứ hai\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- API key không chứa thông tin nhạy cảm\.
- Không có dữ liệu nhạy cảm nào được truyền qua HTTP trong yêu cầu thứ hai\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.44. MANUAL\_REVIEW — python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d45148c24594cd09 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http |
| File | bad\/api\_post\.py |
| Dòng | 30 |
| Severity | LOW |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-319\: Cleartext Transmission of Sensitive Information'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A02\_2021\-Cryptographic\_Failures'\]; technology=\['requests'\] |
| Thời gian xử lý | 3091 ms |

**Thông báo của scanner**

> Detected a request using 'http\:\/\/'\. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information\. Use 'https\:\/\/' instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Tìm thấy một yêu cầu HTTP không được mã hóa trong mã, nhưng không có thông tin đầy đủ để xác định liệu dữ liệu nhạy cảm có được truyền qua mạng không\. Không có kiểm soát bảo mật rõ ràng hoặc xác nhận rằng dữ liệu nhạy cảm đang được truyền\. Cần xem xét thêm ngữ cảnh và mã liên quan\.

**Bằng chứng LLM sử dụng**

- Yêu cầu HTTP được thực hiện tại dòng 30 trong tệp 'bad\/api\_post\.py'\.
- Không có thông tin về liệu dữ liệu nhạy cảm có được truyền qua yêu cầu này hay không\.
- Không có kiểm soát bảo mật hoặc xác thực được chỉ ra trong mã liên quan\.
- Không thể xác định liệu dữ liệu có bị rò rỉ hay không do thiếu thông tin đầy đủ\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về nội dung yêu cầu HTTP hoặc dữ liệu được truyền\.
- Không có thông tin về liệu dữ liệu nhạy cảm có được truyền qua yêu cầu này hay không\.
- Không có kiểm soát bảo mật hoặc xác thực được chỉ ra trong mã liên quan\.

**Giả định LLM đã sử dụng**

- Yêu cầu HTTP có thể truyền dữ liệu nhạy cảm, nhưng không có bằng chứng cụ thể\.
- Không có kiểm soát bảo mật rõ ràng được áp dụng trong mã\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.45. MANUAL\_REVIEW — python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | fdfc85de4c5baf6e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-with\-http\.request\-with\-http |
| File | bad\/api\_list\.py |
| Dòng | 10 |
| Severity | LOW |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-319\: Cleartext Transmission of Sensitive Information'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A02\_2021\-Cryptographic\_Failures'\]; technology=\['requests'\] |
| Thời gian xử lý | 132897 ms |

**Thông báo của scanner**

> Detected a request using 'http\:\/\/'\. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information\. Use 'https\:\/\/' instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink chưa xác định; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Không thể xác định rõ ràng liệu việc sử dụng 'http\:\/\/' có phải là lỗ hổng hay không do thiếu thông tin đầy đủ về ngữ cảnh\. Mã nguồn cho thấy một yêu cầu HTTP được thực hiện, nhưng không có thông tin về liệu dữ liệu nhạy cảm có được truyền qua kết nối này hay không\. Ngoài ra, không có kiểm soát bảo mật nào được xác nhận trong mã\.

**Bằng chứng LLM sử dụng**

- Mã nguồn sử dụng 'http\:\/\/127\.0\.1\.1\:5000\/api\/post\/\{\}'\.format\(username\)' để thực hiện yêu cầu HTTP\.
- Không có thông tin về liệu dữ liệu nhạy cảm có được truyền qua kết nối này hay không\.
- Không có kiểm soát bảo mật nào được xác nhận trong mã\.
- Thông tin về nguồn và điểm cuối không được xác định đầy đủ\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Không có thông tin về liệu dữ liệu nhạy cảm có được truyền qua kết nối HTTP hay không\.
- Không có thông tin về việc liệu có bất kỳ kiểm soát bảo mật nào được áp dụng trước khi thực hiện yêu cầu HTTP hay không\.

**Giả định LLM đã sử dụng**

- Giả sử rằng việc sử dụng HTTP có thể gây rủi ro nếu dữ liệu nhạy cảm được truyền qua kết nối này\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.46. MANUAL\_REVIEW — generic\-api\-key

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e87f90af6848dff4 |
| Scanner / loại finding | GITLEAKS / SECRET |
| Rule | generic\-api\-key — Detected a Generic API Key, potentially exposing access to various services and sensitive operations\. |
| File | good\/libsession\.py |
| Dòng | 9 |
| Severity | UNKNOWN |
| Metadata an toàn | entropy=4\.9877295; rule\_description=Detected a Generic API Key, potentially exposing access to various services and sensitive operations\. |
| Thời gian xử lý | 1694 ms |

**Thông báo của scanner**

> Detected a Generic API Key, potentially exposing access to various services and sensitive operations\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 1\-19\.

#### Phân tích của LLM

- **Verdict:** NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận
- **Confidence:** LOW — Thấp
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v10

**Kết luận ngắn gọn**

> Không có thông tin đầy đủ để xác định liệu khóa API chung được phát hiện có phải là một lỗ hổng thực sự hay không\. Đoạn mã bị che giấu có thể chứa khóa, nhưng không thể xác minh nguồn hoặc cách sử dụng của nó\.

**Bằng chứng LLM sử dụng**

- Đoạn mã bị che giấu có thể chứa khóa API, nhưng không thể xác minh nguồn của nó\.
- Không có thông tin về cách khóa được sử dụng hoặc truyền đạt trong ứng dụng\.
- Không có bằng chứng cho thấy khóa được lưu trữ hoặc truyền dưới dạng không an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- Đoạn mã bị che giấu có thể chứa khóa API, nhưng không thể xác minh nguồn của nó\.
- Không có thông tin về cách khóa được sử dụng hoặc truyền đạt trong ứng dụng\.

**Giả định LLM đã sử dụng**

- Khóa API có thể được sử dụng để truy cập các dịch vụ nhạy cảm, nhưng không có bằng chứng cụ thể cho điều này trong đoạn mã được cung cấp\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v2
- **Đã escalated:** Có
- **Lý do escalation:** Ràng buộc artifact đang ở trạng thái chưa xác minh hoặc chỉ xác minh một phần\.
- **Lý do policy:**
  - Ràng buộc giữa scanner artifact và repository chưa được xác minh đầy đủ\.

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
