# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Có lỗi cần xử lý; không được bỏ qua các finding liên quan\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 30 |
| Triage thành công | 30 |
| Finding có lỗi | 0 |
| Lỗi scanner | 1 |
| Thời gian toàn run (giây) | 180\.663862 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 30 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 0f6d252d\-1902\-45a3\-a61b\-49a34ce9cd10 |
| Repository | realvuln\-dvblab |
| Repository identifier | realvuln\-dvblab |
| Commit | 25bdef1e32055bfb6366856acc5db829e61e3647 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | UNVERIFIED |
| Provider | real\-modal\-qwen |
| Model | Qwen\/Qwen3\-14B\-AWQ |
| Prompt version | triage\-prompt\-v9 |
| Analysis backend | native |
| Backend version | 0\.1\.0 |
| Analysis config ID | python\-cross\-file\-evidence\-v1 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 0\.045612 giây |
| Policy version | conservative\-policy\-v1 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | triage\-resume |
| Bắt đầu | 2026\-08\-12T03\:35\:27\.711181\+00\:00 |
| Kết thúc | 2026\-08\-12T03\:38\:28\.375043\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; MODULE2
- Phiên bản: GITLEAKS=null; MODULE2=0\.1\.0; SEMGREP=1\.150\.0
- Cấu hình: GITLEAKS=artifact\-provided; MODULE2=python\-cross\-file\-evidence\-v1; SEMGREP=artifact\-provided
- Hash artifact: gitleaks=50056c08ce479cc2f54c4d6595a4264bdf32bf84f2995d59ff3bd513897ab414; semgrep=677c3f0c9134e8688bc6f4a371958acda1739e1be3509f946f8e3f5cce4b3a5d

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 026af2a0b0a7cce5 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/auth\_routes\.py\:22 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 2 | MANUAL\_REVIEW | HIGH | 0ca70af0d323edd8 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/transaction\_routes\.py\:93 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 3 | MANUAL\_REVIEW | HIGH | 12f88bb08df09f25 | dockerfile\.security\.missing\-user\.missing\-user | backend\/Dockerfile\:12 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 4 | MANUAL\_REVIEW | HIGH | 1ba615611a637c66 | python\.lang\.security\.deserialization\.avoid\-pyyaml\-load\.avoid\-pyyaml\-load | backend\/routes\/auth\_routes\.py\:157 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 5 | MANUAL\_REVIEW | HIGH | 389a085e791f9d29 | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | backend\/app\.py\:16 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 6 | MANUAL\_REVIEW | HIGH | 42c46643240c5329 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/transaction\_routes\.py\:49 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 7 | MANUAL\_REVIEW | HIGH | 47bf99454c2a15ea | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/auth\_routes\.py\:22 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 8 | MANUAL\_REVIEW | HIGH | 6fc4ba50465bd08d | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | backend\/routes\/transaction\_routes\.py\:95 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 9 | MANUAL\_REVIEW | HIGH | 7896082e263540a4 | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization | backend\/routes\/auth\_routes\.py\:157 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 10 | MANUAL\_REVIEW | HIGH | 79d5ccb86809af66 | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/transaction\_routes\.py\:93 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 11 | MANUAL\_REVIEW | HIGH | 86216123fa851727 | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/auth\_routes\.py\:36 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 12 | MANUAL\_REVIEW | HIGH | aa7f467312719b31 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | backend\/routes\/transaction\_routes\.py\:50 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 13 | MANUAL\_REVIEW | HIGH | abf2d2a781cf0d32 | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/auth\_routes\.py\:36 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 14 | MANUAL\_REVIEW | HIGH | b885c47947f27296 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | backend\/routes\/auth\_routes\.py\:37 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 15 | MANUAL\_REVIEW | HIGH | ca74f831df1cadc0 | python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret | backend\/routes\/auth\_routes\.py\:42–50 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 16 | MANUAL\_REVIEW | HIGH | ce1669e09ae37052 | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query | backend\/routes\/auth\_routes\.py\:23 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 17 | MANUAL\_REVIEW | HIGH | f98496b6d4abfa74 | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | backend\/routes\/transaction\_routes\.py\:49 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 18 | MANUAL\_REVIEW | MEDIUM | 0aba1733dbb21c99 | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute | backend\/routes\/transaction\_routes\.py\:47–50 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 19 | MANUAL\_REVIEW | MEDIUM | 2ac20c15fbc58823 | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password | backend\/app\.py\:176 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 20 | MANUAL\_REVIEW | MEDIUM | 3e9f48ada14d4749 | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | backend\/app\.py\:228 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 21 | MANUAL\_REVIEW | MEDIUM | 56da2d36b375fd74 | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | backend\/models\.py\:27 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 22 | MANUAL\_REVIEW | MEDIUM | 5966d753bb69454c | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | backend\/routes\/auth\_routes\.py\:37 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 23 | MANUAL\_REVIEW | MEDIUM | 781bfa53fce8e28e | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | backend\/routes\/auth\_routes\.py\:23 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 24 | MANUAL\_REVIEW | MEDIUM | 9bdecf3c2ae481c6 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | backend\/routes\/transaction\_routes\.py\:50 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 25 | MANUAL\_REVIEW | MEDIUM | b93a4c1b0ea8a863 | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query | backend\/routes\/transaction\_routes\.py\:95 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 26 | MANUAL\_REVIEW | MEDIUM | bb7368d67ab2f41b | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password | backend\/routes\/auth\_routes\.py\:146 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 27 | MANUAL\_REVIEW | MEDIUM | d013fb7c5429788a | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | backend\/routes\/auth\_routes\.py\:21 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 28 | MANUAL\_REVIEW | MEDIUM | d0f0379734a04275 | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute | backend\/routes\/transaction\_routes\.py\:89–95 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 29 | MANUAL\_REVIEW | MEDIUM | d37f957261d6bcce | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | backend\/models\.py\:24 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |
| 30 | MANUAL\_REVIEW | MEDIUM | e30d08d566cc3c40 | python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host | backend\/app\.py\:228 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 026af2a0b0a7cce5 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 22 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-915\: Improperly Controlled Modification of Dynamically\-Determined Object Attributes'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1732 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 12\-28, hàm register, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một chuỗi SQL được xây dựng thủ công từ đầu vào người dùng, điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc truyền dữ liệu không an toàn\. Sử dụng ORM hoặc truy vấn tham số hóa là cách tiếp cận an toàn hơn\.

**Bằng chứng LLM sử dụng**

- Đầu vào người dùng được lấy từ \`request\.get\_json\(\)\` và được lưu trữ vào biến \`username\`\.
- Biến \`username\` được sử dụng trực tiếp trong chuỗi SQL được xây dựng bằng \`f\-string\`\.
- Không có biện pháp kiểm tra, xác thực, hoặc tham số hóa được áp dụng trước khi thực thi truy vấn SQL\.
- Truy vấn SQL được thực thi bằng \`db\.session\.execute\(insert\_query\)\` mà không có bất kỳ biện pháp bảo vệ nào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng \`request\.get\_json\(\)\` trả về dữ liệu đầu vào từ người dùng, có thể bị kiểm soát bởi đối phương\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.2. MANUAL\_REVIEW — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0ca70af0d323edd8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 93 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-915\: Improperly Controlled Modification of Dynamically\-Determined Object Attributes'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1720 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 86\-111, hàm search\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng tham số đầu vào người dùng để xây dựng trực tiếp chuỗi SQL, điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát nào được áp dụng để ngăn chặn việc này\. Lỗ hổng được xác nhận rõ ràng trong đoạn mã\.

**Bằng chứng LLM sử dụng**

- Tham số 'search\_term' được lấy từ request\.args\.get\(\), một nguồn đầu vào người dùng\.
- Giá trị 'search\_term' được chèn trực tiếp vào chuỗi SQL mà không có tham số hóa\.
- Không có biện pháp kiểm soát, xác thực hoặc làm sạch nào được áp dụng cho giá trị 'search\_term' trước khi sử dụng\.
- Đoạn mã được đánh dấu là 'deliberately vulnerable' cho mục đích giáo dục, nhưng điều này không loại bỏ rủi ro bảo mật\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có thông tin nào cho thấy 'search\_term' được kiểm tra hoặc làm sạch trước khi sử dụng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.3. MANUAL\_REVIEW — dockerfile\.security\.missing\-user\.missing\-user

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 12f88bb08df09f25 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | dockerfile\.security\.missing\-user\.missing\-user |
| File | backend\/Dockerfile |
| Dòng | 12 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-250\: Execution with Unnecessary Privileges'\]; owasp=\['A04\:2021 \- Insecure Design', 'A06\:2025 \- Insecure Design'\]; references=\['https\:\/\/owasp\.org\/Top10\/A04\_2021\-Insecure\_Design'\]; technology=\['dockerfile'\] |
| Thời gian xử lý | 131263 ms |

**Thông báo của scanner**

> By not specifying a USER, a program in the container may run as 'root'\. This is a security hazard\. If an attacker can control a process running as root, they may have control over the container\. Ensure that the last USER in a Dockerfile is a USER other than 'root'\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 2\-12, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tệp Dockerfile không chỉ định lệnh USER, dẫn đến việc chương trình có thể chạy dưới quyền root, gây nguy hiểm về bảo mật\. Lệnh CMD được sử dụng để chạy ứng dụng, nhưng không có lệnh USER nào được chỉ định trước đó\. Điều này làm tăng nguy cơ nếu một người tấn công có thể kiểm soát quy trình chạy dưới quyền root\.

**Bằng chứng LLM sử dụng**

- Không có lệnh USER nào được chỉ định trong Dockerfile, dẫn đến việc container có thể chạy dưới quyền root\.
- Lệnh CMD được sử dụng để chạy ứng dụng, nhưng không có lệnh USER nào được chỉ định trước đó để xác định người dùng chạy ứng dụng\.
- Không có bất kỳ biện pháp nào được thực hiện để đảm bảo chương trình chạy dưới quyền người dùng không phải là root\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có lệnh USER nào được chỉ định trong Dockerfile\.
- Lệnh CMD được sử dụng để chạy ứng dụng dưới quyền root\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.4. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.avoid\-pyyaml\-load\.avoid\-pyyaml\-load

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1ba615611a637c66 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.avoid\-pyyaml\-load\.avoid\-pyyaml\-load |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 157 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/github\.com\/yaml\/pyyaml\/wiki\/PyYAML\-yaml\.load\(input\)\-Deprecation', 'https\:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE\-2017\-18342'\]; technology=\['pyyaml'\] |
| Thời gian xử lý | 1991 ms |

**Thông báo của scanner**

> Detected a possible YAML deserialization vulnerability\. \`yaml\.unsafe\_load\`, \`yaml\.Loader\`, \`yaml\.CLoader\`, and \`yaml\.UnsafeLoader\` are all known to be unsafe methods of deserializing YAML\. An attacker with control over the YAML input could create special YAML input that allows the attacker to run arbitrary Python code\. This would allow the attacker to steal files, download and install malware, or otherwise take over the machine\. Use \`yaml\.safe\_load\` or \`yaml\.SafeLoader\` instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 151\-165, hàm import\_profile, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng có thể khai thác trong việc sử dụng \`yaml\.load\` với \`yaml\.Loader\`, một phương pháp không an toàn để deserialize YAML\. Dữ liệu đầu vào có thể bị kiểm soát bởi người tấn công, và không có biện pháp kiểm soát nào được áp dụng để ngăn chặn điều này\. Điều này có thể dẫn đến việc thực thi mã Python tùy ý\.

**Bằng chứng LLM sử dụng**

- Dữ liệu \`profile\_yaml\` được lấy từ \`request\.get\_json\(\)\.get\('profile\_yaml', ''\)\`, một nguồn có thể bị kiểm soát bởi người tấn công\.
- Đoạn mã sử dụng \`yaml\.load\(profile\_yaml, Loader\=yaml\.Loader\)\`, một phương pháp không an toàn để deserialize YAML\.
- Không có biện pháp kiểm soát, xác thực, hoặc làm sạch nào được áp dụng trước khi deserialize dữ liệu\.
- Không có giá trị mặc định an toàn hoặc kiểm tra nào được thực hiện để đảm bảo tính hợp lệ của dữ liệu đầu vào\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng \`request\.get\_json\(\)\.get\('profile\_yaml', ''\)\` có thể nhận đầu vào từ người dùng không đáng tin cậy\.
- Giả sử rằng \`yaml\.Loader\` là một phương pháp không an toàn theo như quy tắc được chỉ định\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.5. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 389a085e791f9d29 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | backend\/app\.py |
| Dòng | 16 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 1597 ms |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 6\-26\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Biến \`SECRET\_KEY\` được đặt giá trị cố định là 'supersecret' trong mã nguồn\. Theo quy tắc, giá trị này nên được lấy từ biến môi trường hoặc tệp cấu hình thay vì được đặt cứng trong mã\. Không có bất kỳ kiểm soát an ninh nào được áp dụng để ngăn chặn việc sử dụng giá trị cố định này\.

**Bằng chứng LLM sử dụng**

- Biến \`SECRET\_KEY\` được gán giá trị cố định 'supersecret' trong mã nguồn\.
- Không có kiểm soát an ninh nào được áp dụng để ngăn chặn việc sử dụng giá trị cố định này\.
- Quy tắc yêu cầu tránh sử dụng giá trị cố định cho \`SECRET\_KEY\` và thay vào đó nên sử dụng biến môi trường hoặc tệp cấu hình\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có bất kỳ kiểm soát an ninh nào được áp dụng để ngăn chặn việc sử dụng giá trị cố định này\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.6. MANUAL\_REVIEW — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 42c46643240c5329 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 49 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-915\: Improperly Controlled Modification of Dynamically\-Determined Object Attributes'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1822 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 44\-62, hàm get\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một chuỗi SQL được xây dựng thủ công từ tham số truy vấn HTTP, có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng\. Sử dụng ORM hoặc truy vấn tham số hóa là giải pháp an toàn hơn\.

**Bằng chứng LLM sử dụng**

- Tham số 'user\_id' được lấy từ request\.args\.get, là giá trị do người dùng kiểm soát\.
- Giá trị 'user\_id' được chèn trực tiếp vào chuỗi SQL mà không có tham số hóa\.
- Không có biện pháp kiểm tra, mã hóa, hoặc xác thực nào được áp dụng cho giá trị 'user\_id' trước khi chèn vào truy vấn SQL\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), có thể bị tấn công SQL injection nếu 'user\_id' chứa dữ liệu độc hại\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'user\_id' có thể chứa dữ liệu do người dùng kiểm soát\.
- Giả sử rằng 'db\.session\.execute' thực thi truy vấn SQL trực tiếp mà không có cơ chế bảo vệ\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.7. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 47bf99454c2a15ea |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 22 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 1829 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 12\-28, hàm register, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc xây dựng truy vấn SQL thủ công từ dữ liệu người dùng không được xử lý an toàn\. Dữ liệu người dùng được lấy từ request\.get\_json\(\) và được sử dụng trực tiếp trong một chuỗi SQL không được tham số hóa, tạo điều kiện cho lỗ hổng SQL injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng\.

**Bằng chứng LLM sử dụng**

- Dữ liệu người dùng được lấy từ request\.get\_json\(\) và được lưu trữ vào biến 'username' và 'password'\.
- Biến 'username' và 'password' được sử dụng trực tiếp trong một chuỗi SQL không được tham số hóa\.
- Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn SQL injection\.
- Truy vấn SQL được xây dựng bằng cách sử dụng f\-string và được thực thi bằng db\.session\.execute\(insert\_query\)\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Dữ liệu được lấy từ request\.get\_json\(\) là đầu vào do người dùng kiểm soát\.
- Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn SQL injection\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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
| Finding ID | 6fc4ba50465bd08d |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 95 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 1724 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 86\-111, hàm search\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc nối chuỗi SQL trực tiếp từ đầu vào không đáng tin cậy, có thể dẫn đến lỗ hổng SQL Injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn điều này\. SQLAlchemy không sử dụng các tham số tên hoặc các phương pháp an toàn khác\.

**Bằng chứng LLM sử dụng**

- Đầu vào từ request\.args\.get được gán trực tiếp vào biến search\_term mà không có bất kỳ biện pháp làm sạch nào\.
- Biến search\_term được nối trực tiếp vào chuỗi SQL bằng cách sử dụng f\-string, tạo ra nguy cơ SQL Injection\.
- Không có biện pháp kiểm soát hoặc bảo vệ nào được áp dụng trước khi thực thi truy vấn SQL\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), trong đó query là chuỗi SQL được tạo từ đầu vào không đáng tin cậy\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng request\.args\.get\('description', ''\) là đầu vào từ người dùng, có thể bị kiểm soát bởi người tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.9. MANUAL\_REVIEW — python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7896082e263540a4 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.avoid\-insecure\-deserialization\.avoid\-insecure\-deserialization |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 157 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['django'\] |
| Thời gian xử lý | 1701 ms |

**Thông báo của scanner**

> Avoid using insecure deserialization library, backed by \`pickle\`, \`\_pickle\`, \`cpickle\`, \`dill\`, \`shelve\`, or \`yaml\`, which are known to lead to remote code execution vulnerabilities\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 151\-165, hàm import\_profile, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng hàm \`yaml\.load\` với dữ liệu từ \`request\.get\_json\(\)\` mà không có kiểm tra an toàn, dẫn đến nguy cơ deserialization không an toàn\. Dữ liệu đầu vào có thể bị kiểm soát bởi người tấn công, và không có biện pháp bảo vệ nào được áp dụng\.

**Bằng chứng LLM sử dụng**

- Dữ liệu \`profile\_yaml\` được lấy từ \`request\.get\_json\(\)\` \- nguồn có thể bị kiểm soát bởi người tấn công\.
- Hàm \`yaml\.load\(profile\_yaml\)\` được gọi trực tiếp mà không có kiểm tra hoặc giới hạn nào\.
- Không có biện pháp bảo vệ \(guard\) nào được áp dụng để ngăn chặn việc deserialization không an toàn\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng \`request\.get\_json\(\)\` có thể nhận đầu vào từ người dùng không đáng tin cậy\.
- Giả sử rằng \`yaml\.load\` có thể gây ra lỗ hổng RCE nếu dữ liệu đầu vào không được kiểm tra\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.10. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 79d5ccb86809af66 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 93 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 1879 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 86\-111, hàm search\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng tham số truy vấn HTTP để xây dựng trực tiếp chuỗi SQL, điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát nào được áp dụng để ngăn chặn việc này\. Mã nguồn có chứa chú thích cho thấy đây là một lỗ hổng được thiết kế nhằm mục đích giáo dục\.

**Bằng chứng LLM sử dụng**

- Tham số 'search\_term' được lấy từ request\.args\.get, một nguồn đầu vào người dùng có thể bị kiểm soát\.
- Giá trị 'search\_term' được chèn trực tiếp vào chuỗi SQL bằng cách sử dụng f\-string mà không có tham số hóa\.
- Câu lệnh SQL được thực thi bằng db\.session\.execute\(query\), đây là điểm cuối \(sink\) có thể bị tấn công SQL injection\.
- Không có biện pháp kiểm soát \(guard\) nào được áp dụng để ngăn chặn việc này\.
- Chú thích trong mã nguồn cho thấy đây là một lỗ hổng được thiết kế nhằm mục đích giáo dục\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'request\.args\.get' là một nguồn đầu vào có thể bị kiểm soát bởi người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.11. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 86216123fa851727 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 36 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 1621 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 30\-79, hàm login, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc xây dựng truy vấn SQL thủ công từ đầu vào người dùng, điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc này\. Sử dụng truy vấn tham số hóa là cách tiếp cận an toàn hơn\.

**Bằng chứng LLM sử dụng**

- Đầu vào người dùng được lấy từ request\.get\_json\(\) và được lưu vào biến username\.
- Biến username được sử dụng trực tiếp trong chuỗi SQL không được tham số hóa\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), không có biện pháp kiểm soát hoặc tham số hóa\.
- Không có biện pháp kiểm tra hoặc mã hóa đầu vào trước khi sử dụng trong truy vấn SQL\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng request\.get\_json\(\) trả về dữ liệu đầu vào từ người dùng, có thể bị tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.12. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | aa7f467312719b31 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 50 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 1730 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 44\-62, hàm get\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng chuỗi SQL thô với đầu vào không đáng tin cậy, có thể dẫn đến lỗ hổng SQL Injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc này\. SQLAlchemy không sử dụng các tham số được chuẩn bị\.

**Bằng chứng LLM sử dụng**

- Đầu vào từ request\.args\.get\('user\_id'\) được gán trực tiếp vào chuỗi SQL thô mà không có xử lý\.
- Chuỗi SQL được xây dựng bằng cách sử dụng f\-string với giá trị user\_id, không sử dụng tham số được chuẩn bị\.
- Không có biện pháp kiểm tra, xác thực hoặc mã hóa nào được áp dụng cho giá trị user\_id trước khi đưa vào truy vấn SQL\.
- db\.session\.execute\(query\) được gọi trực tiếp với chuỗi SQL thô, không sử dụng TextualSQL hoặc các phương pháp an toàn khác\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng giá trị user\_id có thể bị kiểm soát bởi người dùng, vì nó đến từ request\.args\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.13. MANUAL\_REVIEW — python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | abf2d2a781cf0d32 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 36 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-915\: Improperly Controlled Modification of Dynamically\-Determined Object Attributes'\]; owasp=\['A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1553 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using the Django object\-relational mappers \(ORM\) instead of raw SQL queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 30\-79, hàm login, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc xây dựng truy vấn SQL thủ công từ dữ liệu người dùng không được xử lý an toàn\. Điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng trước khi truy vấn được thực thi\.

**Bằng chứng LLM sử dụng**

- Dữ liệu người dùng được lấy từ request\.get\_json\(\) và lưu vào biến username\.
- Biến username được sử dụng trực tiếp trong chuỗi SQL không được tham số hóa\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), không có biện pháp kiểm soát an toàn\.
- Không có mã kiểm tra hoặc xử lý đặc biệt để ngăn chặn SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Dữ liệu được lấy từ request\.get\_json\(\) là đầu vào người dùng, do đó có thể bị tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.14. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b885c47947f27296 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 37 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 1785 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 30\-79, hàm login, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng chuỗi SQL thô với đầu vào không đáng tin cậy, có thể dẫn đến lỗ hổng SQL Injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn điều này\. Sử dụng SQLAlchemy không đúng cách, không sử dụng tham số tên\.

**Bằng chứng LLM sử dụng**

- Đầu vào 'username' được lấy từ request\.get\_json\(\), có thể bị kiểm soát bởi người tấn công\.
- Chuỗi SQL được tạo bằng cách sử dụng f\-string với giá trị 'username' không được xử lý an toàn\.
- Đoạn mã sử dụng db\.session\.execute\(query\) với query là chuỗi SQL thô, không sử dụng tham số tên hoặc biểu thức SQL\.
- Không có biện pháp kiểm tra, xác thực, hoặc mã hóa nào được áp dụng để ngăn chặn SQL Injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'username' là đầu vào không đáng tin cậy từ người dùng\.
- Giả sử rằng không có biện pháp kiểm soát nào được áp dụng để ngăn chặn SQL Injection\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.15. MANUAL\_REVIEW — python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ca74f831df1cadc0 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.jwt\.security\.jwt\-hardcode\.jwt\-python\-hardcoded\-secret |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 42–50 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-522\: Insufficiently Protected Credentials'\]; owasp=\['A02\:2017 \- Broken Authentication', 'A04\:2021 \- Insecure Design', 'A06\:2025 \- Insecure Design'\]; references=\['https\:\/\/semgrep\.dev\/blog\/2020\/hardcoded\-secrets\-unverified\-tokens\-and\-other\-common\-jwt\-mistakes\/'\]; technology=\['jwt'\] |
| Thời gian xử lý | 1635 ms |

**Thông báo của scanner**

> Hardcoded JWT secret or private key is used\. This is a Insufficiently Protected Credentials weakness\: https\:\/\/cwe\.mitre\.org\/data\/definitions\/522\.html Consider using an appropriate security mechanism to protect the credentials \(e\.g\. keeping secrets in environment variables\)

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 30\-79, hàm login, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Một khóa bí mật JWT được mã hóa cứng trong mã nguồn, không được lấy từ biến môi trường\. Điều này vi phạm quy tắc bảo mật về việc lưu trữ thông tin xác thực một cách an toàn\. Không có cơ chế nào được sử dụng để bảo vệ khóa bí mật này\.

**Bằng chứng LLM sử dụng**

- Khóa 'secret' được truyền trực tiếp vào hàm jwt\.encode mà không được lấy từ biến môi trường\.
- Không có kiểm tra hoặc mã hóa nào được thực hiện trên khóa bí mật trước khi sử dụng\.
- Không có cơ chế nào được sử dụng để bảo vệ khóa bí mật khỏi bị lộ ra ngoài\.
- Thông báo lỗi từ scanner xác nhận rằng khóa JWT được mã hóa cứng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có cơ chế nào được sử dụng để bảo vệ khóa bí mật trong mã nguồn\.
- Không có biến môi trường nào được sử dụng để lưu trữ khóa bí mật\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.16. MANUAL\_REVIEW — python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ce1669e09ae37052 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.sqlalchemy\.security\.sqlalchemy\-execute\-raw\-query\.sqlalchemy\-execute\-raw\-query |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 23 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy'\] |
| Thời gian xử lý | 1492 ms |

**Thông báo của scanner**

> Avoiding SQL string concatenation\: untrusted input concatenated with raw SQL query can result in SQL Injection\. In order to execute raw query safely, prepared statement should be used\. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters\. For complex SQL composition, use SQL Expression Language or Schema Definition Language\. In most cases, SQLAlchemy ORM will be a better option\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 12\-28, hàm register, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy việc sử dụng chuỗi SQL thô với giá trị đầu vào không được kiểm soát\. Điều này có thể dẫn đến lỗ hổng SQL Injection\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc này\.

**Bằng chứng LLM sử dụng**

- Giá trị 'username' được lấy từ request\.get\_json\(\) và được sử dụng trực tiếp trong chuỗi SQL thô\.
- Không có biện pháp kiểm tra, xác thực, hoặc sử dụng prepared statement để ngăn chặn SQL Injection\.
- Câu lệnh SQL được xây dựng bằng cách sử dụng f\-string với giá trị đầu vào không được kiểm soát\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'username' là đầu vào từ người dùng và có thể bị kiểm soát bởi đối tượng tấn công\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.17. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f98496b6d4abfa74 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 49 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 1556 ms |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 44\-62, hàm get\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một chuỗi SQL được xây dựng thủ công từ tham số truy vấn người dùng\. Điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát nào được áp dụng để ngăn chặn việc truyền dữ liệu không an toàn\.

**Bằng chứng LLM sử dụng**

- Tham số 'user\_id' được lấy từ request\.args\.get, một nguồn đầu vào người dùng\.
- Giá trị 'user\_id' được sử dụng trực tiếp trong chuỗi SQL không được tham số hóa\.
- Không có biện pháp kiểm soát, xác thực hoặc làm sạch đầu vào được áp dụng trước khi truyền vào db\.session\.execute\.
- Đường dẫn taint hoàn chỉnh từ nguồn người dùng đến điểm nguy hiểm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'request\.args\.get' là một nguồn đầu vào người dùng không được kiểm soát\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.18. MANUAL\_REVIEW — python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0aba1733dbb21c99 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 47–50 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1833 ms |

**Thông báo của scanner**

> User\-controlled data from a request is passed to 'execute\(\)'\. This could lead to a SQL injection and therefore protected information could be leaked\. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection\. For example, you could use \`Entry\.objects\.filter\(date\=2006\)\`\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 44\-62, hàm get\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một lỗ hổng SQL injection trong đoạn mã khi giá trị từ request\.args được truyền trực tiếp vào execute\(\) mà không có tham số hóa\. Không có biện pháp kiểm soát nào được áp dụng để ngăn chặn việc này\. Sử dụng QuerySets thay vì raw SQL là cách an toàn hơn\.

**Bằng chứng LLM sử dụng**

- Giá trị user\_id được lấy từ request\.args\.get\('user\_id', current\_user\.id\), một nguồn dữ liệu do người dùng kiểm soát\.
- Giá trị user\_id được sử dụng trực tiếp trong chuỗi SQL không được tham số hóa, dẫn đến nguy cơ SQL injection\.
- Không có biện pháp kiểm soát, xác thực, hoặc tham số hóa nào được áp dụng trước khi truyền vào execute\(\)\.
- Đoạn mã sử dụng db\.session\.execute\(query\) với query là chuỗi SQL được xây dựng bằng f\-string\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng request\.args\.get\('user\_id', current\_user\.id\) là một nguồn dữ liệu do người dùng kiểm soát\.
- Giả sử rằng không có biện pháp kiểm soát nào được áp dụng để ngăn chặn SQL injection\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.19. MANUAL\_REVIEW — python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2ac20c15fbc58823 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password |
| File | backend\/app\.py |
| Dòng | 176 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-521\: Weak Password Requirements'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/\#module\-django\.contrib\.auth\.password\_validation'\]; technology=\['django'\] |
| Thời gian xử lý | 1844 ms |

**Thông báo của scanner**

> The password on 'user' is being set without validating the password\. Call django\.contrib\.auth\.password\_validation\.validate\_password\(\) with validation functions before setting the password\. See https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/ for more information\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 166\-186, hàm init\_db\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Mật khẩu được thiết lập cho người dùng mà không có quá trình kiểm tra tính hợp lệ\. Mật khẩu được lấy từ \`user\_data\['password'\]\`, một giá trị có thể bị kiểm soát bởi người dùng, và không có bất kỳ biện pháp kiểm tra nào được thực hiện trước khi thiết lập mật khẩu\. Điều này vi phạm quy trình an toàn được khuyến nghị bởi Django\.

**Bằng chứng LLM sử dụng**

- Mật khẩu được thiết lập bằng \`user\.set\_password\(user\_data\['password'\]\)\` mà không có bất kỳ kiểm tra nào\.
- Giá trị \`user\_data\['password'\]\` được lấy từ \`test\_users\`, một cấu trúc dữ liệu cục bộ, nhưng không có thông tin cho thấy nó được kiểm tra hoặc mã hóa trước khi sử dụng\.
- Không có lời gọi đến \`django\.contrib\.auth\.password\_validation\.validate\_password\(\)\` trước khi thiết lập mật khẩu\.
- Không có biện pháp kiểm soát hoặc xác thực nào được áp dụng cho mật khẩu trước khi lưu trữ\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử \`test\_users\` chứa dữ liệu mật khẩu được cung cấp bởi người dùng hoặc nguồn bên ngoài, do đó có thể bị kiểm soát bởi người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.20. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 3e9f48ada14d4749 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | backend\/app\.py |
| Dòng | 228 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 1453 ms |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 218\-228\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tính năng debug\=True được phát hiện trong mã, nhưng không có bằng chứng cho thấy nó bị kiểm soát bởi người dùng hoặc có thể bị tấn công\. Giá trị này được đặt cố định trong mã và không phụ thuộc vào đầu vào từ người dùng\.

**Bằng chứng LLM sử dụng**

- Giá trị debug\=True được đặt cố định trong mã, không phụ thuộc vào bất kỳ đầu vào nào từ người dùng\.
- Không có luồng taint nào cho thấy giá trị debug bị ảnh hưởng bởi đầu vào người dùng\.
- Không có cơ chế nào trong mã cho phép người dùng thay đổi giá trị debug tại runtime\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng giá trị debug\=True được thiết lập cố định trong mã và không bị thay đổi bởi bất kỳ đầu vào nào từ người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.21. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 56da2d36b375fd74 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | backend\/models\.py |
| Dòng | 27 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 1520 ms |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 26\-27, lớp User, hàm check\_password, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Phát hiện thấy hàm \`hashlib\.md5\` được sử dụng để băm mật khẩu, điều này là không an toàn\. Không có cơ chế kiểm soát hoặc thay thế bằng hàm băm an toàn như \`hashlib\.scrypt\`\. Không có bằng chứng cho thấy giá trị đầu vào không bị kiểm soát bởi người dùng\.

**Bằng chứng LLM sử dụng**

- Hàm \`hashlib\.md5\(password\.encode\(\)\)\.hexdigest\(\)\` được sử dụng trực tiếp để băm mật khẩu\.
- Không có kiểm tra hoặc thay thế bằng hàm băm an toàn như \`hashlib\.scrypt\`\.
- Không có giá trị đầu vào được kiểm soát hoặc mã hóa trước khi băm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử \`password\` là giá trị đầu vào từ người dùng, do đó bị kiểm soát bởi người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.22. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5966d753bb69454c |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 37 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 1819 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 30\-79, hàm login, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được xây dựng bằng cách sử dụng f\-string với giá trị username được lấy từ request\.get\_json\(\)\. Điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp bảo vệ nào được áp dụng trước khi thực thi truy vấn\.

**Bằng chứng LLM sử dụng**

- Giá trị username được lấy từ request\.get\_json\(\), một nguồn đầu vào người dùng có thể bị kiểm soát\.
- Giá trị username được chèn trực tiếp vào truy vấn SQL thông qua f\-string, không sử dụng tham số hóa\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), không có biện pháp kiểm soát hoặc xác thực nào được áp dụng\.
- Không có mã nào được hiển thị để kiểm tra hoặc làm sạch giá trị username trước khi sử dụng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng request\.get\_json\(\) có thể chứa dữ liệu đầu vào từ người dùng không đáng tin cậy\.
- Giả sử rằng không có biện pháp kiểm tra hoặc làm sạch nào được áp dụng cho giá trị username trước khi chèn vào truy vấn SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.23. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 781bfa53fce8e28e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 23 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 1580 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 12\-28, hàm register, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được xây dựng bằng cách sử dụng chuỗi định dạng với giá trị username lấy từ request\. Điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp bảo vệ nào được áp dụng trước khi thực thi truy vấn\.

**Bằng chứng LLM sử dụng**

- Giá trị username được lấy từ request\.get\_json\(\) và được gán trực tiếp vào chuỗi SQL\.
- Truy vấn SQL được xây dựng bằng cách sử dụng f\-string với các giá trị không được tham số hóa\.
- Không có biện pháp kiểm tra hoặc xử lý đầu vào trước khi thực thi truy vấn SQL\.
- Không có mã nào kiểm tra hoặc làm sạch giá trị username trước khi chèn vào cơ sở dữ liệu\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng giá trị username có thể bị kiểm soát bởi người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.24. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9bdecf3c2ae481c6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 50 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 1620 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 44\-62, hàm get\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy một truy vấn SQL được xây dựng bằng cách sử dụng f\-string với giá trị người dùng được truyền trực tiếp từ tham số truy vấn HTTP\. Điều này có thể dẫn đến lỗ hổng SQL injection\. Không có biện pháp kiểm soát an toàn nào được áp dụng\.

**Bằng chứng LLM sử dụng**

- Giá trị 'user\_id' được lấy từ request\.args\.get, là tham số truy vấn HTTP, do người dùng kiểm soát\.
- Giá trị 'user\_id' được gán trực tiếp vào chuỗi SQL mà không được tham số hóa\.
- Truy vấn SQL được thực thi bằng db\.session\.execute\(query\), nơi 'query' chứa giá trị người dùng không được kiểm soát\.
- Không có biện pháp kiểm soát an toàn nào được áp dụng để ngăn chặn SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử rằng 'db\.session\.execute' thực thi truy vấn SQL trực tiếp từ chuỗi được truyền vào\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.25. MANUAL\_REVIEW — python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b93a4c1b0ea8a863 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.formatted\-sql\-query\.formatted\-sql\-query |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 95 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/775296\/mysql\-parameterized\-queries'\]; technology=\['python'\] |
| Thời gian xử lý | 1699 ms |

**Thông báo của scanner**

> Detected possible formatted SQL query\. Use parameterized queries instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 86\-111, hàm search\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Đoạn mã sử dụng tham số từ request\.args\.get\(\) để xây dựng truy vấn SQL trực tiếp bằng f\-string, tạo điều kiện cho lỗ hổng SQL injection\. Không có biện pháp kiểm soát hoặc tham số hóa được áp dụng\. Lỗ hổng được xác nhận rõ ràng\.

**Bằng chứng LLM sử dụng**

- search\_term được lấy từ request\.args\.get\(\), một nguồn đầu vào người dùng có thể bị kiểm soát\.
- search\_term được chèn trực tiếp vào truy vấn SQL thông qua f\-string mà không có tham số hóa\.
- db\.session\.execute\(query\) là điểm cuối \(sink\) thực thi truy vấn SQL với giá trị query bị nhiễm độc\.
- Không có biện pháp kiểm soát, xác thực, hoặc tham số hóa được áp dụng để ngăn chặn SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- request\.args\.get\(\) là nguồn đầu vào người dùng có thể bị kiểm soát\.
- Không có biện pháp kiểm soát nào được áp dụng trước khi thực thi truy vấn SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.26. MANUAL\_REVIEW — python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | bb7368d67ab2f41b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.audit\.unvalidated\-password\.unvalidated\-password |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 146 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-521\: Weak Password Requirements'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/\#module\-django\.contrib\.auth\.password\_validation'\]; technology=\['django'\] |
| Thời gian xử lý | 1581 ms |

**Thông báo của scanner**

> The password on 'user' is being set without validating the password\. Call django\.contrib\.auth\.password\_validation\.validate\_password\(\) with validation functions before setting the password\. See https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/auth\/passwords\/ for more information\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 137\-149, hàm update\_password, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Mật khẩu được thiết lập mà không qua kiểm tra, vi phạm quy trình xác thực Django\. Mật khẩu được lấy từ dữ liệu yêu cầu, không có kiểm tra an toàn trước khi lưu trữ\. Quy tắc yêu cầu gọi validate\_password\(\) trước khi thiết lập mật khẩu\.

**Bằng chứng LLM sử dụng**

- Mật khẩu được lấy từ 'data\.get\('new\_password'\)' mà không có kiểm tra\.
- Mật khẩu được truyền trực tiếp vào 'user\.set\_password\(new\_password\)' mà không qua hàm validate\_password\(\)\.
- Không có kiểm tra hoặc xác thực mật khẩu trước khi lưu trữ\.
- Dữ liệu mật khẩu đến từ request\.get\_json\(\), có thể bị kiểm soát bởi người dùng\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Dữ liệu 'new\_password' đến từ người dùng và có thể bị kiểm soát\.
- Không có kiểm tra hoặc xác thực mật khẩu được thực hiện trước khi lưu trữ\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.27. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d013fb7c5429788a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | backend\/routes\/auth\_routes\.py |
| Dòng | 21 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 1729 ms |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 12\-28, hàm register, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> MD5 được sử dụng để băm mật khẩu, điều này không an toàn\. Không có biện pháp bảo vệ nào được áp dụng để ngăn chặn việc sử dụng thuật toán yếu\. Mật khẩu người dùng được lấy từ đầu vào và không được xử lý trước khi băm\.

**Bằng chứng LLM sử dụng**

- Mật khẩu người dùng được lấy từ \`request\.get\_json\(\)\` và không được kiểm tra hoặc mã hóa trước khi băm\.
- MD5 được sử dụng trực tiếp để băm mật khẩu mà không có bất kỳ biện pháp bảo vệ nào\.
- Không có kiểm tra hoặc xác thực nào được thực hiện trước khi lưu trữ mật khẩu đã băm vào cơ sở dữ liệu\.
- Không có hàm băm an toàn như \`hashlib\.scrypt\` được sử dụng thay thế\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Đầu vào \`request\.get\_json\(\)\` chứa mật khẩu người dùng, có thể bị kiểm soát bởi người tấn công\.
- Không có kiểm tra hoặc xác thực nào được thực hiện trước khi lưu trữ mật khẩu\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.28. MANUAL\_REVIEW — python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d0f0379734a04275 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute |
| File | backend\/routes\/transaction\_routes\.py |
| Dòng | 89–95 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1927 ms |

**Thông báo của scanner**

> User\-controlled data from a request is passed to 'execute\(\)'\. This could lead to a SQL injection and therefore protected information could be leaked\. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection\. For example, you could use \`Entry\.objects\.filter\(date\=2006\)\`\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 86\-111, hàm search\_transactions\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Đoạn mã sử dụng tham số từ request\.args\.get\(\) để xây dựng truy vấn SQL bằng cách nối chuỗi trực tiếp, dẫn đến nguy cơ lỗ hổng SQL injection\. Không có biện pháp kiểm soát hoặc xử lý đầu vào nào được áp dụng, và không có bất kỳ cơ chế bảo vệ nào được sử dụng để ngăn chặn việc truyền dữ liệu người dùng vào truy vấn SQL\.

**Bằng chứng LLM sử dụng**

- Tham số 'search\_term' được lấy từ request\.args\.get\(\), một nguồn dữ liệu do người dùng kiểm soát\.
- Truy vấn SQL được xây dựng bằng cách nối chuỗi trực tiếp với 'search\_term' mà không có tham số hóa\.
- Truy vấn SQL được truyền trực tiếp vào db\.session\.execute\(\), một điểm đích nguy hiểm cho SQL injection\.
- Không có biện pháp kiểm soát, xử lý, hoặc tham số hóa nào được áp dụng để ngăn chặn lỗ hổng SQL injection\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Không có bất kỳ cơ chế kiểm soát nào được áp dụng để ngăn chặn việc truyền dữ liệu người dùng vào truy vấn SQL\.
- Không có bất kỳ tham số hóa hoặc xử lý đầu vào nào được thực hiện trước khi truyền vào truy vấn SQL\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.29. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d37f957261d6bcce |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | backend\/models\.py |
| Dòng | 24 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 1684 ms |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 23\-24, lớp User, hàm set\_password, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Phát hiện thấy hàm \`hashlib\.md5\` được sử dụng để băm mật khẩu, điều này là không an toàn\. Không có cơ chế kiểm soát hoặc thay thế bằng hàm băm an toàn như \`hashlib\.scrypt\`\. Không có bằng chứng cho thấy giá trị đầu vào không phải là mật khẩu hoặc được xử lý an toàn\.

**Bằng chứng LLM sử dụng**

- Hàm \`hashlib\.md5\(password\.encode\(\)\)\.hexdigest\(\)\` được gọi trực tiếp với \`password\` làm đầu vào, không có mã hóa hoặc kiểm tra\.
- Không có cơ chế kiểm soát hoặc xác thực đầu vào trước khi băm\.
- Không có hàm băm an toàn như \`hashlib\.scrypt\` được sử dụng thay thế\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả sử \`password\` là đầu vào từ người dùng, có thể bị kiểm soát bởi đối tượng tấn công\.
- Không có thông tin bổ sung về cách \`password\` được xử lý trước khi truyền vào hàm\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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

### 5.30. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e30d08d566cc3c40 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host |
| File | backend\/app\.py |
| Dòng | 228 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 1569 ms |

**Thông báo của scanner**

> Running flask app with host 0\.0\.0\.0 could expose the server publicly\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 218\-228\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v9

**Kết luận ngắn gọn**

> Tìm thấy lỗi không phải là điểm yếu thực sự vì giá trị 'host' được cung cấp là hằng số '0\.0\.0\.0' và không đến từ đầu vào người dùng\. Không có kiểm soát an ninh nào được áp dụng để ngăn chặn việc chạy ứng dụng trên host này\. Tuy nhiên, giá trị này là cố định và không phụ thuộc vào đầu vào người dùng\.

**Bằng chứng LLM sử dụng**

- Giá trị 'host' được cung cấp là hằng số '0\.0\.0\.0' trong mã\.
- Không có đầu vào người dùng nào được sử dụng để xác định giá trị 'host'\.
- Không có kiểm soát an ninh nào được áp dụng để ngăn chặn việc chạy ứng dụng trên host này\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giá trị 'host' được cung cấp là cố định và không phụ thuộc vào đầu vào người dùng\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
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
- Giai đoạn: PARSE — Đọc và chuẩn hóa artifact; mã lỗi: PARSE\_INVALID\_JSON; scanner: GITLEAKS; finding: null; có thể thử lại: False; thông báo an toàn: Gitleaks artifact file contains invalid JSON\.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
