# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 3 |
| Triage thành công | 3 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 1\.727366 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 3 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 098f0553\-7ef9\-4d61\-84c8\-389fc1a5e967 |
| Repository | realvuln\-vfapi |
| Repository identifier | realvuln\-vfapi |
| Commit | f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3 |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 13\.550817 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:45\:47\.467969\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:45\:49\.195335\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=8a5d24b4d0a672f2394dfabc7621f056c02902be505530fa9231181c53717dee

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | MEDIUM | 40d9d6efc0db68e2 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | main\.py\:187 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | MEDIUM | 8fecf7cb07b74bdd | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | main\.py\:113 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | MEDIUM | b5944fe5162bdd1d | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | main\.py\:187 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 40d9d6efc0db68e2 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | main\.py |
| Dòng | 187 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 260 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | dbced5b8c6d22f6b6076ba553177da24c3395369ad909bedfb5c3bc86c0f4a64 |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink main\.py\:187; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.2. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8fecf7cb07b74bdd |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | main\.py |
| Dòng | 113 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 259 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a598290ff29ca24c55841af7e30d4d6c488b8cb013317afecc7a05d057fadaf2 |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink main\.py\:113; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.3. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b5944fe5162bdd1d |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | main\.py |
| Dòng | 187 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 1194 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 73658fc7091dcc1346e0ff46813bf8ffc4a5fa9bc235798e6e595cde4cadd185 |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink main\.py\:187; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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
