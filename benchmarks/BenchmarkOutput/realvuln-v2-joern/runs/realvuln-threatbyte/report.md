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
| Thời gian toàn run (giây) | 25\.049968 |

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
| Run ID | 26d7ff5d\-0a8b\-4a54\-844c\-c5736e6568e7 |
| Repository | realvuln\-threatbyte |
| Repository identifier | realvuln\-threatbyte |
| Commit | c4db46f72586c4ecb65859051ea037018dbf0e5e |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 15\.204461 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:44\:10\.478627\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:44\:35\.528595\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570; semgrep=2a28e3507e614ac34c6cb60aece5c24dd0c66def5531ca261304bd28502f8035

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 08d027f9634008a668261852ce96125f3229ef2753aad7ce676e41ffb18ac729 | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:198 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 0c1d123e2926275c6e1cb8a7c3f1841773633bad8abfad170bcf9158516cfac0 | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:207 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 120553b40a81b3a4b3d36561eef766c0ffeb3dcac5d9a9a94f819849cb8f3412 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:132 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 14d59bf4253b07195718138a584161ff71f980f54b501889acb05aafdf13b04b | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:232 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | 152953725043e8facbdc61eda322d52a5284b157bf7a1d4a810d1cbcc2cab4f6 | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:275 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | 1783b64e1d7d12f726d266b4dfa8b3c8d3c61a8509ec76698edd0191f2941d0e | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:266 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | HIGH | 2bace3f57980caf1c7dc4e9f20ee31834013349fd6e46ae2ea231096c98924e3 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:275 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 34deeae5608698ecb80f7c2b7f69c13eed237a035981705c69cad91990f249bb | module2\.joern\.cross\-file\.execute | server\/routes\.py\:206 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | HIGH | 370a085c0317c5a1 | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string | server\/routes\.py\:137 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | HIGH | 4070501fbf2385ec09f901b5013865d08d5c75c2932fd85917f3c2e460cc3e92 | module2\.joern\.cross\-file\.execute | db\/create\_db\_tables\.py\:29 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | HIGH | 41856fca100d8bad2495b7c004fbd25908ddc15068bfd5a29c988b0d4c57541b | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:229 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | HIGH | 42f6a66429b6daeceeb15f3bf2f16aafeba8bf657c02015f38d7510dd38702c3 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:292 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | HIGH | 438a22138892cf3916ad876608076421bc8b73f6ab6f09de121069047c0f4802 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:180 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | HIGH | 4689a8273db4223cfc128b302e069dd3622c5023c3cbccadd25b1c761fa211f8 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:330 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | HIGH | 48123e6dfed166692401a7a36aaa0c18d18cfa5c81bb595f77fa01daa1f6d69c | module2\.joern\.cross\-file\.execute | server\/routes\.py\:356 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 16 | MANUAL\_REVIEW | HIGH | 4c23054158e00d72 | python\.flask\.security\.open\-redirect\.open\-redirect | server\/routes\.py\:256 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 17 | MANUAL\_REVIEW | HIGH | 51adffcb7ab002849b94056fe142443ca35424296d644ee14dc0a5f0504a7782 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:46 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 18 | MANUAL\_REVIEW | HIGH | 51ae5b6b6ddd838369b93b389039891ed43fb55554c88275002b96d7309cbdc1 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:298 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 19 | MANUAL\_REVIEW | HIGH | 6992d928559592b09b2f78b0c166e3f27f701a5ace3fd9136e36c5ff1dd9b343 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:270 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 20 | MANUAL\_REVIEW | HIGH | 6d1d83a26e0c9fe3d88066897f60547c56724c4ec9028d3c55d3b67e73d69cc0 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:350 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 21 | MANUAL\_REVIEW | HIGH | 717c4bc01b8d5aa76c725a9c621651a2e900ce552364f35328e60e508a93ac5c | module2\.joern\.cross\-file\.execute | server\/routes\.py\:106 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 22 | MANUAL\_REVIEW | HIGH | 71b8c024d3a4ad4a2b85ee3468ea5931ad6d55796a78ccf7e7be7cfe02908ae3 | module2\.joern\.cross\-file\.execute | db\/create\_db\_tables\.py\:7 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 23 | MANUAL\_REVIEW | HIGH | 74a40fe27a6a89b7f15387dd06992f21187c1ef20efb67c68c3d5574aece187c | module2\.joern\.cross\-file\.execute | server\/routes\.py\:411 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 24 | MANUAL\_REVIEW | HIGH | 7f0d289c650aac00ae8c139e055dfd0e0997d412e7bde9d6da0978f1306ac241 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:324 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 25 | MANUAL\_REVIEW | HIGH | 84fd0262ab2a8a441c0b3c63c6fdd7918342f77b28751b6b7d4a2871adff5ec2 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:165 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 26 | MANUAL\_REVIEW | HIGH | 8d2f4780cc8e8e3bbae36185781091a4151c31d23da71ae84f59e4ab555b2ce4 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:138 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 27 | MANUAL\_REVIEW | HIGH | 8d6c2b39f080c705761e813abab8a252c7888440ab9d04e90c5557e623f134f6 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:234 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 28 | MANUAL\_REVIEW | HIGH | 8fae7d74208bf1b53b9dd25990eefe314e7ec11632fa83530db895883c97e3b8 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:365 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 29 | MANUAL\_REVIEW | HIGH | 90e35c0627ea455fef2b6c9aee6df82e6dc4018e44935bced6e5684b7fd8c12c | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:288 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 30 | MANUAL\_REVIEW | HIGH | 9b1e2a10f13eebaa027bfb660aed62b7c70fcfeb4d27961cb30d548d45b2e98c | module2\.joern\.cross\-file\.executemany | db\/create\_dummy\_data\.py\:30 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 31 | MANUAL\_REVIEW | HIGH | 9be2c8ce998c5720856d0fdbe4f24469511492a04fdf2880a019e6a90b07c55a | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:164 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 32 | MANUAL\_REVIEW | HIGH | b56142a40e8351172da59bf6b0eae78eb029c2be003cbf75cfd1f6dafd128591 | module2\.joern\.cross\-file\.open | server\/api\/v1\/api\_v1\.py\:284 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 33 | MANUAL\_REVIEW | HIGH | b7ab93417aafe09d6287556922b093223f0e0e6c67af45daf3843c062ad09470 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:140 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 34 | MANUAL\_REVIEW | HIGH | c25bdfe3e082328aed19b25b163c1583bcd45e36366d4b79cdc5bdc60ea6c279 | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:139 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 35 | MANUAL\_REVIEW | HIGH | c5c238cf26ed4ac4718a134ab95de528b20b768f37a19e981367c9e549073ba6 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:99 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 36 | MANUAL\_REVIEW | HIGH | d29f44b4ca57a040 | python\.flask\.security\.open\-redirect\.open\-redirect | server\/routes\.py\:260 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 37 | MANUAL\_REVIEW | HIGH | dcb65958460f7f1f54c2e299e7afeab0498ab17f1e05fdeb8f705b59e351f1fe | module2\.joern\.cross\-file\.execute | server\/routes\.py\:55 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 38 | MANUAL\_REVIEW | HIGH | e3243e5dfc9b5ae1ea043388d7b7095bf7cd94df657ffc70020de94941ac1a36 | module2\.joern\.cross\-file\.execute | server\/api\/v1\/api\_v1\.py\:124 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 39 | MANUAL\_REVIEW | HIGH | f05c8efba8ee3174549e62f32d1cf84a6f46e886c7949781d1bf50db4e937275 | module2\.joern\.cross\-file\.execute | server\/routes\.py\:113 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 40 | MANUAL\_REVIEW | MEDIUM | 024b0079e071e635 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | server\/routes\.py\:403 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 41 | MANUAL\_REVIEW | MEDIUM | 163f85718d0e7180 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | client\/templates\/profile\.html\:41 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 42 | MANUAL\_REVIEW | MEDIUM | 32a750ac4cdac871 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | db\/create\_dummy\_data\.py\:8 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 43 | MANUAL\_REVIEW | MEDIUM | 5a76f9b0f1f820a6 | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | server\/routes\.py\:403 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 44 | MANUAL\_REVIEW | MEDIUM | 80824eb0115e6081 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | client\/templates\/dashboard\.html\:64 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 45 | MANUAL\_REVIEW | MEDIUM | 9306258b6caa770b | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute | server\/routes\.py\:126–140 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 46 | MANUAL\_REVIEW | MEDIUM | c88794c1a775b48a | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password | db\/create\_dummy\_data\.py\:8 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 08d027f9634008a668261852ce96125f3229ef2753aad7ce676e41ffb18ac729 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 198 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 425 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4af2dabec7511a1cbe0a399c96b544239a1e9489055450c6ef2a299eecb4c8dc |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.2. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 0c1d123e2926275c6e1cb8a7c3f1841773633bad8abfad170bcf9158516cfac0 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 207 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 359 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 12b38228f12218e68f5890fa5e58aac6a1fd49c5d1a18d98e73207d52af64120 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.3. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 120553b40a81b3a4b3d36561eef766c0ffeb3dcac5d9a9a94f819849cb8f3412 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 132 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 499 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a347dc6626cc5ef31b3e464153425eca8d91851e563df8e20b493da9037b2777 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.4. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 14d59bf4253b07195718138a584161ff71f980f54b501889acb05aafdf13b04b |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 232 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 399 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 73d04b306603117eea88e5b3a4ec415f3a6dc8babb5cacaa628467f281c5e4d7 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.5. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 152953725043e8facbdc61eda322d52a5284b157bf7a1d4a810d1cbcc2cab4f6 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 275 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 404 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 39950a25c7e182b10a788499c406c87998240e93e0542602800c9903c5176471 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.6. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1783b64e1d7d12f726d266b4dfa8b3c8d3c61a8509ec76698edd0191f2941d0e |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 266 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 477 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5ae10fb343367739cf21ea5ee9b6164bf7f42d1d66cf15cf4713b88cf480da1a |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.7. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2bace3f57980caf1c7dc4e9f20ee31834013349fd6e46ae2ea231096c98924e3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 275 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 509 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d8207d6c2a2dc5c3ce2615c120d0645dc76035aacefeff16016a3ba600ac76c4 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.8. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 34deeae5608698ecb80f7c2b7f69c13eed237a035981705c69cad91990f249bb |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 206 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 380 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1a3e71e4e1e3489567e41b25a76a17053a1e476b19f64239b4a93d4ef6fb2a68 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.9. MANUAL\_REVIEW — python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 370a085c0317c5a1 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.injection\.tainted\-sql\-string\.tainted\-sql\-string |
| File | server\/routes\.py |
| Dòng | 137 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-704\: Incorrect Type Conversion or Cast'\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-textual\-sql', 'https\:\/\/www\.tutorialspoint\.com\/sqlalchemy\/sqlalchemy\_quick\_guide\.htm', 'https\:\/\/docs\.sqlalchemy\.org\/en\/14\/core\/tutorial\.html\#using\-more\-specific\-text\-with\-table\-expression\-literal\-column\-and\-expression\-column'\]; technology=\['sqlalchemy', 'flask'\] |
| Thời gian xử lý | 1371 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 347679b67a80967455f4f1ea5ae1d3464205759054ae451ca79ccdc00d4a106d |

**Thông báo của scanner**

> Detected user input used to manually construct a SQL string\. This is usually bad practice because manual construction could accidentally result in a SQL injection\. An attacker could use a SQL injection to steal or modify contents of the database\. Instead, use a parameterized query which is available by default in most database engines\. Alternatively, consider using an object\-relational mapper \(ORM\) such as SQLAlchemy which will protect your queries\.

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

### 5.10. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4070501fbf2385ec09f901b5013865d08d5c75c2932fd85917f3c2e460cc3e92 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | db\/create\_db\_tables\.py |
| Dòng | 29 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 421 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c82a5c60e4115adc6da1f038738a624c288fd2c2fbc822b96a602fa7a5dec486 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.11. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 41856fca100d8bad2495b7c004fbd25908ddc15068bfd5a29c988b0d4c57541b |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 229 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 576 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 63be015371feb9ba43210e215f8852cb3a36753f0da5b4a3c2ddf4b6f4ea3efe |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.12. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 42f6a66429b6daeceeb15f3bf2f16aafeba8bf657c02015f38d7510dd38702c3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 292 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 379 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a6a64b1275a1ee0035560b7d4628924096398a186c348b2ca13d14659f0245df |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.13. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 438a22138892cf3916ad876608076421bc8b73f6ab6f09de121069047c0f4802 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 180 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 555 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 64699f0d18d747e63c3d8b267dbcce81ca006768f34b9e89ee91a3d410ec1dce |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.14. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4689a8273db4223cfc128b302e069dd3622c5023c3cbccadd25b1c761fa211f8 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 330 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 489 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5000ad68accf311bd34e10e3e6f8fef460bc1e20ec316ac706fa445ab30ef9a3 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.15. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 48123e6dfed166692401a7a36aaa0c18d18cfa5c81bb595f77fa01daa1f6d69c |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 356 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 356 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7053a9e50b0460c4506f3f734355084d19cc5ac01ccdf63288e85cb81767a415 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.16. MANUAL\_REVIEW — python\.flask\.security\.open\-redirect\.open\-redirect

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4c23054158e00d72 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.open\-redirect\.open\-redirect |
| File | server\/routes\.py |
| Dòng | 256 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-601\: URL Redirection to Untrusted Site \('Open Redirect'\)"\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/flask\-login\.readthedocs\.io\/en\/latest\/\#login\-example', 'https\:\/\/cheatsheetseries\.owasp\.org\/cheatsheets\/Unvalidated\_Redirects\_and\_Forwards\_Cheat\_Sheet\.html\#dangerous\-url\-redirect\-example\-1', 'https\:\/\/docs\.python\.org\/3\/library\/urllib\.parse\.html\#url\-parsing'\]; technology=\['flask'\] |
| Thời gian xử lý | 1273 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0aa63f00d6adcb4d043ebf8cf79429e308add09fefc43e78f11250d6b11eb4e3 |

**Thông báo của scanner**

> Data from request is passed to redirect\(\)\. This is an open redirect and could be exploited\. Consider using 'url\_for\(\)' to generate links to known locations\. If you must use a URL to unknown pages, consider using 'urlparse\(\)' or similar and checking if the 'netloc' property is the same as your site's host name\. See the references for more information\.

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

### 5.17. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 51adffcb7ab002849b94056fe142443ca35424296d644ee14dc0a5f0504a7782 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 46 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 468 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7e26c7a6a04623c68ab620454d1504252edc9499c710b8e4cb80bedd8646416f |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.18. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 51ae5b6b6ddd838369b93b389039891ed43fb55554c88275002b96d7309cbdc1 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 298 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 362 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 997454b1d9c1de8951a8b2b7e055737be40b4a7e5b90f31bd14ae844f0b55011 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.19. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6992d928559592b09b2f78b0c166e3f27f701a5ace3fd9136e36c5ff1dd9b343 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 270 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 350 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 428f4e21da9abb24ebcfe9d5ee0911389a7319ce8f9a6370755d42934fdd1195 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.20. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6d1d83a26e0c9fe3d88066897f60547c56724c4ec9028d3c55d3b67e73d69cc0 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 350 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 504 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5a603970396290c63d51f47ea960db26d8ef1d3ebe8efc9a4eb343adaa846328 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.21. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 717c4bc01b8d5aa76c725a9c621651a2e900ce552364f35328e60e508a93ac5c |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 106 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 349 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1ddb086ec3a2a7965bb16b0b32f8c0c535ab7aa14b1988a008d80cdb29795c9b |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.22. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 71b8c024d3a4ad4a2b85ee3468ea5931ad6d55796a78ccf7e7be7cfe02908ae3 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | db\/create\_db\_tables\.py |
| Dòng | 7 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 375 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 46f46a678adb9f90d944a27b258cc1ac414abf47f4dcf96a61f40464c908c0a4 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.23. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 74a40fe27a6a89b7f15387dd06992f21187c1ef20efb67c68c3d5574aece187c |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 411 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 359 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6f65ca4ba1bf7db510d37c27039a2f2672a9804a717e293f83ee9a5f541b9c11 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.24. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7f0d289c650aac00ae8c139e055dfd0e0997d412e7bde9d6da0978f1306ac241 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 324 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 360 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 312df3e89dc63bbe82e344fa746cdc231c5751bc01b067cee20d622f585ba151 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.25. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 84fd0262ab2a8a441c0b3c63c6fdd7918342f77b28751b6b7d4a2871adff5ec2 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 165 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 365 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 37ab706685df63e7e1a09081425e5c1317d84f66912006438aad0986cdd7cdde |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.26. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8d2f4780cc8e8e3bbae36185781091a4151c31d23da71ae84f59e4ab555b2ce4 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 138 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 501 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d8fd5070d6a235ee8f4e391763dc03827a8ed81ba6e150e85dd8ee00dc544ee3 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.27. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8d6c2b39f080c705761e813abab8a252c7888440ab9d04e90c5557e623f134f6 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 234 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 381 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0cd50ffb40b971e5e71cdc29fb90bbb8ea4ff8700d3e4de8fed36b7008364af5 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.28. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8fae7d74208bf1b53b9dd25990eefe314e7ec11632fa83530db895883c97e3b8 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 365 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 468 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1a3001a5f3938cc0691e1716e17a4791152a31a8500b0753602254d4b70b45dc |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.29. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 90e35c0627ea455fef2b6c9aee6df82e6dc4018e44935bced6e5684b7fd8c12c |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 288 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 402 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | b1dac85d73276f078d72127319aa15739fcf44faeb72f4304b4a5b184348d868 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.30. MANUAL\_REVIEW — module2\.joern\.cross\-file\.executemany

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9b1e2a10f13eebaa027bfb660aed62b7c70fcfeb4d27961cb30d548d45b2e98c |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.executemany — Joern cross\-file source\-to\-sink path |
| File | db\/create\_dummy\_data\.py |
| Dòng | 30 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 407 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2e85f55273c6e64532dd716ec20b291f483f6633a8d7537eaeb7926b255b6af8 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.31. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9be2c8ce998c5720856d0fdbe4f24469511492a04fdf2880a019e6a90b07c55a |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 164 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 313 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 12e26688b779e240dcac34eff975a6c24adf775fd17789ca7c314fca8770f89b |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.32. MANUAL\_REVIEW — module2\.joern\.cross\-file\.open

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b56142a40e8351172da59bf6b0eae78eb029c2be003cbf75cfd1f6dafd128591 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.open — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 284 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 516 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f9f27624b45b1721a0362500e11aa410d4aea589e29b19b6bf20be7c12bd3cd0 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source server\/api\/v1\/api\_v1\.py\:283; sink server\/api\/v1\/api\_v1\.py\:284; đường source–sink server\/api\/v1\/api\_v1\.py\:283 → server\/api\/v1\/api\_v1\.py\:283 → server\/api\/v1\/api\_v1\.py\:283 → server\/api\/v1\/api\_v1\.py\:283 → server\/api\/v1\/api\_v1\.py\:283 → server\/api\/v1\/api\_v1\.py\:284 → server\/api\/v1\/api\_v1\.py\:284; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.33. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b7ab93417aafe09d6287556922b093223f0e0e6c67af45daf3843c062ad09470 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 140 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 426 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 106833cf3041e4b2c9936747a030116c94a114819d1cb54e4061d55bf8ef5f8e |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.34. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c25bdfe3e082328aed19b25b163c1583bcd45e36366d4b79cdc5bdc60ea6c279 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 139 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 292 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 909d37665eb8e00363d469f15636757109ecc9f4627622c2a45a84769169c86a |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.35. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c5c238cf26ed4ac4718a134ab95de528b20b768f37a19e981367c9e549073ba6 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 99 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 423 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8c9d6f2b4e9d1411d790aeecc39d7585de25a9036d003b6697bf4fe5046f468c |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.36. MANUAL\_REVIEW — python\.flask\.security\.open\-redirect\.open\-redirect

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d29f44b4ca57a040 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.open\-redirect\.open\-redirect |
| File | server\/routes\.py |
| Dòng | 260 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-601\: URL Redirection to Untrusted Site \('Open Redirect'\)"\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/flask\-login\.readthedocs\.io\/en\/latest\/\#login\-example', 'https\:\/\/cheatsheetseries\.owasp\.org\/cheatsheets\/Unvalidated\_Redirects\_and\_Forwards\_Cheat\_Sheet\.html\#dangerous\-url\-redirect\-example\-1', 'https\:\/\/docs\.python\.org\/3\/library\/urllib\.parse\.html\#url\-parsing'\]; technology=\['flask'\] |
| Thời gian xử lý | 1285 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8d16c08427e38f6694a184e4408dd3d09e7ce6c61da8f5ccebb24ba652069dbe |

**Thông báo của scanner**

> Data from request is passed to redirect\(\)\. This is an open redirect and could be exploited\. Consider using 'url\_for\(\)' to generate links to known locations\. If you must use a URL to unknown pages, consider using 'urlparse\(\)' or similar and checking if the 'netloc' property is the same as your site's host name\. See the references for more information\.

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

### 5.37. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dcb65958460f7f1f54c2e299e7afeab0498ab17f1e05fdeb8f705b59e351f1fe |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 55 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 422 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 13caba9bfdfdf716d889bf3900a5180a53bd3fdb203da16ce0627c5ee585e003 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.38. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | e3243e5dfc9b5ae1ea043388d7b7095bf7cd94df657ffc70020de94941ac1a36 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/api\/v1\/api\_v1\.py |
| Dòng | 124 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 415 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 45a522b32b11ae6aaf07c4f7d2e96b512b79a3b7197f84331cb8c79accd859e1 |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.39. MANUAL\_REVIEW — module2\.joern\.cross\-file\.execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f05c8efba8ee3174549e62f32d1cf84a6f46e886c7949781d1bf50db4e937275 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | server\/routes\.py |
| Dòng | 113 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 453 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 95d099e336e24a716fcbfbc699b5475ba99a35e92cdf709e6557b62398ecfc1f |

**Thông báo của scanner**

> Joern found a bounded cross\-file source\-to\-sink path\.

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

### 5.40. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 024b0079e071e635 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | server\/routes\.py |
| Dòng | 403 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 207 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f4d5e5a68d313ffa65a33a8350664ac7c2996e000618d46c8ff06023961a6f2c |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink server\/routes\.py\:403; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.41. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 163f85718d0e7180 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | client\/templates\/profile\.html |
| Dòng | 41 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 944 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 3662b170eea114cb6333160ddc101c3927c624556c621dca64cbf102c345532b |

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

### 5.42. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 32a750ac4cdac871 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | db\/create\_dummy\_data\.py |
| Dòng | 8 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 224 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5e7aa946c2c7a2d62c525326fee083629d6ec29ede283f8d42dc4bc126bf2b96 |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source chưa xác định; sink db\/create\_dummy\_data\.py\:8; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.43. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 5a76f9b0f1f820a6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | server\/routes\.py |
| Dòng | 403 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 1343 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 02ab8cdae85fcf11c9da234e1f560051a1214ca9d8d9fed79d77cf1fb0efd007 |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source server\/routes\.py\:82; sink server\/routes\.py\:403; đường source–sink server\/routes\.py\:82 → server\/routes\.py\:83 → server\/routes\.py\:84 → server\/routes\.py\:85 → server\/routes\.py\:85 → server\/routes\.py\:85 → server\/routes\.py\:85 → server\/routes\.py\:85 → server\/routes\.py\:89 → server\/routes\.py\:89; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.44. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 80824eb0115e6081 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | client\/templates\/dashboard\.html |
| Dòng | 64 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 1107 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1271df72490954d2cca0477cf5968de757618887e49c2d03b1cffe6f53801e39 |

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

### 5.45. MANUAL\_REVIEW — python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9306258b6caa770b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.django\.security\.injection\.sql\.sql\-injection\-using\-db\-cursor\-execute\.sql\-injection\-db\-cursor\-execute |
| File | server\/routes\.py |
| Dòng | 126–140 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-89\: Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/docs\.djangoproject\.com\/en\/3\.0\/topics\/security\/\#sql\-injection\-protection'\]; technology=\['django'\] |
| Thời gian xử lý | 1021 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 3d278a56502936d4ce018cba61a4b297f4c95384288859e150a1767fe8911fc3 |

**Thông báo của scanner**

> User\-controlled data from a request is passed to 'execute\(\)'\. This could lead to a SQL injection and therefore protected information could be leaked\. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection\. For example, you could use \`Entry\.objects\.filter\(date\=2006\)\`\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source server\/routes\.py\:126; sink server\/routes\.py\:132; đường source–sink server\/routes\.py\:126 → server\/routes\.py\:126 → server\/routes\.py\:126 → server\/routes\.py\:126 → server\/routes\.py\:126 → server\/routes\.py\:137 → server\/routes\.py\:137 → server\/routes\.py\:137 → server\/routes\.py\:137 → server\/routes\.py\:138; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.46. MANUAL\_REVIEW — python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | c88794c1a775b48a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.md5\-used\-as\-password\.md5\-used\-as\-password |
| File | db\/create\_dummy\_data\.py |
| Dòng | 8 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc6151', 'https\:\/\/crypto\.stackexchange\.com\/questions\/44151\/how\-does\-the\-flame\-malware\-take\-advantage\-of\-md5\-collision', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html', 'https\:\/\/security\.stackexchange\.com\/questions\/211\/how\-to\-securely\-hash\-passwords', 'https\:\/\/github\.com\/returntocorp\/semgrep\-rules\/issues\/1609', 'https\:\/\/docs\.python\.org\/3\/library\/hashlib\.html\#hashlib\.scrypt'\]; technology=\['pycryptodome', 'hashlib', 'md5'\] |
| Thời gian xử lý | 850 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | afd986493e27d5d214130ebea068b79d774f5ee8e386c7620432a0f3bb83e96f |

**Thông báo của scanner**

> It looks like MD5 is used as a password hash\. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time\. Use a suitable password hashing function such as scrypt\. You can use \`hashlib\.scrypt\`\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink db\/create\_dummy\_data\.py\:8; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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
