# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Pipeline hoàn tất nhưng vẫn còn finding cần chuyên gia review\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 52 |
| Triage thành công | 52 |
| Finding có lỗi | 0 |
| Lỗi scanner | 0 |
| Thời gian toàn run (giây) | 22\.210556 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 52 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | d0534d8c\-362c\-48cd\-92d7\-bc9f6cfd3ec8 |
| Repository | realvuln\-owasp\-web\-playground |
| Repository identifier | realvuln\-owasp\-web\-playground |
| Commit | 5e682aca1b58e03362a5fbd9fc88c37626e429ce |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | fake |
| Model | fake\-triage\-v1 |
| Prompt version | triage\-prompt\-v13 |
| Analysis backend | joern |
| Backend version | 4\.0\.600 |
| Analysis config ID | joern\-pysrc2cpg\-v4\.0\.600\-evidence\-v2 |
| Trạng thái CPG | complete |
| Thời gian dựng CPG | 38\.452587 giây |
| Policy version | conservative\-policy\-v2 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | scan\-and\-triage |
| Bắt đầu | 2026\-08\-20T14\:40\:53\.003254\+00\:00 |
| Kết thúc | 2026\-08\-20T14\:41\:15\.213810\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS; MODULE2
- Thành công: SEMGREP; GITLEAKS; MODULE2
- Phiên bản: GITLEAKS=8\.30\.1; MODULE2=0\.1\.0; SEMGREP=1\.170\.0
- Cấu hình: GITLEAKS=gitleaks\-built\-in; MODULE2=python\-idor\-business\-logic\-v1; SEMGREP=p\/python\+p\/security\-audit
- Hash artifact: gitleaks=9fb4db3b610ba24f8f6740acdf7395ffd7fccb713c4b46f72f315c795a18d36d; semgrep=12047158694d81b97d5989a0012f2b4ff5f42bedcf06900f44ab156dcb5168ea

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 32645a2c03547757 | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/xmlrpc\.py\:6 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 2 | MANUAL\_REVIEW | HIGH | 43a44d6d32d46d1f | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/compat\.py\:81 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 3 | MANUAL\_REVIEW | HIGH | 6ebe981851314794 | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc | venv\/Lib\/site\-packages\/pip\/\_internal\/commands\/search\.py\:5 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 4 | MANUAL\_REVIEW | HIGH | 725382415ca824cd | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/xmlrpc\.py\:14 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 5 | MANUAL\_REVIEW | HIGH | 8b4cf4e84106788f61e237900f11061875e78d9136e88965f771dc0ee5c04248 | module2\.joern\.cross\-file\.execute | python\/database\.py\:145 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 6 | MANUAL\_REVIEW | HIGH | 92e48da03eea17cf | python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization | python\/app\.py\:436 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 7 | MANUAL\_REVIEW | HIGH | 9b104e6f63b342ba | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY | python\/app\.py\:25 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 8 | MANUAL\_REVIEW | HIGH | 9ba7ca590aef0fce4598d6d5d658c7a76e5fc33a94d1c667a674725c6e70bd1f | module2\.joern\.cross\-file\.execute | python\/database\.py\:118 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 9 | MANUAL\_REVIEW | HIGH | d26fd9c70b303b6e | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml | python\/app\.py\:11 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 10 | MANUAL\_REVIEW | HIGH | d92bc82c7fd91a78 | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true | venv\/Lib\/site\-packages\/pip\/\_internal\/commands\/configuration\.py\:239 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 11 | MANUAL\_REVIEW | HIGH | e7c88991619b1075ab91338bb810cf4f522467bb6dadd7520f5d7e4a1e549aba | module2\.joern\.cross\-file\.execute | python\/database\.py\:121 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 12 | MANUAL\_REVIEW | HIGH | fc0175f9be8cd9c9 | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/compat\.py\:42 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 13 | MANUAL\_REVIEW | MEDIUM | 1b68843d4bf24e4d | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py\:172 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 14 | MANUAL\_REVIEW | MEDIUM | 1c11325775110877 | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:367 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 15 | MANUAL\_REVIEW | MEDIUM | 23195c296113a201 | python\.lang\.security\.audit\.marshal\.marshal\-usage | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py\:242 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 16 | MANUAL\_REVIEW | MEDIUM | 262457150349febf | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py\:162 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 17 | MANUAL\_REVIEW | MEDIUM | 2d4c47effd7624b8 | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:387 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 18 | MANUAL\_REVIEW | MEDIUM | 304ad3a63f48096b | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:86 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 19 | MANUAL\_REVIEW | MEDIUM | 34522dca34f67cb3 | python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie | python\/app\.py\:195 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 20 | MANUAL\_REVIEW | MEDIUM | 46fb2f44230b0c52 | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:546–549 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 21 | MANUAL\_REVIEW | MEDIUM | 490bf3051af4fa93 | python\.lang\.security\.audit\.marshal\.marshal\-usage | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py\:751 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 22 | MANUAL\_REVIEW | MEDIUM | 4b1f1052539b562b | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/index\.py\:269 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 23 | MANUAL\_REVIEW | MEDIUM | 4e8e7217436a74bc | python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1 | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py\:205 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 24 | MANUAL\_REVIEW | MEDIUM | 61140bfe09ecdd60 | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled | python\/app\.py\:661 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 25 | MANUAL\_REVIEW | MEDIUM | 667c18699ceea636 | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/pkg\_resources\/\_\_init\_\_\.py\:1714 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 26 | MANUAL\_REVIEW | MEDIUM | 667c6d867c491a77 | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/pkg\_resources\/\_\_init\_\_\.py\:1725 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 27 | MANUAL\_REVIEW | MEDIUM | 66f0b33f66d9f814 | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py\:103 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 28 | MANUAL\_REVIEW | MEDIUM | 6fdeeb00120e1d80 | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py\:177 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 29 | MANUAL\_REVIEW | MEDIUM | 70bd14a1b907b717 | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash | venv\/Lib\/site\-packages\/pip\/\_internal\/self\_outdated\_check\.py\:42 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 30 | MANUAL\_REVIEW | MEDIUM | 73e2e0a80d77db97 | python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host | python\/app\.py\:661 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 31 | MANUAL\_REVIEW | MEDIUM | 77992e04fa227d44 | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/pygments\/lexers\/\_\_init\_\_\.py\:154 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 32 | MANUAL\_REVIEW | MEDIUM | 7b69f3b70b00fff6 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/database\.py\:1007 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 33 | MANUAL\_REVIEW | MEDIUM | 92f7587487160883 | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py\:148 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 34 | MANUAL\_REVIEW | MEDIUM | 973351913c96b03e | python\.lang\.security\.audit\.httpsconnection\-detected\.httpsconnection\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/util\.py\:1572 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 35 | MANUAL\_REVIEW | MEDIUM | 9db04b033f7f26fd | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py\:106 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 36 | MANUAL\_REVIEW | MEDIUM | a57021b634efe2c3 | python\.lang\.security\.audit\.marshal\.marshal\-usage | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py\:475 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 37 | MANUAL\_REVIEW | MEDIUM | b5e2715ee34f2bd4 | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:351 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 38 | MANUAL\_REVIEW | MEDIUM | b8a5d1a78ed89059 | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash | venv\/Lib\/site\-packages\/pip\/\_vendor\/cachecontrol\/caches\/file\_cache\.py\:96 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 39 | MANUAL\_REVIEW | MEDIUM | b91d9243e4f402d2 | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:93 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 40 | MANUAL\_REVIEW | MEDIUM | ba919c176f2a58be | python\.lang\.security\.audit\.exec\-detected\.exec\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/pygments\/formatters\/\_\_init\_\_\.py\:103 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 41 | MANUAL\_REVIEW | MEDIUM | cc54aeb4afa7eb88 | python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1 | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py\:156 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 42 | MANUAL\_REVIEW | MEDIUM | cd22d976d6028de3 | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe | python\/templates\/reflected\_xss\.html\:56 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 43 | MANUAL\_REVIEW | MEDIUM | ce382f2626c39de6 | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle | python\/app\.py\:436 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 44 | MANUAL\_REVIEW | MEDIUM | d078c4f7fc651a40 | python\.lang\.security\.audit\.marshal\.marshal\-usage | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py\:191 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 45 | MANUAL\_REVIEW | MEDIUM | d5bb054b79758b0b | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py\:374 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 46 | MANUAL\_REVIEW | MEDIUM | d6453e9b3c75261f | python\.lang\.security\.audit\.eval\-detected\.eval\-detected | venv\/Lib\/site\-packages\/pip\/\_vendor\/packaging\/licenses\/\_\_init\_\_\.py\:100 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 47 | MANUAL\_REVIEW | MEDIUM | d6684af3c5bbb09f | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash | venv\/Lib\/site\-packages\/pip\/\_internal\/cache\.py\:29 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 48 | MANUAL\_REVIEW | MEDIUM | dc3da15b7114ce26 | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py\:99 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 49 | MANUAL\_REVIEW | MEDIUM | f1f59fde21a8edf4 | python\.lang\.security\.audit\.ssl\-wrap\-socket\-is\-deprecated\.ssl\-wrap\-socket\-is\-deprecated | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/util\/ssl\_\.py\:182 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 50 | MANUAL\_REVIEW | MEDIUM | f5d80ac834e79f4a | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py\:167 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 51 | MANUAL\_REVIEW | LOW | 8018de1b73569035 | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-session\-with\-http\.request\-session\-with\-http | venv\/Lib\/site\-packages\/pip\/\_vendor\/cachecontrol\/\_cmd\.py\:33 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |
| 52 | MANUAL\_REVIEW | UNKNOWN | 9b84acc8ad55bbc2 | generic\-api\-key | \.venv\/Lib\/site\-packages\/jwt\/algorithms\.py\:734 | NEEDS\_REVIEW — LLM chưa đủ bằng chứng để kết luận / MEDIUM — Trung bình |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 32645a2c03547757 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/xmlrpc\.py |
| Dòng | 6 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-776\: Improper Restriction of Recursive Entity References in DTDs \('XML Entity Expansion'\)"\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/pypi\.org\/project\/defusedxml\/', 'https\:\/\/docs\.python\.org\/3\/library\/xml\.html\#xml\-vulnerabilities'\]; technology=\['python'\] |
| Thời gian xử lý | 337 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6d1cc6e6a542871cf0e90b6f8be1a6e096ffa84dd8578085df47f3c840c7fe4a |

**Thông báo của scanner**

> Detected use of xmlrpc\. xmlrpc is not inherently safe from vulnerabilities\. Use defusedxml\.xmlrpc instead\.

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

### 5.2. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 43a44d6d32d46d1f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/compat\.py |
| Dòng | 81 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-776\: Improper Restriction of Recursive Entity References in DTDs \('XML Entity Expansion'\)"\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/pypi\.org\/project\/defusedxml\/', 'https\:\/\/docs\.python\.org\/3\/library\/xml\.html\#xml\-vulnerabilities'\]; technology=\['python'\] |
| Thời gian xử lý | 357 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 1dde903c747cc467c44addbb4339c7e9c0a98be9ba914f2e304527c744c9a171 |

**Thông báo của scanner**

> Detected use of xmlrpc\. xmlrpc is not inherently safe from vulnerabilities\. Use defusedxml\.xmlrpc instead\.

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

### 5.3. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6ebe981851314794 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/commands\/search\.py |
| Dòng | 5 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-776\: Improper Restriction of Recursive Entity References in DTDs \('XML Entity Expansion'\)"\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/pypi\.org\/project\/defusedxml\/', 'https\:\/\/docs\.python\.org\/3\/library\/xml\.html\#xml\-vulnerabilities'\]; technology=\['python'\] |
| Thời gian xử lý | 490 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | be8d98242c33933d5c38cd27876d96aa4ad2f5cf2fa14af494352975ee8ef122 |

**Thông báo của scanner**

> Detected use of xmlrpc\. xmlrpc is not inherently safe from vulnerabilities\. Use defusedxml\.xmlrpc instead\.

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

### 5.4. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 725382415ca824cd |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/xmlrpc\.py |
| Dòng | 14 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-776\: Improper Restriction of Recursive Entity References in DTDs \('XML Entity Expansion'\)"\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/pypi\.org\/project\/defusedxml\/', 'https\:\/\/docs\.python\.org\/3\/library\/xml\.html\#xml\-vulnerabilities'\]; technology=\['python'\] |
| Thời gian xử lý | 318 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a6fac91ad2119f3ef5e7a5699a245d5822c3b44b921742f73ed4b16d1e0b46ad |

**Thông báo của scanner**

> Detected use of xmlrpc\. xmlrpc is not inherently safe from vulnerabilities\. Use defusedxml\.xmlrpc instead\.

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
| Finding ID | 8b4cf4e84106788f61e237900f11061875e78d9136e88965f771dc0ee5c04248 |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | python\/database\.py |
| Dòng | 145 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 495 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f623ca7a8e4a56bc68ff16dabd9201cedc8d673d71b5be5956fdcd1845c47e5f |

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

### 5.6. MANUAL\_REVIEW — python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 92e48da03eea17cf |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.insecure\-deserialization\.insecure\-deserialization |
| File | python\/app\.py |
| Dòng | 436 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['flask'\] |
| Thời gian xử lý | 910 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 7343efe07a289a91fe93992e80df9cfea7d309040862f0163c4d7d97b124cf19 |

**Thông báo của scanner**

> Detected the use of an insecure deserialization library in a Flask route\. These libraries are prone to code execution vulnerabilities\. Ensure user data does not enter this function\. To fix this, try to avoid serializing whole objects\. Consider instead using a serializer such as JSON\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source python\/app\.py\:433; sink python\/app\.py\:436; đường source–sink python\/app\.py\:433 → python\/app\.py\:433 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:436 → python\/app\.py\:436 → python\/app\.py\:436; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.7. MANUAL\_REVIEW — python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9b104e6f63b342ba |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.hardcoded\-config\.avoid\_hardcoded\_config\_SECRET\_KEY |
| File | python\/app\.py |
| Dòng | 25 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/bento\.dev\/checks\/flask\/avoid\-hardcoded\-config\/', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#builtin\-configuration\-values', 'https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/config\/?highlight\=configuration\#environment\-and\-debug\-features'\]; technology=\['flask'\] |
| Thời gian xử lý | 799 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 83132545d6d3449e48f8cf4fa9a87506c2740ac64959c302a4a575ad29b6c19f |

**Thông báo của scanner**

> Hardcoded variable \`SECRET\_KEY\` detected\. Use environment variables or config files instead

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
| Finding ID | 9ba7ca590aef0fce4598d6d5d658c7a76e5fc33a94d1c667a674725c6e70bd1f |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | python\/database\.py |
| Dòng | 118 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 367 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c18406bb9f7629092264021acbf9515231a5bcd1069e96fef12f472f306e9b81 |

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

### 5.9. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d26fd9c70b303b6e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xml\.use\-defused\-xml |
| File | python\/app\.py |
| Dòng | 11 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-611\: Improper Restriction of XML External Entity Reference'\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/xml\.html', 'https\:\/\/github\.com\/tiran\/defusedxml', 'https\:\/\/owasp\.org\/www\-community\/vulnerabilities\/XML\_External\_Entity\_\(XXE\)\_Processing'\]; technology=\['python'\] |
| Thời gian xử lý | 965 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 3ac8a855d01cdd52ccb3fd8c7911dd50f98c7d8e95b72955e93c5c9d488b8b88 |

**Thông báo của scanner**

> The Python documentation recommends using \`defusedxml\` instead of \`xml\` because the native Python \`xml\` library is vulnerable to XML External Entity \(XXE\) attacks\. These attacks can leak confidential data and "XML bombs" can cause denial of service\.

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

### 5.10. MANUAL\_REVIEW — python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d92bc82c7fd91a78 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/commands\/configuration\.py |
| Dòng | 239 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-78\: Improper Neutralization of Special Elements used in an OS Command \('OS Command Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/3172470\/actual\-meaning\-of\-shell\-true\-in\-subprocess', 'https\:\/\/docs\.python\.org\/3\/library\/subprocess\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 449 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2bc68d9063c0d8adfcd9d6e04d64a59c96470cf7dd8989345a60c2bc842bbadc |

**Thông báo của scanner**

> Found 'subprocess' function 'check\_call' with 'shell\=True'\. This is dangerous because this call will spawn the command using a shell process\. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands\. Use 'shell\=False' instead\.

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
| Finding ID | e7c88991619b1075ab91338bb810cf4f522467bb6dadd7520f5d7e4a1e549aba |
| Scanner / loại finding | MODULE2 / SAST |
| Rule | module2\.joern\.cross\-file\.execute — Joern cross\-file source\-to\-sink path |
| File | python\/database\.py |
| Dòng | 121 |
| Severity | HIGH |
| Metadata an toàn | analysis\_backend=joern; analysis\_scope=cross\_file |
| Thời gian xử lý | 368 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | cb7d48341a3e120cd9d1d26acc396071265555a082a0c78169f7057ecad0e6c3 |

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

### 5.12. MANUAL\_REVIEW — python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | fc0175f9be8cd9c9 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.use\-defused\-xmlrpc\.use\-defused\-xmlrpc |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/compat\.py |
| Dòng | 42 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-776\: Improper Restriction of Recursive Entity References in DTDs \('XML Entity Expansion'\)"\]; owasp=\['A04\:2017 \- XML External Entities \(XXE\)', 'A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/pypi\.org\/project\/defusedxml\/', 'https\:\/\/docs\.python\.org\/3\/library\/xml\.html\#xml\-vulnerabilities'\]; technology=\['python'\] |
| Thời gian xử lý | 451 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 6759441740b508316cfdd1b0e42f93b8495a9a878a19dca2da1c7f231e1bb24a |

**Thông báo của scanner**

> Detected use of xmlrpc\. xmlrpc is not inherently safe from vulnerabilities\. Use defusedxml\.xmlrpc instead\.

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

### 5.13. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1b68843d4bf24e4d |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py |
| Dòng | 172 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 310 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 051b1cdac21cfd5e174f1c7ed5bf01f0e22cf1f9045925ca86f15e5515112d92 |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.14. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 1c11325775110877 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 367 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 463 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8fbefee6b363c90de32c644b30b8e509a152a98e9c19335867d00e03dd4a6114 |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Found credentials in index url for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.15. MANUAL\_REVIEW — python\.lang\.security\.audit\.marshal\.marshal\-usage

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 23195c296113a201 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.marshal\.marshal\-usage |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py |
| Dòng | 242 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security'\]; technology=\['python'\] |
| Thời gian xử lý | 334 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | cce238c53db43c746b8970c087b39cffd72184a46269808f4a7165b5e28d59b1 |

**Thông báo của scanner**

> The marshal module is not intended to be secure against erroneous or maliciously constructed data\. Never unmarshal data received from an untrusted or unauthenticated source\. See more details\: https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security

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

### 5.16. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 262457150349febf |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py |
| Dòng | 162 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 344 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4c5f64da696687191294dd0ecf7255a9da2e4d41aefc6ac1cecbb6d2730ffc13 |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.17. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 2d4c47effd7624b8 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 387 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 335 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e00c922f477e0cbaea27867ccb0d7c6133649bb7368c477499824a5bfda8766f |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Found credentials in keyring for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.18. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 304ad3a63f48096b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 86 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 412 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | adeacf4ace6c8dede7370f3ace06b2e4ff17e463975a1778f10b94f851b7cef0 |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Getting credentials from keyring for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.19. MANUAL\_REVIEW — python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 34522dca34f67cb3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.secure\-set\-cookie\.secure\-set\-cookie |
| File | python\/app\.py |
| Dòng | 195 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-614\: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"\]; owasp=\['A05\:2021 \- Security Misconfiguration', 'A02\:2025 \- Security Misconfiguration'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/3\.0\.x\/api\/\#flask\.Response\.set\_cookie', 'https\:\/\/flask\.palletsprojects\.com\/en\/3\.0\.x\/security\/\#set\-cookie\-options'\]; technology=\['python', 'flask'\] |
| Thời gian xử lý | 746 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d6c8ff15272039a89bc13d054c2e1b81496ccf2ddc000f5a849842a976cd19cb |

**Thông báo của scanner**

> Found a Flask cookie with insecurely configured properties\.  By default the secure, httponly and samesite ar configured insecurely\. cookies should be handled securely by setting \`secure\=True\`, \`httponly\=True\`, and \`samesite\='Lax'\` in response\.set\_cookie\(\.\.\.\)\. If these parameters are not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker\. Include the \`secure\=True\`, \`httponly\=True\`, \`samesite\='Lax'\` arguments or set these to be true in the Flask configuration\.

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

### 5.20. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 46fb2f44230b0c52 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 546–549 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 470 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | fd0dd3b1b0c429b34ba35ea36f3a6b2c98def882f3cb42536ae77d8da68a457e |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "401 Error, Credentials not correct for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.21. MANUAL\_REVIEW — python\.lang\.security\.audit\.marshal\.marshal\-usage

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 490bf3051af4fa93 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.marshal\.marshal\-usage |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py |
| Dòng | 751 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security'\]; technology=\['python'\] |
| Thời gian xử lý | 340 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 709c1097a02230180da16363638591d5fd619adbca63c103e5bf3fd4dfba182f |

**Thông báo của scanner**

> The marshal module is not intended to be secure against erroneous or maliciously constructed data\. Never unmarshal data received from an untrusted or unauthenticated source\. See more details\: https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security

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

### 5.22. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4b1f1052539b562b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/index\.py |
| Dòng | 269 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 346 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a29c487e07b3d331debf58f29f26bc22687e3bd76b8c71392c3ab0afa30ee49b |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

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

### 5.23. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 4e8e7217436a74bc |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1 |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py |
| Dòng | 205 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 337 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5ba6da1a93a55723f4dfcba2a7aa6b31ed19c10c8a9316e9f2e8a44c51d7d526 |

**Thông báo của scanner**

> Detected SHA1 hash algorithm which is considered insecure\. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

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

### 5.24. MANUAL\_REVIEW — python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 61140bfe09ecdd60 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.debug\-enabled\.debug\-enabled |
| File | python\/app\.py |
| Dòng | 661 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-489\: Active Debug Code'\]; owasp=A06\:2017 \- Security Misconfiguration; references=\['https\:\/\/labs\.detectify\.com\/2015\/10\/02\/how\-patreon\-got\-hacked\-publicly\-exposed\-werkzeug\-debugger\/'\]; technology=\['flask'\] |
| Thời gian xử lý | 545 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 851c9b275364e6c228ff105081ec8f4a04a6117934922be5300e48833022816c |

**Thông báo của scanner**

> Detected Flask app with debug\=True\. Do not deploy to production with this flag enabled as it will leak sensitive information\. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink python\/app\.py\:661; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.25. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 667c18699ceea636 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/pkg\_resources\/\_\_init\_\_\.py |
| Dòng | 1714 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 334 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 930d75f91d725eea5cc20fc0a12b486302eb275e11f66f119d6ef244a1117345 |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

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

### 5.26. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 667c6d867c491a77 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/pkg\_resources\/\_\_init\_\_\.py |
| Dòng | 1725 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 343 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 9d1035df356c2f7ba7aefdfe2cc6f91783f12c83fc90b7f304bae3800f30bbdf |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

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

### 5.27. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 66f0b33f66d9f814 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py |
| Dòng | 103 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 350 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5490464cd9a1dfd5e231b79c3d93bb8dbce1e7914f5292571b6622fa664b7b98 |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.28. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 6fdeeb00120e1d80 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py |
| Dòng | 177 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 366 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5c49d8820f72ba6790fe83d9450e6d52d9d18dcc12f849151eceda9e366ebd1b |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.29. MANUAL\_REVIEW — python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 70bd14a1b907b717 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/self\_outdated\_check\.py |
| Dòng | 42 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/nvlpubs\.nist\.gov\/nistpubs\/SpecialPublications\/NIST\.SP\.800\-131Ar3\.ipd\.pdf', 'https\:\/\/www\.cyber\.gov\.au\/resources\-business\-and\-government\/essential\-cyber\-security\/ism\/cyber\-security\-guidelines\/guidelines\-cryptography'\]; technology=\['python'\] |
| Thời gian xử lý | 412 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | e40d6dd5b5b97c5774dd827cc49d4f7556ec22c8c40ce346a3191c759f4ae356 |

**Thông báo của scanner**

> This code uses a 224\-bit hash function, which is deprecated or disallowed in some security policies\. Consider updating to a stronger hash function such as SHA\-384 or higher to ensure compliance and security\.

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

### 5.30. MANUAL\_REVIEW — python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 73e2e0a80d77db97 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.audit\.app\-run\-param\-config\.avoid\_app\_run\_with\_bad\_host |
| File | python\/app\.py |
| Dòng | 661 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-668\: Exposure of Resource to Wrong Sphere'\]; owasp=\['A01\:2021 \- Broken Access Control', 'A01\:2025 \- Broken Access Control'\]; references=\['https\:\/\/owasp\.org\/Top10\/A01\_2021\-Broken\_Access\_Control'\]; technology=\['flask'\] |
| Thời gian xử lý | 659 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | bc69480da05d3e9f04cd7fc19544ae3fea703a2d32c4c7a1956525ace78bb8a2 |

**Thông báo của scanner**

> Running flask app with host 0\.0\.0\.0 could expose the server publicly\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence partial; source chưa xác định; sink python\/app\.py\:661; đường source–sink chưa có đường đi đầy đủ; control không tìm thấy; Agent dừng vì AGENT\_NO\_PROGRESS\.

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

### 5.31. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 77992e04fa227d44 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/pygments\/lexers\/\_\_init\_\_\.py |
| Dòng | 154 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 458 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | b4d85ed20f45cbb26c03445c76c33fa69f803f64c1eb37a0e9a1dc5da5d05532 |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

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

### 5.32. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 7b69f3b70b00fff6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/database\.py |
| Dòng | 1007 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 408 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5ddfc81193bfd74a62c32cc5319d5604298fbfd6a35163931042a6b474df8e0b |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

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

### 5.33. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 92f7587487160883 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\-md5\.insecure\-hash\-algorithm\-md5 |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py |
| Dòng | 148 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 305 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | a50e9e28bf9d94966eb5f54c85ba56178ac6b147a49221afd35f5675391a6548 |

**Thông báo của scanner**

> Detected MD5 hash algorithm which is considered insecure\. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

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

### 5.34. MANUAL\_REVIEW — python\.lang\.security\.audit\.httpsconnection\-detected\.httpsconnection\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 973351913c96b03e |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.httpsconnection\-detected\.httpsconnection\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/distlib\/util\.py |
| Dòng | 1572 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-295\: Improper Certificate Validation'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection'\]; technology=\['python'\] |
| Thời gian xử lý | 303 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 74fa8622e42cc743f4c1dbecb3765c095fc646246e2670a5e8b9cfe8846a8c5f |

**Thông báo của scanner**

> The HTTPSConnection API has changed frequently with minor releases of Python\. Ensure you are using the API for your version of Python securely\. For example, Python 3 versions prior to 3\.4\.3 will not verify SSL certificates by default\. See https\:\/\/docs\.python\.org\/3\/library\/http\.client\.html\#http\.client\.HTTPSConnection for more information\.

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

### 5.35. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9db04b033f7f26fd |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py |
| Dòng | 106 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 290 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 655e42c9254ae58ecd733991b52d290fb116379eb09f10f8c36ea23dab254cba |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.36. MANUAL\_REVIEW — python\.lang\.security\.audit\.marshal\.marshal\-usage

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a57021b634efe2c3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.marshal\.marshal\-usage |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py |
| Dòng | 475 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security'\]; technology=\['python'\] |
| Thời gian xử lý | 314 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 24de9b26a6bff0c8545c4fd9025a7f3c7bbe9a6d532ab14498a518bbf0b500ec |

**Thông báo của scanner**

> The marshal module is not intended to be secure against erroneous or maliciously constructed data\. Never unmarshal data received from an untrusted or unauthenticated source\. See more details\: https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security

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

### 5.37. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b5e2715ee34f2bd4 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 351 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 377 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 0ed3c831a8490c50db6f4ab9bc43c3eb1b50b7de21e3aaf0e8cce896f1c3c52f |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Found credentials in url for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.38. MANUAL\_REVIEW — python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b8a5d1a78ed89059 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/cachecontrol\/caches\/file\_cache\.py |
| Dòng | 96 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/nvlpubs\.nist\.gov\/nistpubs\/SpecialPublications\/NIST\.SP\.800\-131Ar3\.ipd\.pdf', 'https\:\/\/www\.cyber\.gov\.au\/resources\-business\-and\-government\/essential\-cyber\-security\/ism\/cyber\-security\-guidelines\/guidelines\-cryptography'\]; technology=\['python'\] |
| Thời gian xử lý | 344 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 59c84e863904eb89a2518b78cc9da90b344bf94429bea0bbb7bf50b742c200b7 |

**Thông báo của scanner**

> This code uses a 224\-bit hash function, which is deprecated or disallowed in some security policies\. Consider updating to a stronger hash function such as SHA\-384 or higher to ensure compliance and security\.

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

### 5.39. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | b91d9243e4f402d2 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 93 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 407 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 555979960ddcf3f8e953132489dec3f6a399b853190f630b5ef7869098d32932 |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Getting password from keyring for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.40. MANUAL\_REVIEW — python\.lang\.security\.audit\.exec\-detected\.exec\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ba919c176f2a58be |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.exec\-detected\.exec\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/pygments\/formatters\/\_\_init\_\_\.py |
| Dòng | 103 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 395 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 8babab687acf8b2571b1f80b2d442b50db3c53c69dc4a80d73956c6f22443c52 |

**Thông báo của scanner**

> Detected the use of exec\(\)\. exec\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

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

### 5.41. MANUAL\_REVIEW — python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cc54aeb4afa7eb88 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.insecure\-hash\-algorithms\.insecure\-hash\-algorithm\-sha1 |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/requests\/auth\.py |
| Dòng | 156 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/www\.schneier\.com\/blog\/archives\/2012\/10\/when\_will\_we\_se\.html', 'https\:\/\/www\.trendmicro\.com\/vinfo\/us\/security\/news\/vulnerabilities\-and\-exploits\/sha\-1\-collision\-signals\-the\-end\-of\-the\-algorithm\-s\-viability', 'http\:\/\/2012\.sharcs\.org\/slides\/stevens\.pdf', 'https\:\/\/pycryptodome\.readthedocs\.io\/en\/latest\/src\/hash\/sha3\_256\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 358 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 345e5a87753a2887fcb9348b47fe327a0d4c83f2f3a7175ce613a81d90258abe |

**Thông báo của scanner**

> Detected SHA1 hash algorithm which is considered insecure\. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature\. Use SHA256 or SHA3 instead\.

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

### 5.42. MANUAL\_REVIEW — python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | cd22d976d6028de3 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.flask\.security\.xss\.audit\.template\-unescaped\-with\-safe\.template\-unescaped\-with\-safe |
| File | python\/templates\/reflected\_xss\.html |
| Dòng | 56 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-79\: Improper Neutralization of Input During Web Page Generation \('Cross\-site Scripting'\)"\]; owasp=\['A07\:2017 \- Cross\-Site Scripting \(XSS\)', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/flask\.palletsprojects\.com\/en\/1\.1\.x\/security\/\#cross\-site\-scripting\-xss'\]; technology=\['flask'\] |
| Thời gian xử lý | 467 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4ce21ce13ddd5b1b99eee052cb5f7770eac2846fda25cf23924c2136f470a9cf |

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

### 5.43. MANUAL\_REVIEW — python\.lang\.security\.deserialization\.pickle\.avoid\-pickle

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | ce382f2626c39de6 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.deserialization\.pickle\.avoid\-pickle |
| File | python\/app\.py |
| Dòng | 436 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/pickle\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 694 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 84f98ee61e7ae74ec3ef104f20e37214f6e427affcd27bf706958d69ff8e269f |

**Thông báo của scanner**

> Avoid using \`pickle\`, which is known to lead to code execution vulnerabilities\. When unpickling, the serialized data could be manipulated to run arbitrary code\. Instead, consider serializing the relevant data as JSON or a similar text\-based serialization format\.

**Tóm tắt ngữ cảnh an toàn**

> Joern CPG evidence complete; source python\/app\.py\:433; sink python\/app\.py\:436; đường source–sink python\/app\.py\:433 → python\/app\.py\:433 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:435 → python\/app\.py\:436 → python\/app\.py\:436 → python\/app\.py\:436; control không tìm thấy; Agent dừng vì EVIDENCE\_SUFFICIENT\.

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

### 5.44. MANUAL\_REVIEW — python\.lang\.security\.audit\.marshal\.marshal\-usage

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d078c4f7fc651a40 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.marshal\.marshal\-usage |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/rich\/style\.py |
| Dòng | 191 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-502\: Deserialization of Untrusted Data'\]; owasp=\['A08\:2017 \- Insecure Deserialization', 'A08\:2021 \- Software and Data Integrity Failures', 'A08\:2025 \- Software or Data Integrity Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security'\]; technology=\['python'\] |
| Thời gian xử lý | 334 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4a82dae423e552652dfa8d9521035ad91d57a81f7cff8e3607f81c314ae02b38 |

**Thông báo của scanner**

> The marshal module is not intended to be secure against erroneous or maliciously constructed data\. Never unmarshal data received from an untrusted or unauthenticated source\. See more details\: https\:\/\/docs\.python\.org\/3\/library\/marshal\.html?highlight\=security

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

### 5.45. MANUAL\_REVIEW — python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d5bb054b79758b0b |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.logging\.logger\-credential\-leak\.python\-logger\-credential\-disclosure |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/network\/auth\.py |
| Dòng | 374 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-532\: Insertion of Sensitive Information into Log File'\]; owasp=\['A09\:2021 \- Security Logging and Monitoring Failures', 'A09\:2025 \- Security Logging &amp; Alerting Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A09\_2021\-Security\_Logging\_and\_Monitoring\_Failures'\]; technology=\['python'\] |
| Thời gian xử lý | 384 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | c6aeccb5406777a69d8f9d6ef5a68b2337c97857ff93798509b5d02f772212e3 |

**Thông báo của scanner**

> Detected a python logger call with a potential hardcoded secret "Found credentials in netrc for %s" being logged\. This may lead to secret credentials being exposed\. Make sure that the logger is not logging  sensitive information\.

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

### 5.46. MANUAL\_REVIEW — python\.lang\.security\.audit\.eval\-detected\.eval\-detected

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d6453e9b3c75261f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.eval\-detected\.eval\-detected |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/packaging\/licenses\/\_\_init\_\_\.py |
| Dòng | 100 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=LOW; cwe=\["CWE\-95\: Improper Neutralization of Directives in Dynamically Evaluated Code \('Eval Injection'\)"\]; owasp=\['A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/owasp\.org\/Top10\/A03\_2021\-Injection'\]; technology=\['python'\] |
| Thời gian xử lý | 335 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 152a911eb797afd338ea0b55f427e8e252ce56141fb2e471b28759bd3cb4a857 |

**Thông báo của scanner**

> Detected the use of eval\(\)\. eval\(\) can be dangerous if used to evaluate dynamic content\. If this content can be input from outside the program, this may be a code injection vulnerability\. Ensure evaluated content is not definable by external sources\.

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

### 5.47. MANUAL\_REVIEW — python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | d6684af3c5bbb09f |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.sha224\-hash\.sha224\-hash |
| File | venv\/Lib\/site\-packages\/pip\/\_internal\/cache\.py |
| Dòng | 29 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=HIGH; cwe=\['CWE\-327\: Use of a Broken or Risky Cryptographic Algorithm'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/nvlpubs\.nist\.gov\/nistpubs\/SpecialPublications\/NIST\.SP\.800\-131Ar3\.ipd\.pdf', 'https\:\/\/www\.cyber\.gov\.au\/resources\-business\-and\-government\/essential\-cyber\-security\/ism\/cyber\-security\-guidelines\/guidelines\-cryptography'\]; technology=\['python'\] |
| Thời gian xử lý | 466 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 5d77fc1844a88c82f9e3b73b75abe447ba0491f023ec23c98db360b68dcd0fc6 |

**Thông báo của scanner**

> This code uses a 224\-bit hash function, which is deprecated or disallowed in some security policies\. Consider updating to a stronger hash function such as SHA\-384 or higher to ensure compliance and security\.

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

### 5.48. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | dc3da15b7114ce26 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/pyopenssl\.py |
| Dòng | 99 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 460 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | d859c4f22b7c764abdd1cc50bc746ae9d09afe8c3c9102c7c6f5229a89fc1ab9 |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.49. MANUAL\_REVIEW — python\.lang\.security\.audit\.ssl\-wrap\-socket\-is\-deprecated\.ssl\-wrap\-socket\-is\-deprecated

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f1f59fde21a8edf4 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.ssl\-wrap\-socket\-is\-deprecated\.ssl\-wrap\-socket\-is\-deprecated |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/util\/ssl\_\.py |
| Dòng | 182 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.wrap\_socket', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.SSLContext\.wrap\_socket'\]; technology=\['python'\] |
| Thời gian xử lý | 284 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 2da0487967c380fa3102d59b98f7892ba2c5d0d9f5f609acac69d7026f1fae33 |

**Thông báo của scanner**

> 'ssl\.wrap\_socket\(\)' is deprecated\. This function creates an insecure socket without server name indication or hostname matching\. Instead, create an SSL context using 'ssl\.SSLContext\(\)' and use that to wrap a socket\.

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

### 5.50. MANUAL\_REVIEW — python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | f5d80ac834e79f4a |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.weak\-ssl\-version\.weak\-ssl\-version |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/urllib3\/contrib\/securetransport\.py |
| Dòng | 167 |
| Severity | MEDIUM |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-326\: Inadequate Encryption Strength'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/tools\.ietf\.org\/html\/rfc7568', 'https\:\/\/tools\.ietf\.org\/id\/draft\-ietf\-tls\-oldversions\-deprecate\-02\.html', 'https\:\/\/docs\.python\.org\/3\/library\/ssl\.html\#ssl\.PROTOCOL\_TLSv1\_2'\]; technology=\['python'\] |
| Thời gian xử lý | 349 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | f52e19f20721c1417aea8caa14bfab330b8eb4d13c10668bb338b441a04fa7c7 |

**Thông báo của scanner**

> An insecure SSL version was detected\. TLS versions 1\.0, 1\.1, and all SSL versions are considered weak encryption and are deprecated\. Use 'ssl\.PROTOCOL\_TLSv1\_2' or higher\.

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

### 5.51. MANUAL\_REVIEW — python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-session\-with\-http\.request\-session\-with\-http

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 8018de1b73569035 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.insecure\-transport\.requests\.request\-session\-with\-http\.request\-session\-with\-http |
| File | venv\/Lib\/site\-packages\/pip\/\_vendor\/cachecontrol\/\_cmd\.py |
| Dòng | 33 |
| Severity | LOW |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\['CWE\-319\: Cleartext Transmission of Sensitive Information'\]; owasp=\['A03\:2017 \- Sensitive Data Exposure', 'A02\:2021 \- Cryptographic Failures', 'A04\:2025 \- Cryptographic Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A02\_2021\-Cryptographic\_Failures'\]; technology=\['requests'\] |
| Thời gian xử lý | 371 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | fd1b9c55a0a008531e434230325602874f3551d4887a9dfe6a432f910c73978f |

**Thông báo của scanner**

> Detected a request using 'http\:\/\/'\. This request will be unencrypted\. Use 'https\:\/\/' instead\.

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

### 5.52. MANUAL\_REVIEW — generic\-api\-key

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 9b84acc8ad55bbc2 |
| Scanner / loại finding | GITLEAKS / SECRET |
| Rule | generic\-api\-key — Detected a Generic API Key, potentially exposing access to various services and sensitive operations\. |
| File | \.venv\/Lib\/site\-packages\/jwt\/algorithms\.py |
| Dòng | 734 |
| Severity | UNKNOWN |
| Metadata an toàn | entropy=3\.8521688; rule\_description=Detected a Generic API Key, potentially exposing access to various services and sensitive operations\. |
| Thời gian xử lý | 4 ms |
| Thời gian provider | 0 ms |
| SHA-256 đầu vào triage | 4a56408d29b8d7edc482a4cae9a9a8d5fd9a4dc6360b61c3027050d67cee181f |

**Thông báo của scanner**

> Detected a Generic API Key, potentially exposing access to various services and sensitive operations\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh REDACTED\_LINE\_WINDOW, dòng 674\-794\.

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
