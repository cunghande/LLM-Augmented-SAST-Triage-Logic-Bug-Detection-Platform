# Báo cáo SAST Triage

> **Dành cho security reviewer:** Báo cáo này hiển thị quyết định LLM đã qua
> validation và quyết định policy của hệ thống. Đây không phải response thô hay
> chain-of-thought. Không được tự động đóng finding chỉ dựa trên kết luận của LLM.

## 1. Tóm tắt điều hành

**Trạng thái:** Có lỗi cần xử lý; không được bỏ qua các finding liên quan\.

| Chỉ số | Giá trị |
|---|---:|
| Finding đã parse | 2 |
| Triage thành công | 2 |
| Finding có lỗi | 0 |
| Lỗi scanner | 1 |
| Thời gian toàn run (giây) | 209\.991271 |

### Phân bố quyết định policy

| Action | Số lượng | Reviewer cần làm gì |
|---|---:|---|
| TRIAGE\_ERROR — Lỗi xử lý triage — cần kiểm tra hệ thống | 0 | Kiểm tra mã lỗi xử lý và trạng thái provider trước khi đánh giá finding\. |
| MANUAL\_REVIEW — Cần chuyên gia review thủ công | 2 | Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\. |
| LIKELY\_TP — Có khả năng là lỗ hổng thật | 0 | Xác nhận nguồn dữ liệu, điểm sử dụng nguy hiểm và guard\/sanitizer liên quan\. |
| FP\_CANDIDATE — Ứng viên false positive — không tự động đóng | 0 | Xác minh độc lập rằng dữ liệu không thể đi tới điểm sử dụng nguy hiểm\. |

## 2. Cấu hình và khả năng tái lập

| Thuộc tính | Giá trị |
|---|---|
| Run ID | 14e3c621\-1571\-459e\-8ae1\-9beac145f437 |
| Repository | DjangoGoat\-master |
| Repository identifier | red\-and\-black\/DjangoGoat@master |
| Commit | 5e6aaa6d0497bf24abd179304e6ca51295a8091d |
| Trạng thái working tree | clean |
| Xác minh artifact–repository | VERIFIED |
| Provider | modal\-qwen\-structured |
| Model | Qwen\/Qwen3\-14B\-AWQ |
| Prompt version | triage\-prompt\-v4 |
| Policy version | conservative\-policy\-v1 |
| Tool version | 0\.1\.0 |
| Chế độ CLI | benchmark\-modal\-qwen\-djangogoat |
| Bắt đầu | 2026\-08\-07T03\:31\:14\.276244\+00\:00 |
| Kết thúc | 2026\-08\-07T03\:34\:44\.267515\+00\:00 |

### Scanner

- Đã chạy: SEMGREP; GITLEAKS
- Thành công: SEMGREP; GITLEAKS
- Phiên bản: Không có
- Cấu hình: Không có
- Hash artifact: Không có

## 3. Cách đọc verdict và action

- **Verdict của LLM** là đề xuất phân loại dựa trên ngữ cảnh đã làm sạch.
- **Confidence** phản ánh độ mạnh của bằng chứng, không phải severity.
- **Policy action** là quyết định bảo thủ cuối cùng của hệ thống.
- **FP_CANDIDATE** vẫn phải được con người xác nhận; hệ thống không tự loại finding.
- Phần **Phân tích của LLM** chỉ chứa output có cấu trúc đã qua validation.

## 4. Hàng đợi review

| STT | Action | Severity | Finding ID | Rule | Vị trí | Verdict / Confidence |
|---:|---|---|---|---|---|---|
| 1 | MANUAL\_REVIEW | HIGH | 17b12ed046f0a923 | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true | features\/environment\.py\:37 | LIKELY\_FP — LLM đánh giá có khả năng là false positive / HIGH — Cao |
| 2 | MANUAL\_REVIEW | HIGH | a59484cd86b5a3f1 | generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key | dg\-server\.key\:1–2 | LIKELY\_TP — LLM đánh giá có khả năng là true positive / HIGH — Cao |

## 5. Chi tiết từng finding

### 5.1. MANUAL\_REVIEW — python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | 17b12ed046f0a923 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | python\.lang\.security\.audit\.subprocess\-shell\-true\.subprocess\-shell\-true |
| File | features\/environment\.py |
| Dòng | 37 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=MEDIUM; cwe=\["CWE\-78\: Improper Neutralization of Special Elements used in an OS Command \('OS Command Injection'\)"\]; owasp=\['A01\:2017 \- Injection', 'A03\:2021 \- Injection', 'A05\:2025 \- Injection'\]; references=\['https\:\/\/stackoverflow\.com\/questions\/3172470\/actual\-meaning\-of\-shell\-true\-in\-subprocess', 'https\:\/\/docs\.python\.org\/3\/library\/subprocess\.html'\]; technology=\['python'\] |
| Thời gian xử lý | 10839 ms |

**Thông báo của scanner**

> Found 'subprocess' function 'Popen' with 'shell\=True'\. This is dangerous because this call will spawn the command using a shell process\. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands\. Use 'shell\=False' instead\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh PYTHON\_FUNCTION, dòng 24\-42, hàm start\_zap\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_FP — LLM đánh giá có khả năng là false positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule kiểm tra việc sử dụng subprocess\.Popen với shell\=True, có thể gây OS Command Injection\. Tuy nhiên, trong context, tham số được truyền vào là os\.devnull, một giá trị cố định và không do người dùng kiểm soát\. Do đó, không có dữ liệu từ người dùng đến sink, nên không có nguy cơ lỗ hổng\.

**Bằng chứng LLM sử dụng**

- Nguồn\: os\.devnull là giá trị cố định, không do người dùng kiểm soát\.
- Luồng dữ liệu\: os\.devnull được truyền trực tiếp vào open\(\), không qua bất kỳ biến nào có thể bị kiểm soát bởi người dùng\.
- Điểm sử dụng nguy hiểm\: subprocess\.Popen được gọi với shell\=True, nhưng argument không chứa dữ liệu người dùng\.
- Kết luận\: Không có path từ source người dùng đến sink\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả định rằng os\.devnull không thể bị thay đổi bởi người dùng trong ngữ cảnh này\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Có
- **Lý do escalation:** Severity quá cao để tự động phân loại thành ứng viên FP\.
- **Lý do policy:**
  - Finding Semgrep severity cao không được trở thành ứng viên FP\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

### 5.2. MANUAL\_REVIEW — generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key

> **Ưu tiên review:** Cần chuyên gia review thủ công

#### Thông tin finding

| Thuộc tính | Giá trị |
|---|---|
| Finding ID | a59484cd86b5a3f1 |
| Scanner / loại finding | SEMGREP / SAST |
| Rule | generic\.secrets\.security\.detected\-private\-key\.detected\-private\-key |
| File | dg\-server\.key |
| Dòng | 1–2 |
| Severity | HIGH |
| Metadata an toàn | category=security; confidence=LOW; cwe=\['CWE\-798\: Use of Hard\-coded Credentials'\]; owasp=\['A07\:2021 \- Identification and Authentication Failures', 'A07\:2025 \- Authentication Failures'\]; references=\['https\:\/\/owasp\.org\/Top10\/A07\_2021\-Identification\_and\_Authentication\_Failures'\]; technology=\['secrets'\] |
| Thời gian xử lý | 199151 ms |

**Thông báo của scanner**

> Private Key detected\. This is a sensitive credential and should not be hardcoded here\. Instead, store this in a separate, private file\.

**Tóm tắt ngữ cảnh an toàn**

> Ngữ cảnh LINE\_WINDOW, dòng 1\-12, đã bị cắt bớt\.

#### Phân tích của LLM

- **Verdict:** LIKELY\_TP — LLM đánh giá có khả năng là true positive
- **Confidence:** HIGH — Cao
- **Model / Prompt:** Qwen\/Qwen3\-14B\-AWQ / triage\-prompt\-v4

**Kết luận ngắn gọn**

> Rule đang kiểm tra việc phát hiện khóa riêng tư được mã hóa cứng trong mã nguồn\. Context cho thấy một khóa riêng tư dạng PEM được lưu trữ trực tiếp trong tệp dg\-server\.key, không được bảo vệ bằng bất kỳ cơ chế nào\. Không có guard hoặc sanitizer nào được áp dụng để che giấu hoặc bảo vệ khóa này\. Việc lưu trữ khóa riêng tư trong mã nguồn là một lỗ hổng bảo mật rõ ràng theo CWE\-798 và OWASP A07\. Khóa này có thể bị lộ nếu mã nguồn bị rò rỉ\.

**Bằng chứng LLM sử dụng**

- Nguồn\: Khóa riêng tư dạng PEM được lưu trữ trực tiếp trong tệp dg\-server\.key\.
- Luồng dữ liệu\: Khóa được đọc từ tệp và không được xử lý thêm, không có cơ chế bảo vệ\.
- Điểm sử dụng nguy hiểm\: Khóa được lưu trữ trong mã nguồn, không được bảo vệ\.
- Kết luận\: Không có cơ chế bảo vệ hoặc che giấu khóa, dẫn đến rủi ro lộ thông tin nhạy cảm\.

**Thông tin còn thiếu / câu hỏi cần reviewer xác minh**

- LLM không ghi nhận thông tin quan trọng còn thiếu\.

**Giả định LLM đã sử dụng**

- Giả định rằng tệp dg\-server\.key không được bảo vệ bằng bất kỳ cơ chế nào như encryption hoặc access control\.

> Ghi chú: Đây là phần giải thích có cấu trúc đã qua validation, không phải
> nội dung suy luận nội bộ và không thay thế kết luận của security reviewer.

#### Quyết định policy của hệ thống

- **Action:** MANUAL\_REVIEW — Cần chuyên gia review thủ công
- **Policy version:** conservative\-policy\-v1
- **Đã escalated:** Có
- **Lý do escalation:** LLM đã đưa ra verdict khi bằng chứng từ nguồn đến điểm sử dụng nguy hiểm chưa đầy đủ\.
- **Lý do policy:**
  - Bằng chứng ngữ cảnh vẫn chưa đầy đủ sau khi mở rộng trong giới hạn an toàn\.

#### Reviewer nên làm gì tiếp theo

- Đối chiếu kết luận với từng bằng chứng và dữ kiện còn thiếu do LLM nêu\.
- Kiểm tra trực tiếp file và khoảng dòng tương đối trước khi quyết định TP hoặc FP\.
- Nếu dataflow chưa đầy đủ, giữ finding ở trạng thái cần review\.

#### Lỗi xử lý

- Không có lỗi xử lý cho finding này.

## 6. Lỗi scanner
- Giai đoạn: PARSE — Đọc và chuẩn hóa artifact; mã lỗi: PARSE\_RECORD\_INVALID\_FIELD; scanner: GITLEAKS; finding: null; có thể thử lại: False; thông báo an toàn: Gitleaks record\[0\] produced an invalid NormalizedFinding\.

## 7. Ghi chú bảo mật và giới hạn

- Báo cáo không chứa mã nguồn thô, prompt thô, response LLM thô hoặc traceback.
- Đường dẫn trong báo cáo là đường dẫn tương đối của repository.
- Verdict của LLM là dữ liệu hỗ trợ; policy và reviewer mới quyết định xử lý.
- Mọi finding đều xuất hiện trong báo cáo, kể cả khi triage hoặc scanner gặp lỗi.
