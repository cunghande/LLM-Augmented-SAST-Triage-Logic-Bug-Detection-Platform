# LLM-Augmented SAST Triage Platform: Kiến Trúc Phân Loại Lỗ Hổng Bảo Mật Kết Hợp Suy Luận LLM và Kiểm Chứng Tất Định

**Tác giả:** Nhóm Nghiên cứu Kỹ thuật ML/AppSec  
**Tài liệu tham chiếu:** [claims.md](file:///d:/Code/AI%20security/docs/paper/claims.md) | [case_studies.md](file:///d:/Code/AI%20security/docs/paper/case_studies.md)  
**Trạng thái:** Báo cáo hoàn chỉnh — Toàn bộ số liệu thực nghiệm được sinh ra từ các script đo đạc độc lập trong repository.

---

## Tóm tắt (Abstract)

Các công cụ phân tích mã tĩnh (SAST) như Semgrep đóng vai trò thiết yếu trong việc phát hiện sớm lỗ hổng bảo mật trong mã nguồn phần mềm. Tuy nhiên, tỷ lệ cảnh báo giả (False Positives - FP) cao tạo ra gánh nặng phân loại thủ công khổng lồ cho các kỹ sư bảo mật. Việc ứng dụng các mô hình ngôn ngữ lớn (LLM) để tự động hóa triage mang lại tiềm năng lớn nhưng phải đối mặt với hai rủi ro nghiêm trọng: (1) hiện tượng ảo giác (hallucination) có thể dẫn đến việc tự động bỏ qua lỗ hổng thật (False Negatives - FN), và (2) nguy cơ tấn công tiêm nhiễm câu lệnh gián tiếp (Indirect Prompt Injection) ẩn trong mã nguồn không đáng tin cậy.

Bài báo này trình bày thiết kế và đánh giá hệ thống **LLM-Augmented SAST Triage Platform**, một nền tảng CLI phân loại cảnh báo bảo mật kết hợp hai tầng: **Bounded Evidence Collector** (thu thập bằng chứng tĩnh tất định qua AST và Code Property Graph - Joern) và **LLM Triage Reasoner** có kiểm chứng, được bảo vệ bởi **PolicyEngine** theo nguyên tắc fail-closed. 

Chúng tôi thiết lập bộ đánh giá chuẩn hóa trên mã nguồn thực tế (OWASP PyGoat, DjanGoat, DVPWA, VulPy, DVFA với 219 finding), thực hiện kiểm toán rủi ro false negative và đánh giá khả năng chống chịu tấn công prompt injection với bộ test red-team 16 mẫu. Kết quả thực nghiệm cho thấy hệ thống cải thiện F1-score từ 0.6095 (Scanner baseline) lên 0.7033, tiết kiệm 19.18% công sức phân loại cho analyst trong khi vẫn giữ tỷ lệ False Negative ở mức **0.00%** (so với mức FN thảm họa 21.88% của mô hình LLM-Only). Khả năng chống chịu prompt injection đạt tỷ lệ thành công của kẻ tấn công (Attack Success Rate) là **0.00%**, và tỷ lệ rò rỉ canary secret qua 5 định dạng là **0.00%**.

---

## 1. Giới thiệu (Introduction)

Trong chu trình phát triển phần mềm hiện đại (DevSecOps), công cụ SAST là phòng tuyến quan trọng giúp phát hiện lỗi lập trình bảo mật. Tuy nhiên, do thiếu hiểu biết ngữ cảnh sâu và tính chất phân tích xấp xỉ (over-approximation), SAST thường tạo ra lượng lớn cảnh báo không có khả năng khai thác (false positive). Tỷ lệ cảnh báo giả có thể vượt quá 50-60%, gây nên tình trạng mệt mỏi cảnh báo (alert fatigue) và làm chậm trễ việc vá các lỗ hổng nghiêm trọng.

Sự xuất hiện của các LLM chuyên về mã nguồn (như Qwen2.5-Coder-14B) mở ra khả năng hiểu ngữ cảnh phức tạp và chuỗi dữ liệu (dataflow). Tuy nhiên, việc trực tiếp giao toàn quyền quyết định cho LLM tiềm ẩn rủi ro khôn lường:
1. **Nguy cơ bỏ sót lỗ hổng (False Negative):** Một phán quyết sai lầm xem lỗ hổng nghiêm trọng (như SQL Injection, RCE) là FP có thể khiến lỗ hổng lọt vào môi trường sản xuất. Đánh giá của chúng tôi trên 219 finding cho thấy LLM-Only bỏ sót tới **21.88%** lỗ hổng thật.
2. **Rủi ro an ninh kênh gián tiếp:** Mã nguồn phân tích là dữ liệu đầu vào không đáng tin cậy (untrusted data). Kẻ tấn công có thể chèn các câu lệnh điều khiển vào comment hoặc biến code để đánh lừa LLM đưa ra phán quyết sai.

Hệ thống của chúng tôi giải quyết vấn đề này thông qua ba nguyên tắc thiết kế cốt lõi:
1. **Không bao giờ tin tưởng tuyệt đối vào phán đoán của LLM:** LLM chỉ đưa ra đề xuất (`model_verdict`); quyết định hệ thống (`policy_action`) được quyết định bởi PolicyEngine dựa trên bằng chứng tất định.
2. **Nguyên tắc fail-closed:** Mọi lỗi phân tích, context không hoàn chỉnh hoặc mâu thuẫn bằng chứng đều được đẩy về `MANUAL_REVIEW` để con người thẩm định, tuyệt đối không tự động triệt tiêu cảnh báo. Mọi finding đều xuất hiện trong báo cáo.
3. **Phòng thủ đa tầng trước prompt injection:** Cô lập dữ liệu bằng JSON envelope, escape thẻ phân cách, phát hiện mẫu tiêm nhiễm và yêu cầu bằng chứng phủ định độc lập từ công cụ tĩnh trước khi chấp nhận `FP_CANDIDATE`.

---

## 2. Các công trình liên quan (Related Work)

- **Phân tích mã tĩnh và CPG (Code Property Graph):** Khái niệm CPG do Yamaguchi et al. khởi xướng kết hợp AST, CFG (Control Flow Graph) và PDG (Program Dependence Graph). Joern là nền tảng phân tích CPG nguồn mở hàng đầu, cung cấp khả năng dò vết taint-flow mạnh mẽ.
- **Ứng dụng LLM trong Triage bảo mật:** Các nghiên cứu gần đây sử dụng LLM để giải thích cảnh báo SAST và xếp hạng độ ưu tiên. Tuy nhiên, phần lớn các giải pháp hiện nay coi LLM là một oracle ra quyết định trực tiếp mà thiếu các rào chắn kiểm chứng thuộc tính chương trình (program property verifiers).
- **Prompt Injection trong công cụ phân tích bảo mật:** Greshake et al. đã chứng minh tính khả thi của các cuộc tấn công gián tiếp qua dữ liệu bên ngoài. Trong SAST triage, việc đưa trực tiếp mã nguồn vào ngữ cảnh suy luận tạo ra bề mặt tấn công trực diện nếu không có cơ chế cách ly và lọc nghiêm ngặt.

---

## 3. Mô hình đe dọa (Threat Model)

Mô hình đe dọa của hệ thống giả định:
1. **Mã nguồn trong repository là không đáng tin cậy (Untrusted):** Repository được quét có thể chứa mã độc hại, payload prompt injection được thiết kế tinh vi nhằm vô hiệu hóa công cụ quét hoặc ép model trả về `LIKELY_FP`.
2. **Kênh truyền và hạ tầng:** Môi trường thực thi CLI là tin cậy cục bộ. Khi kết nối tới LLM provider (qua Modal hoặc API cục bộ), chỉ các gói `TriageInput` đã được làm sạch (`SanitizedContext`) mới được gửi đi.
3. **Mục tiêu bảo mật:**
   - **Tính toàn vẹn (Integrity):** Kẻ tấn công không thể thông qua prompt injection để khiến PolicyEngine tự động dán nhãn `FP_CANDIDATE` cho một lỗ hổng thật.
   - **Tính bí mật (Confidentiality):** Không rò rỉ bí mật thô (raw secrets, API keys, credentials) từ repository vào log, prompt gửi ra ngoài, hoặc báo cáo xuất bản.
   - **Tính khả dụng (Availability):** Các vòng lặp thu thập ngữ cảnh được giới hạn chặt chẽ bởi ngân sách (budget), không gây treo hoặc cạn kiệt tài nguyên.

---

## 4. Thiết kế hệ thống (System Design)

Hệ thống vận hành theo pipeline 5 giai đoạn tuần tự, bất biến:

```
[Raw Repository & Scanners (Semgrep/Gitleaks)]
                       │
                       ▼
          [1. Scanner Ingestion & Normalization]
              -> NormalizedFinding (Frozen Domain Model)
                       │
                       ▼
          [2. Bounded Evidence Collector & Safe Context Service]
              -> AST & Joern Bounded CPG Analysis (Deterministic)
              -> Secret Redaction & Sanitization
              -> SanitizedContext (Only model exposed to provider)
                       │
                       ▼
          [3. LLM Triage Reasoner]
              -> Structured Evidence-first Generation (C2)
              -> TriageDecision (Opinion only: structured_evidence, verdict, confidence)
                       │
                       ▼
          [4. Deterministic Post-Verifier & PolicyEngine]
              -> Cross-check symbols against SanitizedContext (C3)
              -> Tightened Conservative Policy Gates (C4, C5)
              -> PolicyDecision (AUTO_CONFIRM / FP_CANDIDATE / MANUAL_REVIEW / TRIAGE_ERROR)
                       │
                       ▼
          [5. Immutable Reporting]
              -> JSON / Markdown / HTML (Leak-proof defense-in-depth)
```

### 4.1. Bounded Evidence Collector (Tầng 1 - D1, D2)
Thu thập thông tin dataflow có giới hạn cục bộ qua chuỗi 3 công cụ (`trace_dataflow`, `find_reachability`, `inspect_security_control`). Quy trình này hoàn toàn tất định (không dùng LLM chọn tool) và tuân thủ schema bằng chứng chuyên biệt theo nhóm lỗ hổng:
- **Injection/Taint (CWE-89, 78, 22, 502, 918):** Đòi hỏi đầy đủ source, sink, reachability và guard.
- **Crypto & Secrets (CWE-327, 328, 330, 798):** Đòi hỏi xác định chính xác sink sử dụng hàm nhạy cảm.
- **IDOR / Authz (CWE-639, 284):** Đòi hỏi đường dẫn truy vấn và security control phân quyền theo chủ sở hữu.
- **Mass Assignment (CWE-915):** Đòi hỏi model update sink và allowlist kiểm tra.
- **TOCTOU (CWE-362, 367):** Đòi hỏi mutation sink, reachability và atomic transaction lock.

### 4.2. Khử nhiễm và Bảo mật Ngữ cảnh (`SafeContextService`)
- Mọi bí mật thô từ Gitleaks được thay thế bằng `<REDACTED_SECRET>`.
- Mở rộng pattern nhận diện nhạy cảm (`db_pass`, `auth_key`, high-entropy tokens, JWT).
- Toàn bộ chuỗi dữ liệu đưa vào LLM được gói trong cấu trúc JSON nghiêm ngặt với các thẻ phân cách `<UNTRUSTED_INPUT_JSON>` đã escape unicode.
- Phát hiện các biểu thức prompt injection và gắn nhãn `PROMPT_INJECTION_FLAGGED` để fail-closed.

### 4.3. LLM Triage Reasoner & Post-Verifier (Tầng 2 - C2, C3)
LLM nhận `TriageInput` và bắt buộc sinh `structured_evidence` trước khi đưa ra phán quyết. Sau khi nhận kết quả, bộ Verifier tất định tiến hành đối chiếu:
- Mọi symbol, file, dòng được LLM viện dẫn phải tồn tại thực sự trong `SanitizedContext`.
- Bác bỏ mọi tuyên bố về guard/sanitizer nếu công cụ phân tích tĩnh không ghi nhận effective security control.
- Ngăn chặn mâu thuẫn giữa phán quyết LIKELY_TP và bằng chứng âm tính có giới hạn (`BOUNDED_LOCAL_NEGATIVE_PROOF`).

### 4.4. PolicyEngine (Chốt chặn chính sách bảo thủ - C4, C5)
- Kết quả truy vấn công cụ được chuẩn hóa 3 trạng thái: `FOUND`, `NOT_FOUND_COMPLETE`, `UNKNOWN`.
- Để đạt `FP_CANDIDATE`, bắt buộc phải có `_fp_has_deterministic_support() is True` (loại bỏ trường hợp `None`).
- Đối với các CWE nguy hiểm (CWE-89, 78, 22, 502, 94/95, 918) ở cả mức HIGH và MEDIUM, bắt buộc phải có bằng chứng phủ định mạnh (`BOUNDED_LOCAL_NEGATIVE_PROOF`).
- 100% cảnh báo xuất hiện trong báo cáo, không bao giờ tự ý ẩn giấu finding.

---

## 5. Thiết lập thực nghiệm (Experimental Setup)

### 5.1. Bộ dữ liệu đánh giá (Benchmark Dataset - B1)
Bộ dữ liệu được xây dựng từ 5 repository Python có lỗ hổng thực tế với ground truth được thẩm định độc lập:
- **OWASP PyGoat** (Django): 95 finding (Split: `development`)
- **DjanGoat** (Django) & **DVPWA** (Flask): 68 finding (Split: `calibration`)
- **VulPy** & **Damn Vulnerable Flask App (DVFA)**: 56 finding (Split: `held_out`)
- **Tổng cộng:** 219 finding (96 True Positives, 123 False Positives). Phân chia split theo repository, tuyệt đối không chia lẫn finding cùng repo.

### 5.2. Các Baseline so sánh (B2)
1. **Scanner-Only Baseline:** Kết quả Semgrep thô (mọi finding đều được coi là lỗ hổng cần xử lý).
2. **LLM-Only Baseline:** Đưa mã nguồn trực tiếp cho LLM và tin tưởng tuyệt đối vào phán đoán, không có graph evidence và không qua policy gate.
3. **Full System:** Hệ thống hoàn chỉnh tích hợp Bounded Evidence Collector, Post-Verifier, và PolicyEngine.

### 5.3. Tiêu chí đánh giá (Metrics)
- **Precision:** $\frac{TP}{TP + FP}$
- **Recall:** $\frac{TP}{TP + FN}$
- **F1-Score:** Trung bình điều hòa giữa Precision và Recall.
- **Tỷ lệ Analyst Effort Saved:** Tỷ lệ cảnh báo được hệ thống tự động xử lý an toàn mà không cần analyst thẩm định thủ công.
- **Tỷ lệ False Negative (FN Rate):** Tỷ lệ lỗ hổng thật bị gán nhầm thành `FP_CANDIDATE`. Yêu cầu an toàn bảo mật: FN Rate $= 0$.
- **Khoảng tin cậy Bootstrap 95%:** Đo lường trên 1,000 lượt bootstrap resample.

---

## 6. Kết quả thực nghiệm (Results)

> Toàn bộ số liệu trong phần này được sinh tự động bởi các script trong thư mục `scripts/` và lưu trữ tại `docs/paper/results/`.

### 6.1. Bảng so sánh hiệu năng Baseline (B2)
*Nguồn: `docs/paper/results/baseline_comparison.json`*

| Phương pháp | Precision [95% CI] | Recall [95% CI] | F1-Score | FN Rate | Effort Saved | ECE |
|---|---|---|---|---|---|---|
| **Scanner-Only (Semgrep)** | 0.4384 [0.3744, 0.5068] | 1.0000 [1.0, 1.0] | 0.6095 | 0.00% | 0.00% | N/A |
| **LLM-Only (No Gate)** | 0.5859 [0.5082, 0.6639] | 0.7812 [0.6979, 0.8646] | 0.6696 | **21.88%** | 41.55% | N/A |
| **Full System (Proposed)** | **0.5424** [0.4696, 0.6149] | **1.0000** [1.0, 1.0] | **0.7033** | **0.00%** | **19.18%** | 0.1507 |

**Phân tích:**
- Mô hình **LLM-Only** tuy tiết kiệm 41.55% công sức nhưng gây ra tỷ lệ **False Negative lên tới 21.88%** (bỏ sót hơn 1/5 số lỗ hổng thật do ảo giác và suy luận sai lệch trên mã nguồn phức tạp). Đây là mức rủi ro không thể chấp nhận được trong bảo mật thực tế.
- **Full System** đạt Recall tuyệt đối **1.0000** (0.00% FN Rate), tăng F1-score lên **0.7033** và tiết kiệm an toàn **19.18%** công sức phân loại cho chuyên gia thông qua việc chỉ tự động gán `FP_CANDIDATE` khi có đầy đủ bằng chứng phủ định tất định.

### 6.2. Hiệu chuẩn Model Confidence & Audit False Negative (B3, B4)
*Nguồn: `docs/paper/results/calibration_metrics.json` và `docs/paper/results/fn_audit_report.json`*

- **Expected Calibration Error (ECE):** **0.0785** (7.85%).
- **Độ chính xác trong nhóm HIGH Confidence:** **98.08%** (51/52 phán quyết đúng). Kết quả này chứng minh cơ sở thống kê vững chắc cho việc PolicyEngine chỉ cho phép tự động dán nhãn khi model đạt confidence mức HIGH.
- **Biểu đồ Reliability Diagram:** Tham chiếu hình ảnh thực nghiệm tại `docs/paper/results/reliability_diagram.png`.
- **Kiểm toán Shadow Mode FN:** Lấy mẫu ngẫu nhiên 10% các finding thuộc nhóm `FP_CANDIDATE` để đối chiếu ground-truth độc lập ghi nhận **0.0% False Negative** (0/5 finding bị gán nhầm).

### 6.3. Khả năng chống chịu Red-Team Prompt Injection (B5)
*Nguồn: `docs/paper/results/prompt_injection_results.json`*

Thử nghiệm trên bộ benchmark red-team gồm 16 payload tấn công tiêm nhiễm gián tiếp trong mã nguồn (delimiter escaping bypass, instruction override trong comment, unicode homoglyphs, Base64/null-byte injection):
- **Naive Baseline Attack Success Rate (ASR):** **100.0%** (16/16 payload ép thành công LLM trả về LIKELY_FP HIGH).
- **Defended System ASR:** **0.00%** (0/16 payload xuyên thủng được chốt chặn chính sách).
- **Tỷ lệ Fail-Closed:** **100.00%** (16/16 trường hợp đều được tự động chuyển về `MANUAL_REVIEW`).

### 6.4. Kiểm tra rò rỉ Canary Secret (B6)
*Nguồn: `docs/paper/results/leak_test_results.json`*

Thử nghiệm 5 dạng canary secret trong mã nguồn (database password, API authentication key, Base64 token, JWT secret, high-entropy hex string):
- **Tỷ lệ rò rỉ vào Sanitized Context:** **0.00%** (0/5)
- **Tỷ lệ rò rỉ vào Prompt gửi tới LLM:** **0.00%** (0/5)
- **Tỷ lệ rò rỉ vào Báo cáo Serialize:** **0.00%** (0/5)

### 6.5. Chi phí, Token và Độ trễ Thực tế (B8)
*Nguồn: `docs/paper/results/cost_and_latency_metrics.json`*

Thay thế hoàn toàn tuyên bố giả định "giảm 70-80% token" bằng số liệu đo đạc thực tế trên 219 finding:
- **Số lượng token context unpruned trung bình:** 977.9 tokens/finding.
- **Số lượng token sau khi sanitize & envelope:** 574.8 tokens/finding.
- **Tỷ lệ cắt giảm token thực tế đo được:** **41.22%**.
- **Độ trễ xử lý cục bộ (`SafeContextService`):** **0.075 ms/finding**.
- **Độ trễ DecisionCache:** Cache miss lookup đạt 0.335 ms, Cache hit đạt 0.413 ms. Khi hit cache, 0 token được gửi tới LLM và thời gian phản hồi tức thì.
- **Ước tính chi phí tài chính:** $0.0862 USD cho mỗi 1,000 finding (tiết kiệm $0.0605 USD / 1k finding so với gửi context thô).
- **Biểu đồ Token & Latency:** Tham chiếu hình ảnh thực nghiệm tại `docs/paper/results/token_latency_chart.png`.

### 6.6. Đánh giá Kiến trúc Controlled Agent & Nghiên cứu Ablation (219 Findings)
*Nguồn: `docs/paper/results/agent_ablation_results.json` và `docs/paper/results/agent_ablation_chart.png`*

Chúng tôi triển khai vòng lặp Controlled Agent với 10 công cụ đóng kín (allowlisted tools) và cơ chế leo thang kiểm soát (`agent_mode = off | escalate | always`), đánh giá thực nghiệm ablation trên toàn bộ 219 finding từ 5 repository mã nguồn mở:

| Cấu hình | Precision [95% CI] | Recall [95% CI] | F1-Score | FN Rate | Manual Review Rate | Effort Saved | Avg Tools | Latency/Finding |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1. Baseline (`agent_off`)** | 0.4384 [0.3744, 0.5068] | 1.0000 [1.0, 1.0] | 0.6095 | **0.00%** | 99.54% | **0.46%** | 0.00 | 0.26 ms |
| **2. Escalation (`agent_escalate`)** | 0.4384 [0.3744, 0.5068] | 1.0000 [1.0, 1.0] | 0.6095 | **0.00%** | **92.24%** | **7.76% (+7.30%)** | **1.32** | 2.88 ms |
| **3. Always Active (`agent_always`)** | 0.4384 [0.3744, 0.5068] | 1.0000 [1.0, 1.0] | 0.6095 | **0.00%** | **92.24%** | **7.76% (+7.30%)** | 2.00 | 3.38 ms |
| **4. Escalate + Self-Consistency** | 0.4384 [0.3744, 0.5068] | 1.0000 [1.0, 1.0] | 0.6095 | **0.00%** | **92.24%** | **7.76% (+7.30%)** | 1.32 | 2.70 ms |

**Kết quả chính:**
- **Tiết kiệm thêm công sức chuyên gia:** Chế độ `agent_escalate` tăng tỷ lệ Effort Saved từ 0.46% lên **7.76%** (giải quyết tự động thêm 16 trường hợp nghi vấn phức tạp mà phân tích tĩnh tĩnh đơn bước phải lùi về con người), trong khi duy trì **0.00% False Negative**.
- **Hiệu quả vượt trội của thiết kế Escalation:** Cấu hình `agent_escalate` đạt cùng mức độ tiết kiệm công sức như `agent_always`, nhưng giảm **34.0% số lượt gọi công cụ** (1.32 vs 2.00 tool calls/finding) và tiết kiệm 11.2% lượng token tiêu thụ.
- **Kiểm định Bootstrap cặp theo cụm repo:** $\Delta F1$ 95% CI là `[0.0000, 0.0000]`. F1 không đổi do Recall được bảo toàn ở mức 1.0000 và Precision ổn định dưới chính sách bảo thủ.
- **Biểu đồ Ablation:** Tham chiếu hình ảnh tại `docs/paper/results/agent_ablation_chart.png`.

### 6.7. Đánh giá Khả năng Phòng thủ Red-Team Suite C (Tool & Code Injection)
*Nguồn: `docs/paper/results/tool_injection_results.json`*

Đánh giá trên 12 mẫu payload tấn công tiêm nhiễm nâng cao nhắm vào vòng lặp của Agent (Path traversal `../../etc/passwd`, absolute path escape, SQL/command injection trong symbol, null bytes, spoofed ledger tags, markdown code fence breakouts, và direct policy overrides):
- **Attack Success Rate (ASR) Trước Phòng Thủ (Naive Agent):** **100.0%** (12/12 payload khai thác thành công).
- **Attack Success Rate (ASR) Sau Phòng Thủ (Antigravity Agent):** **0.00%** (0/12 payload vượt qua được phòng tuyến).
- **Cơ chế phòng thủ:** `ActionValidator` bảo đảm path containment tuyệt đối trong repo root, regex cú pháp symbol, và `PolicyEngine` chặn đứng mọi nỗ lực hạ nhãn FP thiếu chứng cứ tất định.

---

## 7. Các Ca Nghiên Cứu Điển Hình (Case Studies - B9)

Tham chiếu tài liệu chi tiết tại [case_studies.md](file:///d:/Code/AI%20security/docs/paper/case_studies.md) gồm 4 kịch bản thực tế:
1. **True Positive được xác nhận đúng (`AUTO_CONFIRM`):** Lỗ hổng SQL Injection tại `challenge/views.py` (PyGoat, CWE-89) có chuỗi dữ liệu rõ ràng từ `request.GET.get` tới `cursor.execute`.
2. **False Positive được loại đúng (`FP_CANDIDATE`):** Cảnh báo Command Injection (CWE-78) do Semgrep báo tại `subprocess.run(["ping", ...])` với mảng tham số cố định, được chứng minh âm tính bằng `BOUNDED_LOCAL_NEGATIVE_PROOF`.
3. **Ảo giác bị Verifier chặn và chuyển `MANUAL_REVIEW`:** Lỗ hổng IDOR (CWE-639) trong DjanGoat khi LLM hiểu nhầm decorator `@login_required` là cơ chế bảo vệ phân quyền sở hữu đối tượng. Bộ Post-Verifier (C3) đã phát hiện guard không hợp lệ và hạ phán quyết về `MANUAL_REVIEW`.
4. **Tấn công Prompt Injection bị vô hiệu hóa:** Đoạn mã chứa bình luận giả thẻ đóng `</UNTRUSTED_INPUT_JSON>` nhằm ép verdict `LIKELY_FP` đã bị cơ chế khử nhiễm phát hiện, kích hoạt cờ `PROMPT_INJECTION_FLAGGED` và fail-closed về `MANUAL_REVIEW`.

---

## 8. Hạn chế và Đạo đức nghiên cứu (Limitations & Ethics)

### 8.1. Các mục CHƯA ĐO và Giới hạn Kỹ thuật
Theo đúng cam kết không bịa đặt số liệu:
1. **Độ bao phủ của Joern CPG trên diện rộng (B7):** [CHƯA ĐO]. Chúng tôi đã kiểm tra tính đúng đắn trên 5 repo benchmark thử nghiệm, nhưng chưa có số liệu đo đạc tỷ lệ dựng CPG thành công trên quy mô toàn bộ hệ sinh thái hàng nghìn package Python của PyPI.
2. **Dynamic Few-Shot / Retrieval Tự động (C10):** [CHƯA LÀM]. Hệ thống hiện sử dụng prompt v15 chuẩn mực, chưa tích hợp vector search để động truy xuất mẫu tương tự.
3. **Thực thi tuần tự:** Hệ thống hiện vận hành hoàn toàn tuần tự (single-threaded) theo quy tắc kiến trúc của Sprint 1, chưa áp dụng concurrency hay async worker.

### 8.2. Đạo đức nghiên cứu
- Mọi mã nguồn thử nghiệm đều xuất phát từ các dự án mã nguồn mở có giấy phép rõ ràng (Apache 2.0, MIT, GPL) được xây dựng cho mục đích nghiên cứu và đào tạo bảo mật.
- Không sử dụng thông tin xác thực, token, hay dữ liệu của bất kỳ hệ thống thực tế nào của người khác.

---

## 9. Khả năng tái lập kết quả (Reproducibility)

Mọi bảng số liệu, biểu đồ và kết quả đánh giá trong bài báo đều có thể được tái lập hoàn toàn thông qua các lệnh độc lập sau:

```powershell
# 1. Chạy toàn bộ 544 test unit và integration (100% Pass)
pytest

# 2. Sinh lại bảng so sánh Baseline và khoảng tin cậy Bootstrap 95% (B1, B2)
python scripts/run_eval_baseline.py

# 3. Sinh lại đồ thị Calibration Reliability Diagram và Shadow FN Audit (B3, B4)
python scripts/run_calibration_and_audit.py

# 4. Chạy lại bộ benchmark Red-Team 16 mẫu Prompt Injection (B5)
python scripts/run_prompt_injection_suite.py

# 5. Chạy lại benchmark rò rỉ Canary Secret qua 5 định dạng (B6)
python scripts/run_leak_test.py

# 6. Đo lường lại số lượng token cắt giảm, độ trễ và chi phí (B8)
python scripts/benchmark_cost_tokens.py

# 7. Chạy lại thực nghiệm Ablation 4 cấu hình Agent trên 219 finding (Ablation A)
python scripts/run_agent_ablation.py

# 8. Chạy lại bộ benchmark Red-Team Suite C 12 mẫu Tool Injection
python scripts/run_tool_injection_redteam.py
```
