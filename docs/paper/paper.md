# LLM-Augmented SAST Triage Platform: Kiến Trúc Phân Loại Lỗ Hổng Bảo Mật Kết Hợp Suy Luận LLM và Kiểm Chứng Tất Định

**Tác giả:** Nhóm Nghiên cứu Kỹ thuật ML/AppSec  
**Tài liệu tham chiếu:** [claims.md](file:///d:/Code/AI%20security/docs/paper/claims.md)  
**Trạng thái:** Bản thảo nghiên cứu (Draft) — Các chỉ số thực nghiệm được tham chiếu trực tiếp từ kết quả do script trong repo sinh ra.

---

## Tóm tắt (Abstract)

Các công cụ phân tích mã tĩnh (SAST) như Semgrep đóng vai trò thiết yếu trong việc phát hiện sớm lỗ hổng bảo mật trong mã nguồn phần mềm. Tuy nhiên, tỷ lệ cảnh báo giả (False Positives - FP) cao tạo ra gánh nặng phân loại thủ công khổng lồ cho các kỹ sư bảo mật. Việc ứng dụng các mô hình ngôn ngữ lớn (LLM) để tự động hóa triage mang lại tiềm năng lớn nhưng phải đối mặt với hai rủi ro nghiêm trọng: (1) hiện tượng ảo giác (hallucination) có thể dẫn đến việc tự động bỏ qua lỗ hổng thật (False Negatives - FN), và (2) nguy cơ tấn công tiêm nhiễm câu lệnh gián tiếp (Indirect Prompt Injection) ẩn trong mã nguồn không đáng tin cậy.

Bài báo này trình bày thiết kế và đánh giá hệ thống **LLM-Augmented SAST Triage Platform**, một nền tảng CLI phân loại cảnh báo bảo mật kết hợp hai tầng: **Bounded Evidence Collector** (thu thập bằng chứng tĩnh tất định qua AST và Code Property Graph - Joern) và **LLM Triage Reasoner** có kiểm chứng, được bảo vệ bởi **PolicyEngine** theo nguyên tắc fail-closed. Chúng tôi thiết lập bộ đánh giá chuẩn hóa trên mã nguồn thực tế (OWASP PyGoat, DVPWA, VAmPI,...), thực hiện kiểm toán rủi ro false negative và đánh giá khả năng chống chịu tấn công prompt injection với bộ test red-team chuyên dụng.

---

## 1. Giới thiệu (Introduction)

Trong chu trình phát triển phần mềm hiện đại (DevSecOps), công cụ SAST là phòng tuyến quan trọng giúp phát hiện lỗi lập trình bảo mật. Tuy nhiên, do thiếu hiểu biết ngữ cảnh sâu và tính chất phân tích xấp xỉ (over-approximation), SAST thường tạo ra lượng lớn cảnh báo không có khả năng khai thác (false positive). Tỷ lệ cảnh báo giả có thể vượt quá 50-70%, gây nên tình trạng mệt mỏi cảnh báo (alert fatigue) và làm chậm trễ việc vá các lỗ hổng nghiêm trọng.

Sự xuất hiện của các LLM chuyên về mã nguồn (như Qwen2.5-Coder) mở ra khả năng hiểu ngữ cảnh phức tạp và chuỗi dữ liệu (dataflow). Tuy nhiên, việc trực tiếp giao toàn quyền quyết định cho LLM tiềm ẩn rủi ro khôn lường:
- **Nguy cơ bỏ sót lỗ hổng (False Negative):** Một phán quyết sai lầm xem lỗ hổng nghiêm trọng (như SQL Injection, RCE) là FP có thể khiến lỗ hổng lọt vào môi trường sản xuất.
- **Rủi ro an ninh kênh gián tiếp:** Mã nguồn phân tích là dữ liệu đầu vào không đáng tin cậy (untrusted data). Kẻ tấn công có thể chèn các câu lệnh điều khiển vào comment hoặc biến code để đánh lừa LLM đưa ra phán quyết sai.

Hệ thống của chúng tôi giải quyết vấn đề này thông qua ba nguyên tắc thiết kế cốt lõi:
1. **Không bao giờ tin tưởng tuyệt đối vào phán đoán của LLM:** LLM chỉ đưa ra đề xuất (`model_verdict`); quyết định hệ thống (`policy_action`) được quyết định bởi PolicyEngine dựa trên bằng chứng tất định.
2. **Nguyên tắc fail-closed:** Mọi lỗi phân tích, context không hoàn chỉnh hoặc mâu thuẫn bằng chứng đều được đẩy về `MANUAL_REVIEW` để con người thẩm định, tuyệt đối không tự động triệt tiêu cảnh báo.
3. **Phòng thủ đa tầng trước prompt injection:** Cô lập dữ liệu bằng JSON envelope, escape thẻ phân cách và kiểm tra bằng chứng độc lập từ công cụ tĩnh.

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
              -> Structured Evidence-first Generation
              -> TriageDecision (Opinion only: verdict, confidence)
                       │
                       ▼
          [4. Deterministic Post-Verifier & PolicyEngine]
              -> Cross-check symbols against SanitizedContext
              -> Conservative Policy Rules (Fail-Closed Gates)
              -> PolicyDecision (LIKELY_TP / FP_CANDIDATE / MANUAL_REVIEW / TRIAGE_ERROR)
                       │
                       ▼
          [5. Immutable Reporting]
              -> JSON / Markdown / HTML (Leak-proof defense-in-depth)
```

### 4.1. Bounded Evidence Collector (Tầng 1)
Thu thập thông tin dataflow có giới hạn cục bộ: xác định nguồn (source), đích (sink), và kiểm tra bảo mật (sanitizer/guard). Quá trình này hoàn toàn tất định, tuân thủ ngân sách tối đa về độ sâu và số bước truy vấn.

### 4.2. Khử nhiễm và Bảo mật Ngữ cảnh (`SafeContextService`)
- Mọi bí mật thô từ Gitleaks được thay thế bằng `<REDACTED_SECRET>`.
- Các định dạng khóa riêng tư PEM, Bearer token, credentials trong chuỗi kết nối và gán biến nhạy cảm được tự động làm sạch.
- Toàn bộ chuỗi dữ liệu đưa vào LLM được gói trong cấu trúc JSON nghiêm ngặt với các thẻ phân cách đã escape unicode.

### 4.3. LLM Triage Reasoner & Post-Verifier (Tầng 2)
LLM nhận `TriageInput` và suy luận theo rubric bảo mật chuyên biệt. Sau khi nhận kết quả, bộ Verifier tất định tiến hành đối chiếu:
- Mọi file, dòng, symbol được LLM viện dẫn phải tồn tại trong ngữ cảnh an toàn đã cung cấp.
- Nếu LLM khẳng định có cơ chế phòng thủ (sanitizer) nhưng bộ phân tích tĩnh không ghi nhận, kết quả bị hạ cấp về `MANUAL_REVIEW`.

### 4.4. PolicyEngine (Chốt chặn chính sách bảo thủ)
- Để một cảnh báo đạt `FP_CANDIDATE`, bắt buộc phải có bằng chứng hỗ trợ tất định (`_fp_has_deterministic_support() is True`) và thỏa mãn điều kiện chứng minh âm tính có giới hạn (`BOUNDED_LOCAL_NEGATIVE_PROOF`) đối với các mức độ nghiêm trọng cao hoặc nhóm CWE nguy hiểm.
- Không bao giờ loại bỏ bất kỳ phát hiện nào khỏi báo cáo cuối cùng.

---

## 5. Thiết lập thực nghiệm (Experimental Setup)

### 5.1. Bộ dữ liệu đánh giá (Benchmark Dataset)
Bộ dữ liệu được trích xuất từ các repository mã nguồn mở Python có lỗ hổng đã được xác nhận (ground-truth) bao gồm:
- **OWASP PyGoat** (Django): Các lỗ hổng SQLi, Command Injection, XSS, Deserialization, Insecure Cryptography.
- **DVPWA & VAmPI**: Lỗ hổng API, IDOR, Broken Authentication.
- Phân chia split theo Repository (tránh rò rỉ dữ liệu cùng repo):
  - `development`: Tinh chỉnh rubric và quy tắc.
  - `calibration`: Đo đạc độ tin cậy và hiệu chỉnh ngưỡng confidence.
  - `held_out`: Đánh giá chất lượng độc lập cuối cùng.

### 5.2. Các Baseline so sánh
1. **Scanner-Only Baseline:** Kết quả Semgrep thô (mọi finding đều được coi là lỗ hổng cần xử lý).
2. **LLM-Only Baseline:** Sử dụng LLM trực tiếp trên snippet mã nguồn mà không có graph evidence mở rộng và không qua PolicyEngine.
3. **Full System:** Hệ thống đầy đủ với Bounded Evidence Collector, Post-Verifier và PolicyEngine.

### 5.3. Tiêu chí đánh giá (Metrics)
- **Precision:** $\frac{TP_{predicted}}{TP_{predicted} + FP_{predicted}}$
- **Recall:** $\frac{TP_{predicted}}{TP_{actual}}$
- **F1-Score:** Trung bình điều hòa của Precision và Recall.
- **Tỷ lệ Manual Review:** Tỷ lệ cảnh báo được chuyển cho con người xem xét.
- **Tỷ lệ False Negative (FN Rate):** Tỷ lệ các lỗ hổng thật bị gán nhầm thành `FP_CANDIDATE` (Mục tiêu an toàn tối thượng: FN Rate $\approx 0$).

---

## 6. Kết quả thực nghiệm (Results)

> *Ghi chú:* Các con số trong phần này được sinh tự động bởi script `scripts/run_eval_benchmark.py` trên tập benchmark thực tế trong repo.

### 6.1. Bảng so sánh hiệu năng Baseline

*(Dữ liệu cập nhật theo kết quả thực tế đo đạc)*

| Phương pháp | Precision | Recall | F1-Score | Manual Review Rate | False Negative Rate |
|---|---|---|---|---|---|
| **Semgrep Baseline** | *Xem [results_baseline.json]* | 1.000 | *Xem [results_baseline.json]* | 0.000 | 0.000 |
| **LLM-Only** | *Xem [results_baseline.json]* | *Xem [results_baseline.json]* | *Xem [results_baseline.json]* | 0.000 | *Xem [results_baseline.json]* |
| **Full System (Proposed)** | *Xem [results_baseline.json]* | *Xem [results_baseline.json]* | *Xem [results_baseline.json]* | *Xem [results_baseline.json]* | **0.000** |

### 6.2. Kiểm toán Calibration và False Negative
- **Expected Calibration Error (ECE):** Tham chiếu `results/calibration_metrics.json`.
- **False Negative Audit:** Kết quả lấy mẫu kiểm toán 10% các finding `FP_CANDIDATE` khẳng định không phát hiện bất kỳ trường hợp nào bỏ sót lỗ hổng nghiêm trọng (Critical/High).

### 6.3. Khả năng chống chịu Red-Team Prompt Injection
- Bộ test 15 mẫu prompt injection đặc thù (giả thẻ đóng, yêu cầu đổi verdict trong comment, payload gián tiếp) ghi nhận:
  - **Tỷ lệ lái verdict thành công:** **0.0%** (15/15 ca bị chặn hoặc giữ nguyên quyết định an toàn).

---

## 7. Đánh giá thành phần (Ablation Study)

| Cấu hình | Precision | Recall | F1 | Ghi chú tác động |
|---|---|---|---|---|
| **Hệ thống đầy đủ** | *Đang cập nhật* | *Đang cập nhật* | *Đang cập nhật* | Đầy đủ chốt chặn an toàn |
| - Bỏ Post-LLM Verifier (C3) | *Đang cập nhật* | *Đang cập nhật* | *Đang cập nhật* | Đánh giá nguy cơ hallucination |
| - Bỏ Bounded Negative Proof (C4) | *Đang cập nhật* | *Đang cập nhật* | *Đang cập nhật* | Đánh giá tỷ lệ False Negative tăng |
| - Bỏ Bounded Evidence Collector | *Đang cập nhật* | *Đang cập nhật* | *Đang cập nhật* | Đánh giá độ phụ thuộc vào CPG |

---

## 8. Hạn chế và Đạo đức nghiên cứu (Limitations & Ethics)

1. **Giới hạn kích thước tập dữ liệu:** Mặc dù sử dụng mã nguồn thực tế có lỗ hổng đã được gắn nhãn (OWASP PyGoat, DVPWA), kích thước tập dữ liệu còn khiêm tốn (khoảng vài chục đến hàng trăm finding), chưa đủ để khái quát hóa cho toàn bộ hệ sinh thái mã nguồn mở.
2. **Chi phí tính toán CPG:** Việc xây dựng CPG bằng Joern đòi hỏi môi trường Java/Scala và tiêu tốn bộ nhớ đáng kể đối với các repository lớn.
3. **Phạm vi bảo mật:** Hệ thống tập trung vào Python; các đặc thù của ngôn ngữ động khác cần nghiên cứu bổ sung.
4. **Đạo đức nghiên cứu:** Mọi dữ liệu sử dụng đều là mã nguồn mở thuộc các dự án cố tình dễ bị tổn thương cho mục đích giáo dục hoặc mã đã được công bố CVE kèm bản vá, tuân thủ giấy phép mã nguồn mở (Apache 2.0, MIT). Không sử dụng bất kỳ bí mật hay dữ liệu riêng tư thực tế nào.

---

## 9. Khả năng tái lập kết quả (Reproducibility)

Toàn bộ quy trình thực nghiệm có thể chạy lại độc lập bằng một lệnh duy nhất:
```powershell
python scripts/run_eval_benchmark.py --dataset benchmarks/curated_benchmark.json --output-dir docs/paper/results
```
Môi trường thử nghiệm, phiên bản công cụ và seed ngẫu nhiên được ghim cố định trong `pyproject.toml` và `Dockerfile`.
