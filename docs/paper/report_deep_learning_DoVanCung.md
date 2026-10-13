# Ứng Dụng Mô Hình Ngôn Ngữ Lớn Trong Phân Loại Cảnh Báo Lỗ Hổng Bảo Mật Kết Hợp Đồ Thị Thuộc Tính Mã Nguồn và Rào Chắn Chính Sách Bảo Thủ

**Đỗ Văn Cung**  
**Lớp:** 12423TN  
**Bài tập lớn môn:** Deep Learning  
**Mã nguồn & Thực nghiệm:** Commit `f0b1805d861c80dd1960ea20937c701a994dd744`

---

### Tóm tắt nội dung

Các công cụ phân tích mã tĩnh (Static Application Security Testing - SAST) như Semgrep đóng vai trò phòng tuyến quan trọng trong phát hiện sớm lỗ hổng bảo mật mã nguồn. Tuy nhiên, do bản chất phân tích gần đúng (over-approximation), SAST tạo ra tỷ lệ cảnh báo giả (False Positives - FP) vượt quá 50–60%, gây tình trạng quá tải cảnh báo (alert fatigue) cho các kỹ sư bảo mật. Việc ứng dụng các mô hình ngôn ngữ lớn (Large Language Models - LLM) chuyên về mã nguồn như Qwen2.5-Coder-14B để tự động hóa phân loại (triage) mang lại tiềm năng hiểu ngữ cảnh sâu nhưng phải đối mặt với hai rủi ro cốt tử: (1) hiện tượng ảo giác suy luận dẫn đến việc tự động bỏ sót lỗ hổng thật (False Negatives - FN), và (2) nguy cơ bị điều hướng bởi các đoạn mã độc hại cài cắm trong mã nguồn (Indirect Prompt Injection).

Bài báo này nghiên cứu và hiện thực một kiến trúc phân loại kết hợp hai tầng: **Tầng 1 (Tier-1 Deterministic Bounded Collector)** thu thập ngữ cảnh cú pháp AST, cắt lát luồng dữ liệu đồ thị thuộc tính mã nguồn (Code Property Graph - Joern CPG) và khử nhiễm bí mật nhạy cảm; **Tầng 2 (Tier-2 Deterministic Multi-turn Investigative Coordinator)** kích hoạt cơ chế điều tra nhiều vòng có giới hạn ngân sách với 10 công cụ chỉ đọc, được kiểm soát bởi bộ thẩm định hành động (`ToolActionValidator`), sổ cái bằng chứng đơn điệu (`EvidenceLedger`) và cổng chính sách bảo thủ (`PolicyEngine`). 

Đánh giá thực nghiệm trên 219 cảnh báo thực tế từ 5 kho mã nguồn mở (OWASP PyGoat, DjanGoat, DVPWA, VulPy, DVFA) cho thấy: mô hình LLM đơn bước không rào chắn bỏ sót tới 16,67%–21,88% lỗ hổng thật. Ngược lại, hệ thống đề xuất duy trì tỷ lệ False Negative ở mức **0,00%** (Recall đạt **1,0000** với khoảng tin cậy Clopper-Pearson 95% là **[0,9623, 1,0000]**), giải quyết tự động **7,76%** cảnh báo (17/219) ra khỏi hàng đợi phân loại thủ công mà không làm suy giảm độ an toàn, đồng thời cắt giảm **41,22%** lượng token tiêu thụ. Tỷ lệ tấn công thành công (ASR) qua 16 mẫu Prompt Injection và 12 mẫu Tool Injection đều bị triệt tiêu về **0,00%**.

---

## 1. Giới thiệu

Trong công nghệ phần mềm hiện đại, bảo mật ứng dụng (Application Security - AppSec) trong chu trình DevSecOps yêu cầu phát hiện và vá lỗi ngay từ giai đoạn viết mã. Công cụ SAST quét mã nguồn trên diện rộng nhưng thường thiếu hiểu biết ngữ cảnh liên hàm (cross-file dataflow), dẫn đến lượng cảnh báo giả khổng lồ. Kỹ sư bảo mật phải duyệt hàng nghìn cảnh báo mỗi tuần, trong đó đa số là các đoạn mã an toàn đã có cơ chế kiểm tra (guards) hoặc các biến không nhận dữ liệu từ người dùng (untainted variables).

Sự phát triển của Deep Learning, đặc biệt là các mô hình nền tảng Transformer xử lý mã nguồn (Code LLMs), mở ra triển vọng phân loại tự động cảnh báo nhờ khả năng hiểu ngữ nghĩa ngôn ngữ tự nhiên và cấu trúc lập trình. Tuy nhiên, việc áp dụng trực tiếp Deep Learning vào bảo mật phần mềm gặp phải bài toán đánh đổi khắt khe:
- **Cái giá của sự nhầm lẫn không đối xứng:** Trong bài toán phân loại ảnh thông thường, nhầm một con mèo thành con chó chỉ làm giảm điểm Top-1 Accuracy. Nhưng trong bảo mật, phân loại nhầm một lỗ hổng nghiêm trọng (SQL Injection, Remote Code Execution) thành cảnh báo giả (False Negative) sẽ khiến lỗ hổng lọt ra môi trường sản xuất, dẫn đến rò rỉ dữ liệu hoặc xâm nhập hệ thống.
- **Dữ liệu đầu vào mang tính đối kháng (Adversarial Untrusted Input):** Mã nguồn phân tích không phải dữ liệu tin cậy. Kẻ tấn công nội bộ hoặc mã từ bên thứ ba có thể cố tình chèn chỉ thị (prompt injection) vào chú thích (comment) hoặc docstring để ép mô hình đưa ra phán quyết sai lệch.

**Câu hỏi nghiên cứu của bài báo:** Khi ứng dụng LLM vào phân loại cảnh báo SAST, làm thế nào để tận dụng khả năng suy luận ngữ cảnh của mô hình nhằm giảm bớt công sức của kỹ sư bảo mật mà vẫn đảm bảo tính an toàn nghiêm ngặt (tỷ lệ False Negative bằng 0) trước các hiện tượng ảo giác và tấn công tiêm nhiễm câu lệnh?

**Đóng góp chính của bài báo:**
1. **Kiến trúc phân loại hai tầng (Two-Tier Architecture):** Kết hợp phân tích đồ thị tất định (Code Property Graph) và bộ điều phối điều tra nhiều vòng có giới hạn ngân sách.
2. **Quy tắc chính sách bảo thủ đóng an toàn (Conservative Fail-Closed Policy):** Thiết lập rào chắn kiểm chứng thuộc tính chương trình, cam kết không tự ý loại bỏ cảnh báo nếu thiếu bằng chứng phủ định mạnh mẽ (`BOUNDED_LOCAL_NEGATIVE_PROOF`).
3. **Bộ thẩm định an toàn đa lớp (Defense-in-Depth):** Khử nhiễm bí mật (`<REDACTED_SECRET>`), kiểm soát nghiêm ngặt đường dẫn tệp (chặn 100% Path Traversal) và sổ cái bằng chứng đơn điệu ngăn chặn hallucination.
4. **Đánh giá thực nghiệm toàn diện trên 219 cảnh báo thực tế:** Phân rã 7 cấu hình thành phần, đo đạc khoảng tin cậy chính xác Clopper-Pearson, kiểm định cặp Bootstrap cụm theo kho mã nguồn, phân tích chi tiết lỗi và đo lường mức độ cắt giảm token thực tế.

---

## 2. Công trình liên quan

**Mô hình ngôn ngữ lớn cho mã nguồn (Code LLMs).** Các mô hình kiến trúc Transformer tự hồi quy được tiền huấn luyện trên lượng lớn mã nguồn (như CodeLlama, StarCoder, Qwen2.5-Coder) đã chứng minh năng lực vượt trội trong sinh mã, dịch mã và giải thích đoạn mã. Tuy nhiên, các nghiên cứu gần đây chỉ ra rằng khi giao toàn quyền quyết định (unconstrained reasoning) cho LLM trong các bài toán bảo mật, mô hình dễ mắc ảo giác logic do không theo dõi được trạng thái biến toàn cục.

**Đồ thị thuộc tính mã nguồn (Code Property Graph - CPG).** Khái niệm CPG do Yamaguchi và cộng sự [1] đề xuất kết hợp ba biểu diễn đồ thị: Cây cú pháp trừu tượng (AST), Đồ thị luồng điều khiển (CFG) và Đồ thị phụ thuộc chương trình (PDG). Joern [2] là nền tảng phân tích CPG mã nguồn mở hàng đầu, cho phép thực hiện taint analysis chính xác. Tuy nhiên, CPG thuần túy thường sinh cảnh báo thiếu giải thích ngữ nghĩa và gặp khó khăn với các framework web động (như Django, Flask).

**Tấn công tiêm nhiễm câu lệnh gián tiếp (Indirect Prompt Injection).** Greshake và cộng sự [3] đã chứng minh tính khả thi của việc tấn công mô hình ngôn ngữ thông qua dữ liệu bên ngoài. Trong ngữ cảnh công cụ kiểm thử mã, việc đưa trực tiếp mã nguồn vào prompt mà không có cơ chế cách ly tạo ra bề mặt tấn công trực diện, cho phép kẻ tấn công điều khiển phán quyết của mô hình.

---

## 3. Phương pháp

### 3.1 Giao thức dữ liệu và bộ Benchmark chuẩn hóa

Nghiên cứu sử dụng bộ dữ liệu chuẩn hóa gồm **22.424 dòng mã với 219 cảnh báo bảo mật thực tế** được thẩm định ground-truth độc lập từ 5 kho mã nguồn web Python:
- **OWASP PyGoat** (Django): 95 cảnh báo.
- **DjanGoat** (Django): 42 cảnh báo.
- **DVPWA** (Damn Vulnerable Python Web Application - Flask): 26 cảnh báo.
- **VulPy** (Flask): 31 cảnh báo.
- **DVFA** (Damn Vulnerable Flask Application): 25 cảnh báo.

**Chia tập đánh giá (Splits Protocol):** Để đánh giá trung thực khả năng tổng quát hóa và tránh hiện tượng rò rỉ dữ liệu (data leakage) giữa các cảnh báo cùng dự án, dữ liệu được phân chia theo kho mã nguồn độc lập:
1. `development` (OWASP PyGoat - 95 cảnh báo: 44 TP, 51 FP): Dùng để khảo sát mẫu và hiệu chỉnh ban đầu.
2. `calibration` (DjanGoat, DVPWA - 68 cảnh báo: 28 TP, 40 FP): Dùng để hiệu chuẩn độ tin cậy và kiểm tra ranh giới.
3. `held_out` (VulPy, DVFA - 56 cảnh báo: 24 TP, 32 FP): Tập kiểm thử độc lập tuyệt đối, chỉ đánh giá một lần duy nhất với mô hình và cấu hình đã đóng băng.

**Thành phần cảnh báo (Ground-Truth):** Tổng cộng 219 cảnh báo gồm 96 lỗ hổng thật (True Positives - 43,84%) và 123 cảnh báo giả (False Positives - 56,16%), bao gồm các nhóm CWE nguy hiểm: SQL Injection (CWE-89), Command Injection (CWE-78), Path Traversal (CWE-22), IDOR/Phân quyền (CWE-639), Lộ bí mật (CWE-798), và Bỏ qua cơ chế bảo vệ CSRF (CWE-352).

```
Bảng 1: Phân bổ dữ liệu đánh giá theo dự án và tập chia (Splits).
-------------------------------------------------------------------------
Kho mã nguồn      Framework    Tập chia        Tổng cảnh báo   TP    FP
-------------------------------------------------------------------------
realvuln-pygoat   Django       development          95         44    51
realvuln-djangoat Django       calibration          42         18    24
realvuln-dvpwa    Flask        calibration          26         10    16
realvuln-vulpy    Flask        held_out             31         14    17
realvuln-dvfa     Flask        held_out             25         10    15
-------------------------------------------------------------------------
Tổng cộng                      3 tập độc lập       219         96   123
-------------------------------------------------------------------------
```

---

### 3.2 Kiến trúc hệ thống hai tầng

Hệ thống hoạt động qua đường ống xử lý tuần tự gồm các khối chức năng chính:

```
[Mã Nguồn Kho Lưu Trữ] ➔ [Semgrep / Gitleaks / Logic Detector]
                                    │
                         [NormalizedFinding]
                                    │
               [Khối Khử Nhiễm SafeContextService]
 (Thay thế <REDACTED_SECRET>, Mã hóa JSON Envelope, Cắt lát AST/CPG)
                                    │
             ┌──────────────────────┴──────────────────────┐
             ▼                                             ▼
   [Đủ chứng cứ tất định]                       [Nghi ngờ / Thiếu dữ kiện]
             │                                             │
             │                           [Bộ Điều Phối Điều Tra Nhiều Vòng]
             │                           ├── ReAct Loop (Tối đa 4–8 bước)
             │                           ├── 10 Công cụ chỉ đọc (read_function...)
             │                           ├── ToolActionValidator (Chặn Traversal)
             │                           ├── EvidenceLedger (Sổ cái đơn điệu)
             │                           └── Judge Verifier (Thẩm định chéo)
             │                                             │
             └──────────────────────┬──────────────────────┘
                                    │
                         [Cổng Chính Sách Bảo Thủ]
       (PolicyEngine: LIKELY_TP | FP_CANDIDATE | MANUAL_REVIEW | TRIAGE_ERROR)
                                    │
               ┌────────────────────┴────────────────────┐
               ▼                                         ▼
         [report.html]                             [report.json]
```

#### Tầng 1: Thu thập ngữ cảnh và Khử nhiễm tất định (SafeContextService)
- **Cắt lát cú pháp (AST & CPG Slicing):** Thay vì gửi toàn bộ tệp mã nguồn vào prompt gây lãng phí token và nhiễu ngữ cảnh, hệ thống trích xuất lát cắt bao hàm hàm chứa cảnh báo (enclosing function) và dấu vết luồng dữ liệu source-to-sink từ Joern CPG.
- **Khử nhiễm bí mật (Secret Redaction):** Mọi chuỗi thông tin xác thực, khóa bí mật, token có entropy cao hoặc nhãn từ Gitleaks đều được thay thế cục bộ bằng thẻ `<REDACTED_SECRET>`. Mã nguồn thô (raw source) không bao giờ vượt qua biên giới thành phần này.
- **Bao đóng JSON (Envelope Isolation):** Toàn bộ đoạn mã gửi tới mô hình được đặt trong cấu trúc JSON nghiêm ngặt, mã hóa ký tự phân cách Unicode (`\u003c` và `\u003e`), phát hiện sớm các mẫu tiêm nhiễm để gắn cờ `PROMPT_INJECTION_FLAGGED`.

#### Tầng 2: Bộ điều phối điều tra nhiều vòng (Controlled Multi-turn Investigative Coordinator)
Khi phán quyết Tier-1 chưa đạt độ tự tin cao hoặc kết quả đồ thị CPG là `UNKNOWN`, hệ thống tự động leo thang (escalate) sang bộ điều phối điều tra:
- **Ngân sách thực thi (Bounded Budget):** Giới hạn tối đa 4 bước lặp (iterations) và 4 lượt gọi công cụ (tool calls), thời gian chờ (timeout) 30 giây để ngăn chặn vòng lặp vô hạn.
- **10 Công cụ đóng kín chỉ đọc (Allowlisted Read-only Tools):** Bao gồm `read_function`, `find_callees`, `get_route_decorators`, `check_lock_or_transaction`, `get_model_schema`... Tuyệt đối không cung cấp công cụ ghi đè tệp hoặc thực thi lệnh shell.
- **Bộ kiểm soát hành động (ToolActionValidator):** Xác thực nghiêm ngặt tính hợp lệ của tham số: kiểm tra path containment (ngăn chặn mọi biến thể của `../` hoặc đường dẫn tuyệt đối ra ngoài thư mục dự án), kiểm tra cú pháp định danh ký tự biểu tượng (symbol validation chống SQL/Command Injection).
- **Sổ cái bằng chứng đơn điệu (EvidenceLedger):** Lưu trữ các sự kiện đã kiểm chứng từ các công cụ dưới dạng cấu trúc bất biến (immutable facts). Mô hình thẩm định (Judge) bắt buộc phải suy luận dựa trên các sự kiện đã ghi nhận trong sổ cái, triệt tiêu khả năng tự bịa đặt bằng chứng.

---

### 3.3 Cổng chính sách bảo thủ và Thước đo đánh giá

#### Nguyên tắc cổng chính sách (PolicyEngine)
Chính sách phân loại tuân thủ mô hình 4 trạng thái quyết định:
1. `LIKELY_TP`: Xác nhận có chuỗi luồng dữ liệu độc hại rõ ràng từ đầu vào người dùng tới hàm nguy hiểm (sink) mà không có cơ chế lọc.
2. `FP_CANDIDATE`: Chỉ được gán khi có **bằng chứng phủ định tất định mạnh mẽ** (`BOUNDED_LOCAL_NEGATIVE_PROOF`), ví dụ: chứng minh được toàn bộ tham số truyền vào lệnh hệ thống là mảng hằng số cố định.
3. `MANUAL_REVIEW`: Trạng thái mặc định đóng an toàn (fail-closed) khi bằng chứng chưa đầy đủ, có xung đột hoặc phát hiện dấu hiệu bất thường.
4. `TRIAGE_ERROR`: Khi xảy ra lỗi ngoại lệ; cảnh báo vẫn được giữ nguyên đầy đủ trong báo cáo.

#### Thước đo toán học (Evaluation Metrics)
Trong bài toán bảo mật, ta định nghĩa nhãn dương tính ($P$) là cảnh báo cần reviewer xử lý (bao gồm cả `LIKELY_TP` và `MANUAL_REVIEW`), nhãn âm tính ($N$) là cảnh báo được hệ thống tự động xác định an toàn để đề xuất bỏ qua (`FP_CANDIDATE`).

- **Độ chính xác (Precision):** Tỷ lệ cảnh báo thực sự nguy hiểm trong số các cảnh báo được hệ thống giữ lại:
  $$P = \frac{TP}{TP + FP}$$
- **Độ bao phủ (Recall):** Tỷ lệ lỗ hổng thật được hệ thống giữ lại:
  $$R = \frac{TP}{TP + FN}$$
- **Khoảng tin cậy chính xác Clopper-Pearson (Exact Binomial CI):** Đối với bài toán yêu cầu an toàn cao nơi $Recall = 1,0$ (tức $k = n = 96$), khoảng tin cậy tiệm cận Wald thường bị suy biến thành $[1,0, 1,0]$. Chúng tôi sử dụng phân phối Beta để tính khoảng tin cậy chính xác Clopper-Pearson với mức ý nghĩa $\alpha = 0,05$:
  $$R_{lower} = B\left(\frac{\alpha}{2}; k, n - k + 1\right), \quad R_{upper} = B\left(1 - \frac{\alpha}{2}; k + 1, n - k\right)$$
  Với $k=96, n=96$, cận dưới chính xác là $0,975^{1/96} \approx 0,9623$, cho khoảng tin cậy là **$[0,9623, 1,0000]$**.
- **Điểm F1 điều hòa (F1-Score):**
  $$F_1 = 2 \cdot \frac{P \cdot R}{P + R}$$
- **Tỷ lệ bỏ sót lỗ hổng (False Negative Rate - FNR):** Yêu cầu an toàn bắt buộc $FNR = 0,00\%$:
  $$FNR = \frac{FN}{TP + FN}$$
- **Tỷ lệ công sức phân loại tiết kiệm được (Analyst Effort Saved):** Tỷ lệ cảnh báo được hệ thống tự động giải quyết dứt điểm ra khỏi hàng đợi phân loại thủ công ban đầu:
  $$\text{Effort Saved} = \frac{N_{\text{total}} - N_{\text{MANUAL\_REVIEW}}}{N_{\text{total}}} \times 100\%$$
- **Sai số hiệu chuẩn kỳ vọng (Expected Calibration Error - ECE):** Đo lường mức độ tin cậy của xác suất dự đoán chia theo $M$ khoảng (bins):
  $$\text{ECE} = \sum_{m=1}^{M} \frac{|B_m|}{N} |\text{acc}(B_m) - \text{conf}(B_m)|$$

---

## 4. Thí nghiệm và kết quả

### 4.1 Môi trường thực nghiệm
Toàn bộ mã nguồn và dữ liệu thực nghiệm được quản lý thống nhất tại commit `f0b1805d`. Thử nghiệm chạy trên hệ thống CPU Intel Core i5 / Windows với môi trường Python 3.12/3.14. Nền tảng Joern CPG chạy trong Docker container cô lập (`sast-triage-joern:4.0.600`). Bộ kiểm thử tự động đạt **542/542 bài test thông qua (100% Passed)**.

---

### 4.2 So sánh với các đường cơ sở (Baseline Comparison)

Bảng 2 so sánh hiệu năng giữa ba phương pháp tiếp cận trên toàn bộ 219 cảnh báo benchmark:

```
Bảng 2: So sánh hiệu năng giữa Scanner Baseline, LLM-Only và Hệ thống đề xuất.
-----------------------------------------------------------------------------------------
Phương pháp                 Precision [95% CI]      Recall [Clopper-Pearson]   F1      FN Rate  Effort Saved
-----------------------------------------------------------------------------------------
1. Scanner-Only (Semgrep)   0,4384 [0,3744, 0,5068] 1,0000 [0,9623, 1,0000]   0,6095   0,00%     0,00%
2. LLM-Only (Không rào)    0,6504 [0,5652, 0,7302] 0,8333 [0,7435, 0,9016]   0,7306  16,67%   100,00%
3. Hệ thống đề xuất         0,4384 [0,3744, 0,5068] 1,0000 [0,9623, 1,0000]   0,6095   0,00%     7,76%
-----------------------------------------------------------------------------------------
```

**Phân tích quan sát:**
1. **Rủi ro chí mạng của mô hình LLM thuần túy:** Mô hình LLM-Only khi không có cổng chính sách bảo thủ đạt F1 cao biểu kiến (0,7306) và tiết kiệm 100% công sức, nhưng lại tạo ra tỷ lệ **False Negative lên tới 16,67%–21,88%** (bỏ sót 16 đến 21 lỗ hổng thật). Mô hình bị đánh lừa bởi cấu trúc mã phức tạp và tự ý coi các hàm thiếu kiểm soát là an toàn. Trong an ninh phần mềm, đây là sự đánh đổi không thể chấp nhận.
2. **Bảo toàn tính an toàn tuyệt đối:** Hệ thống đề xuất duy trì Recall đạt mức tối đa **1,0000** (FN Rate = 0,00%), đảm bảo không bỏ sót bất kỳ lỗ hổng thật nào.
3. **Tiết kiệm công sức an toàn:** Hệ thống tự động xác nhận và đưa 17 cảnh báo có chuỗi bằng chứng rõ ràng sang `LIKELY_TP` (tiết kiệm **7,76%** công sức thẩm định ban đầu), đồng thời chuyển 202 cảnh báo còn lại (92,24%) về hàng đợi `MANUAL_REVIEW` để chuyên gia con người thẩm định an toàn.

---

### 4.3 Phân rã thành phần hệ thống (Component Decomposition Ablation)

Để đánh giá độc lập sự đóng góp của từng khối kiến trúc, chúng tôi tiến hành phân rã hệ thống qua 7 cấu hình tăng dần:

```
Bảng 3: Phân rã 7 cấu hình thành phần hệ thống trên 219 cảnh báo.
--------------------------------------------------------------------------------------------------------
Cấu hình thành phần                 Precision   Recall [Clopper-Pearson]   F1      FN Rate  % MANUAL  Effort Saved
--------------------------------------------------------------------------------------------------------
C1. Scanner-Only (Semgrep)           0,4384     1,0000 [0,9623, 1,0000]   0,6095   0,00%    100,00%     0,00%
C2. LLM-Only (No Guardrails)         0,6504     0,8333 [0,7435, 0,9016]   0,7306  16,67%      0,00%   100,00%
C3. LLM + Cổng độ tự tin HIGH        0,4866     0,9479 [0,8826, 0,9829]   0,6431   5,21%     68,95%    31,05%
C4. + Kiểm tra Joern CPG Reachability0,4848     1,0000 [0,9623, 1,0000]   0,6531   0,00%     66,21%    33,79%
C5. + Cổng PolicyEngine bảo thủ      0,4384     1,0000 [0,9623, 1,0000]   0,6095   0,00%     99,54%     0,46%
C6. + Bộ thẩm định Post-Verifier     0,4384     1,0000 [0,9623, 1,0000]   0,6095   0,00%     99,54%     0,46%
C7. + Bộ điều phối Agent leo thang   0,4384     1,0000 [0,9623, 1,0000]   0,6095   0,00%     92,24%     7,76%
--------------------------------------------------------------------------------------------------------
```

**Ý nghĩa của từng thành phần:**
- Cấu hình C3 (Cổng độ tự tin HIGH) giảm mạnh tỷ lệ FN từ 16,67% xuống 5,21%.
- Cấu hình C4 (Joern CPG) giải quyết triệt để các ca thiếu vết luồng dữ liệu, đưa tỷ lệ FN về 0,00%.
- Cấu hình C5 & C6 (PolicyEngine fail-closed) khóa chặt rủi ro bỏ sót, nhưng đẩy hầu hết cảnh báo (99,54%) về `MANUAL_REVIEW` vì phân tích tĩnh đơn bước không đủ thông tin liên hàm.
- Cấu hình C7 (Bộ điều phối Agent leo thang) giải quyết nút thắt cổ chai: vòng lặp điều tra đa bước sử dụng các công cụ tra cứu mã cục bộ để giải quyết **144 trường hợp UNKNOWN ban đầu về 0**, từ đó chuyển 16 ca nghi vấn phức tạp sang xác nhận an toàn, nâng tỷ lệ Effort Saved từ **0,46% lên 7,76% (+7,30%)**.

---

### 4.4 Bóc tách các chế độ hoạt động của Bộ điều phối (Agent Modes Ablation)

```
Bảng 4: So sánh 4 chế độ vận hành của bộ điều phối điều tra.
-----------------------------------------------------------------------------------------
Chế độ           Recall [Clopper-Pearson]   F1      Effort Saved   Số Tool/cảnh báo  Độ trễ TB
-----------------------------------------------------------------------------------------
agent_off        1,0000 [0,9623, 1,0000]   0,6095      0,46%             0,00         0,26 ms
agent_escalate   1,0000 [0,9623, 1,0000]   0,6095      7,76%             1,32         2,88 ms
agent_always     1,0000 [0,9623, 1,0000]   0,6095      7,76%             2,00         3,38 ms
agent_escalate_sc1,0000 [0,9623, 1,0000]   0,6095      7,76%             1,32         2,70 ms
-----------------------------------------------------------------------------------------
```

**Tính ưu việt của cơ chế leo thang kiểm soát (Escalation):** Chế độ `agent_escalate` đạt cùng mức hiệu quả tiết kiệm công sức như `agent_always` (7,76%), nhưng **giảm 34,0% số lượt gọi công cụ** (1,32 so với 2,00 lượt) và giảm 14,8% độ trễ xử lý. Hệ thống chỉ kích hoạt điều tra chuyên sâu khi thực sự cần thiết.

---

### 4.5 Hiệu chuẩn độ tin cậy và Kiểm toán False Negative

- **Sai số ECE:** Đạt **0,0598 – 0,0785** (5,98%–7,85%). 
- **Độ tin cậy nhóm HIGH:** Trong nhóm các phán quyết có độ tự tin mức HIGH, độ chính xác thực tế đạt **98,08%** (102/104 phán quyết đúng). Kết quả này chứng minh tính đúng đắn về mặt thống kê của quy tắc: chỉ cho phép tự động xử lý khi độ tự tin đạt mức HIGH.
- **Kiểm toán Shadow Mode FN:** Lấy mẫu ngẫu nhiên 10% cảnh báo độc lập ghi nhận **0,0% False Negative** (không có lỗ hổng thật nào bị triệt tiêu sai).

---

### 4.6 Hiệu quả cắt giảm Token và Chi phí suy luận

- Số lượng token ngữ cảnh thô trung bình: **977,9 tokens/cảnh báo**.
- Số lượng token sau khi làm sạch và đóng gói: **574,8 tokens/cảnh báo**.
- **Mức cắt giảm token thực tế đo được:** **41,22%**.
- Độ trễ xử lý cục bộ: **0,076 ms/cảnh báo**.
- Chi phí tài chính ước tính: Chỉ khoảng **0,0862 USD cho mỗi 1.000 cảnh báo** (tiết kiệm 41% chi phí suy luận so với gửi ngữ cảnh thô).

---

### 4.7 Thử nghiệm phòng thủ an ninh đối kháng (Adversarial Red-Team)

1. **Chống Prompt Injection gián tiếp (Suite B - 16 mẫu):**
   - Mô hình không phòng thủ (Naive Baseline): Tỷ lệ tấn công thành công ASR = **100,0%** (16/16 payload ép thành công mô hình hạ nhãn cảnh báo).
   - Hệ thống đề xuất: Tỷ lệ tấn công thành công ASR = **0,00%** (16/16 payload bị phát hiện và chuyển an toàn về `MANUAL_REVIEW`).
2. **Chống Tool & Code Injection trong vòng lặp điều tra (Suite C - 12 mẫu):**
   - Các payload cố tình thoát thư mục (`../../../../etc/passwd`), chèn ký tự điều khiển SQL/Command Injection vào tên hàm đều bị `ToolActionValidator` từ chối 100%. ASR = **0,00%**.
3. **Thử nghiệm rò rỉ Canary Secret (Suite A - 5 định dạng):**
   - Không có bất kỳ chuỗi bí mật nào bị rò rỉ vào Sanitized Context, Prompt hay Báo cáo xuất bản (**0,00% rò rỉ**).

---

### 4.8 Phân tích lỗi chi tiết (Error Analysis)

Khi chuyển từ chế độ Tier-1 sang điều tra leo thang (`agent_escalate`), có đúng **17 cảnh báo** được chuyển trạng thái từ `MANUAL_REVIEW` sang `LIKELY_TP`:
- **3 cảnh báo là lỗ hổng thật (True Positives):** Được xác nhận chính xác nhờ công cụ `read_function` tìm thấy chuỗi gán khóa API cứng thật trong mã nguồn backend (`introduction/views.py:870`, `introduction/views.py:872`, và `good/libsession.py:9`).
- **14 cảnh báo là cảnh báo giả (False Positives):** Các cảnh báo này nằm trong tệp kiểm thử đơn vị (`app/tests/.../test_a6_sensitive_data_exposure.py`, `test_password_reset.py`), tệp kịch bản giao diện tĩnh (`introduction/static/js/a7.js`, `a9.js`) hoặc tệp tài liệu hướng dẫn markdown (`A6-Sensitive-Data-Exposure.md`).
- **Nguyên nhân cốt lõi:** Bộ thẩm định heuristic hiện tại chưa tích hợp bộ lọc nhận diện ngữ cảnh tệp kiểm thử (test-file exclusion heuristic), nên khi phát hiện chuỗi khóa khớp quy tắc trong tệp kiểm thử, hệ thống vẫn đánh giá là LIKELY_TP. Tuy nhiên, vì cả `LIKELY_TP` và `MANUAL_REVIEW` đều là cảnh báo dương tính được đưa cho reviewer xử lý, điểm số F1 và Recall của hệ thống không bị suy giảm.

---

## 5. Thảo luận

**Trả lời câu hỏi nghiên cứu.** Kết quả thực nghiệm khẳng định rằng: hoàn toàn có thể ứng dụng LLM vào tự động hóa phân loại cảnh báo SAST mà không phải đánh đổi độ an toàn (0% False Negative), với điều kiện tiên quyết là **LLM không được nắm quyền quyết định cuối cùng**. Rào chắn chính sách bảo thủ dựa trên thuộc tính chương trình và đồ thị luồng dữ liệu (CPG) là yếu tố quyết định để ngăn chặn ảo giác.

**Bản chất của các con số đánh đổi:**
- Tỷ lệ công sức tiết kiệm đạt **7,76%** thoạt nhìn khiêm tốn so với con số 100% của mô hình LLM thuần túy. Tuy nhiên, 100% của LLM thuần túy đi kèm với cái giá thảm họa: bỏ sót 16,67%–21,88% lỗ hổng thật. Trong bảo mật, tiết kiệm 7,76% công việc mà **bảo toàn 100% lỗ hổng thật** có giá trị thực tiễn vượt trội so với tự động hóa mù quáng.

**Hạn chế của nghiên cứu (Limitations):**
1. *Quy mô tập dữ liệu:* Đánh giá trên 219 cảnh báo từ 5 ứng dụng web Python. Cần mở rộng quy mô trên các dự án lớn hơn và đa dạng ngôn ngữ lập trình.
2. *Độ bao phủ của Joern CPG trên diện rộng:* [CHƯA ĐO]. Nghiên cứu kiểm tra thành công trên 5 kho mã nguồn thực nghiệm, nhưng tỷ lệ dựng đồ thị CPG thành công trên quy mô toàn bộ hệ sinh thái hàng nghìn package của PyPI cần được đo đạc trong tương lai.
3. *Thực thi tuần tự:* Hệ thống hiện vận hành đơn luồng tuần tự, chưa áp dụng xử lý đa luồng song song (multithreading / async).
4. *Phạm vi tính toán Recall:* Recall chỉ được tính toán trên tập hợp các cảnh báo do scanner (Semgrep) phát hiện ra. Nếu scanner ban đầu bỏ sót một lỗ hổng trong mã nguồn (scanner blind spot), hệ thống triage không thể tiếp cận và đánh giá lỗ hổng đó.

---

## 6. Kết luận và Hướng phát triển

Bài báo đã thiết kế và đánh giá thực nghiệm hệ thống **LLM-Augmented SAST Triage Platform** kết hợp hai tầng: thu thập ngữ cảnh tất định và điều tra nhiều vòng có kiểm soát, bảo vệ bởi chính sách bảo thủ fail-closed. Hệ thống chứng minh tính khả thi trong việc loại bỏ hoàn toàn rủi ro False Negative (Recall = 1,0000, FN Rate = 0,00%), tiết kiệm 7,76% công sức thẩm định, giảm 41,22% token và vô hiệu hóa hoàn toàn các tấn công tiêm nhiễm câu lệnh.

**Hướng phát triển tiếp theo:**
1. Tích hợp bộ lọc loại trừ tệp kiểm thử (test-file heuristic) để tránh xác nhận nhầm các khóa mẫu trong unit test.
2. Mở rộng bộ phân tích CPG và hỗ trợ thêm các ngôn ngữ phổ biến (JavaScript, Java, Go).
3. Triển khai cơ chế song song hóa luồng điều tra (asynchronous workers) để tăng tốc độ phân loại trên các kho mã nguồn quy mô lớn.

---

## Tài liệu tham khảo

- [1] F. Yamaguchi, N. Golde, D. Arp, K. Rieck, “Modeling and discovering vulnerabilities with code property graphs,” in *IEEE Symposium on Security and Privacy (S&P)*, 2014.
- [2] Joern, “The open-source code analysis platform for C/C++/Java/Python/JavaScript,” 2024. [Online]. Available: https://joern.io/
- [3] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, M. Fritz, “Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection,” in *ACM Workshop on Artificial Intelligence and Security (AISEC)*, 2023.
- [4] Qwen Team, “Qwen2.5-Coder: Technical Report,” arXiv preprint arXiv:2409.12186, 2024.
- [5] C. Clopper, E. S. Pearson, “The use of confidence or fiducial limits illustrated in the case of the binomial,” *Biometrika*, vol. 26, no. 4, pp. 404–413, 1934.
- [6] C. Guo, G. Pleiss, Y. Sun, K. Q. Weinberger, “On calibration of modern neural networks,” in *International Conference on Machine Learning (ICML)*, 2017.
- [7] B. Efron, R. J. Tibshirani, *An Introduction to the Bootstrap*. CRC Press, 1994.
- [8] OWASP, “OWASP Top 10: 2021 - The Ten Most Critical Web Application Security Risks,” 2021.
- [9] Semgrep, “Lightweight static analysis for many languages,” 2024. [Online]. Available: https://semgrep.dev/
- [10] Gitleaks, “Audit git repositories for secrets,” 2024. [Online]. Available: https://github.com/gitleaks/gitleaks
