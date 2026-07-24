# BÁO CÁO TIẾN ĐỘ DỰ ÁN (WEEKLY PROGRESS REPORT)

**Người thực hiện**: Đỗ Văn Cung  
**Dự án**: LLM-Augmented SAST Triage & Logic-Bug Detection Platform  
**GitHub Repository**: [https://github.com/cunghande/LLM-Augmented-SAST-Triage-Logic-Bug-Detection-Platform](https://github.com/cunghande/LLM-Augmented-SAST-Triage-Logic-Bug-Detection-Platform)  
**Ngày báo cáo**: 24/07/2026  

---

## 🎯 Kính gửi Mentor,

Em xin phép báo cáo tóm tắt các công việc và tiến độ em đã thực hiện nghiên cứu, phát triển trong tuần qua đối với nền tảng tự động hóa phân loại cảnh báo SAST và phát hiện lỗi logic ứng dụng bằng LLM.

---

## 🛠️ 1. Các Kết Quả Đã Hoàn Thành Trong Tuần Qua

Dự án đã được thiết kế và hoàn thiện theo mô hình **Multi-Agent Platform (3 Agents)** chạy hoàn toàn với LLM Local (Qwen 3:8b trên Ollama), không phụ thuộc cloud API:

### 🔹 Sprint 1 — Automated SAST Triage MVP
- **Bộ Parsers Chuẩn Hóa**: Chuẩn hóa dữ liệu thô từ **Semgrep** (JSON/SARIF) và **Gitleaks** (Secrets) về một schema duy nhất `UnifiedFinding`.
- **Context Extractor**: Tự động trích xuất đoạn code xung quanh cảnh báo (±15 dòng), nhận diện hàm/route bao bọc và tự động che giấu (redact) thông tin nhạy cảm.
- **Agent 1 (SAST Triage Engine)**: Sử dụng Qwen 3:8b để tự động phân loại cảnh báo thành **True Positive (TP)** hoặc **False Positive (FP)** kèm độ tin cậy (confidence) và lý giải bảo mật.

### 🔹 Sprint 2 — Logic-Bug Detection, CPG Graph, Risk Scoring & Remediation
- **Agent 2 (CPG & Logic-Bug Detector)**: Xây dựng pipeline phân tích mã nguồn AST/CPG (Code Property Graph) trích xuất luồng `Entrypoint → Guard → Sensitive Sink` để phát hiện các lớp lỗi logic phức tạp (IDOR, Mass Assignment, Business Bypass, Plain-text auth flow).
- **Tích hợp Neo4j Graph Database**: Khởi chạy container Neo4j qua Docker (`neo4j:5.24-community`), xuất trực tiếp đồ thị CPG vào Neo4j giúp trực quan hóa và truy vấn luồng mã nguồn bằng ngôn ngữ **Cypher Query**.
- **Agent 3a (Risk Scoring Engine)**: Đánh giá điểm rủi ro từ 1.0 đến 5.0 dựa trên 5 thành phần: *Severity, Reachability, Exposure, Data Sensitivity, Exploitability*.
- **Agent 3b (Remediation Generator)**: Tự động sinh bản vá mã nguồn dạng **Code Diff Patch** chuẩn cho các cảnh báo TP.
- **CLI Suite & Unit Tests**: Xây dựng 11 lệnh CLI hoàn chỉnh, bộ unit tests đạt **11/11 PASS (100%)**.

---

## 🔬 2. Công Việc Đang Thực Hiện (Evaluation & Data Validation)

Để nâng cao độ tin cậy và kiểm chứng tính thực tiễn của hệ thống, em đang triển khai đánh giá mở rộng trên dữ liệu chuẩn:

- **Benchmark Chuẩn Khảo Sát**: Đã tích hợp bộ **OWASP Benchmark 1.2** (gồm **2,740 testcases** chuẩn).
- **Thử Nghiệm Thực Tế**: Đã chạy thử nghiệm thành công trên các dự án mẫu thực tế (`CN_WEB`, `Sequential-Recommender`).
- **Đánh Giá Định Lượng**: Đang tiến hành đo đạc các chỉ số **Precision, Recall, F1-Score** và **Tỷ lệ lọc nhiễu FP % (FP Reduction Rate)** để đưa vào báo cáo đánh giá cuối cùng.

---

## 🔮 3. Kế Hoạch Tuần Tiếp Theo

1. **Hoàn thiện bảng đo đạc chỉ số** độ chính xác trên bộ OWASP Benchmark (2,740 testcases).
2. **Khởi chạy Sprint 3**: Xây dựng cơ chế **FP Suppression Database** (lưu vết cảnh báo giả để không quét lại) và viết thêm bộ luật Semgrep tùy chỉnh cho hệ thống.
3. **Chuẩn bị tích hợp CI/CD Pipeline** (Jenkins/GitHub Actions).

---

*Em rất mong nhận được những góp ý và định hướng thêm từ Mentor để hoàn thiện dự án tốt hơn ạ.*

**Trân trọng,**  
**Đỗ Văn Cung**
