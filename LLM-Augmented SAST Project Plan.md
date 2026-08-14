> [!IMPORTANT]
> **Tài liệu lưu trữ của đề xuất v9 — không phải kế hoạch triển khai hiện tại.**
> Các mục tiêu risk scoring, remediation, auto-suppression, 20 custom rules,
> Jenkins, dashboard và phát hiện năm lớp logic bug chưa được chấp nhận làm
> deliverable. Xem [`docs/current-project-plan.md`](docs/current-project-plan.md)
> và [`docs/sprint-1-scope.md`](docs/sprint-1-scope.md).

# KẾ HOẠCH DỰ ÁN

## LLM-Augmented SAST Triage & Logic-Bug Detection Platform

> **Mục tiêu tổng quát:** Xây dựng nền tảng tăng cường SAST bằng LLM nhằm tự động phân loại finding, giảm false positive, phát hiện các lỗi logic mà công cụ dựa trên rule dễ bỏ sót, ưu tiên xử lý theo rủi ro và tích hợp vào quy trình CI/CD.

---

## 1. Thông tin tổng quan

| Hạng mục | Nội dung |
|---|---|
| **Tên dự án** | **LLM-Augmented SAST Triage & Logic-Bug Detection Platform** |
| **Phạm vi chính** | Triage finding từ Gitleaks/Semgrep; phát hiện logic-bug theo ngữ cảnh codebase; risk scoring; remediation; quản lý false positive; sinh custom Semgrep rule; tích hợp Jenkins và dashboard. |
| **Đối tượng sử dụng** | AppSec/Security Engineer, DevSecOps, Development Team, Tech Lead và người vận hành CI/CD. |
| **Đầu vào** | Kết quả Gitleaks/Semgrep dạng SARIF/JSON, source code, metadata repository, cấu hình deployment và dữ liệu phản hồi TP/FP. |
| **Đầu ra** | Báo cáo finding đã triage; finding logic-bug; risk score; thứ tự ưu tiên; remediation/code diff; suppression database; custom rules; Jenkins shared library; dashboard và tài liệu vận hành. |
| **Thời lượng đề xuất** | 03 sprint; thời lượng từng sprint được xác định theo năng lực đội dự án và số lượng repository/service thực tế. |

---

## 2. Sản phẩm bàn giao

| ID | Sản phẩm bàn giao | Mô tả chức năng | Đầu ra chính |
|---|---|---|---|
| **DLV-01** | **Pipeline triage tự động** | Nhận output Gitleaks/Semgrep dạng SARIF/JSON; chuẩn hóa finding; dùng LLM phân loại True Positive/False Positive kèm confidence và lý do; xuất báo cáo đã lọc. | CLI/API triage; schema finding chuẩn; báo cáo JSON/Markdown/HTML hoặc định dạng đã thống nhất. |
| **DLV-02** | **Module phát hiện logic-bug** | Phân tích codebase theo call-flow và context bằng AST/CPG/repository context để phát hiện lỗi mà rule-based scanner thường bỏ sót. | Finding cho authz bypass, IDOR, race condition/TOCTOU, mass assignment, business-logic flaw và insecure workflow. |
| **DLV-03** | **Engine ưu tiên và remediation** | Tính điểm rủi ro dựa trên severity, reachability, exposure và data sensitivity; đề xuất bản vá cụ thể cho từng finding. | Risk score; mức ưu tiên; lý do xếp hạng; remediation và code diff đề xuất. |
| **DLV-04** | **FP feedback loop** | Lưu finding đã xác nhận FP bằng fingerprint; tự động suppress ở các lần scan tiếp theo; hỗ trợ expiry và re-review. | FP database; API/CLI mark-as-FP; suppression engine; báo cáo độ chính xác fingerprint. |
| **DLV-05** | **Custom Semgrep Rule Pack** | Sinh và kiểm thử custom rule từ các pattern TP lặp lại và các logic-bug đã xác thực. | Tối thiểu 20 rule nội bộ; test case; kết quả đo finding mới và FP phát sinh. |
| **DLV-06** | **Tích hợp CI/CD** | Tích hợp quy trình scan, triage, risk gate và phản hồi kết quả vào Jenkins/MR/PR. | Jenkins shared library; pipeline mẫu; chính sách gate; comment/check kết quả trên MR/PR. |
| **DLV-07** | **Dashboard và báo cáo** | Theo dõi finding theo service, xu hướng FP, thời gian xử lý và backlog theo rủi ro. | Dashboard vận hành; báo cáo định kỳ; dữ liệu phục vụ quản trị và audit. |
| **DLV-08** | **Tài liệu và bàn giao** | Hướng dẫn cài đặt, vận hành, xử lý sự cố, sử dụng cho developer và chuyển giao cho team. | Bộ tài liệu; runbook; hướng dẫn developer; checklist bàn giao; buổi training. |

---

## 3. Tiêu chí hoàn thành và chỉ số nghiệm thu

| ID | Chỉ số/Kết quả mong muốn | Mục tiêu nghiệm thu | Phương pháp đo đề xuất | Bằng chứng nghiệm thu |
|---|---|---:|---|---|
| **KPI-01** | Giảm finding phải review thủ công | **≥ 60%** | So sánh số finding cần con người review trước và sau triage trên cùng benchmark hoặc cùng nhóm repository. | Báo cáo baseline và báo cáo sau triển khai. |
| **KPI-02** | False Positive rate sau triage | **≤ 15%** | FP rate = số finding được đưa ra review nhưng được xác nhận FP / tổng số finding được đưa ra review. | Kết quả gán nhãn thủ công và confusion matrix. |
| **KPI-03** | False Negative của bộ triage | **≤ 10%** | FN rate = finding TP bị auto-suppress hoặc phân loại sai / tổng số TP trong benchmark có ground truth. | Benchmark có ground truth; log verdict; báo cáo đánh giá. |
| **KPI-04** | Thời gian triage trung bình | Từ **X giờ/scan xuống ≤ 15 phút/scan** | Đo từ lúc nhận output scanner đến lúc sinh báo cáo triage cuối cùng; báo cáo P50/P95 bên cạnh giá trị trung bình. | Log thời gian chạy trên bộ repo đại diện. |
| **KPI-05** | Năng lực phát hiện logic-bug | **≥ 5 lớp lỗi** ngoài khả năng hiện tại của Semgrep/Gitleaks | Đối chiếu finding của module với baseline scanner và xác nhận thủ công. | Danh sách finding, bằng chứng code path và phân tích nguyên nhân. |
| **KPI-06** | Xác thực trên hệ thống thật | PoC trên **ít nhất 03 service thật** | Security review và xác nhận khả năng khai thác/tác động trong môi trường được kiểm soát. | PoC, ticket xác nhận, biên bản review; dữ liệu nhạy cảm phải được che/redact. |
| **KPI-07** | Chất lượng finding TP | **100% TP** có risk score, mức ưu tiên và remediation ở mức code | Kiểm tra completeness theo schema báo cáo và review mẫu bởi developer. | Báo cáo finding; code diff; phản hồi của developer. |
| **KPI-08** | Khả năng áp dụng remediation | Developer áp dụng được mà không cần hỏi lại | Review trên mẫu finding TP; ghi nhận tỷ lệ patch được chấp nhận hoặc chỉ cần chỉnh sửa nhỏ. | PR/commit thử nghiệm; nhận xét của developer/tech lead. |
| **KPI-09** | Suppression finding FP | Finding đã mark FP không xuất hiện lại ở scan kế tiếp | Chạy lại scan sau khi mark FP và so sánh fingerprint. | Log suppression và báo cáo regression. |
| **KPI-10** | Độ chính xác fingerprint | **≥ 95%** | Đo tỷ lệ match đúng qua thay đổi dòng, format và refactor nhẹ; theo dõi collision/mismatch. | Bộ test fingerprint và kết quả đánh giá. |
| **KPI-11** | Custom Semgrep rules | **≥ 20 rule nội bộ** | Chạy rule trên benchmark và repository đại diện; đo precision và số finding mới bắt thêm. | Rule pack, test case, changelog và báo cáo hiệu quả. |
| **KPI-12** | Tích hợp vận hành | Chạy tự động trong pipeline và bàn giao cho team | Kiểm thử pipeline end-to-end, risk gate, báo cáo, alert và hướng dẫn rollback. | Jenkins shared library; pipeline run; tài liệu và biên bản bàn giao. |

> **Lưu ý:** Giá trị **X giờ/scan** cần được chốt sau giai đoạn khảo sát baseline trong Sprint 1. Nên ghi nhận thêm P50 và P95 để tránh giá trị trung bình che khuất các repository có thời gian xử lý bất thường.

---

## 4. Kế hoạch triển khai theo sprint

### Sprint 1 — Baseline, Benchmark và Automated Triage MVP

**Mục tiêu:** Thiết lập baseline, xây benchmark có ground truth và hoàn thiện CLI triage end-to-end trên một repository.

| ID | Nhóm công việc | Nội dung thực hiện | Kết quả đầu ra | Tiêu chí hoàn thành gợi ý |
|---|---|---|---|---|
| **S1-01** | Khảo sát hiện trạng | Thống kê volume finding và tỷ lệ FP thực tế của Gitleaks/Semgrep trên 20–30 repository đại diện. Phân nhóm theo ngôn ngữ, service, rule và severity. | Báo cáo baseline; danh sách rule nhiễu; phân bố finding theo repository. | Có số liệu đủ cho 20–30 repo; xác định baseline FP và thời gian review hiện tại. |
| **S1-02** | Benchmark ground truth | Chọn khoảng 200–300 finding và gán nhãn TP/FP thủ công; lưu lý do, reviewer và mức độ chắc chắn. | Dataset benchmark có version; guideline gán nhãn; kết quả review chéo. | Mỗi mẫu có nhãn và bằng chứng; mẫu tranh chấp được adjudication bởi reviewer có thẩm quyền. |
| **S1-03** | Chuẩn hóa input | Xây parser SARIF/JSON về schema finding thống nhất gồm rule_id, file, line, snippet, severity và metadata. | Unified finding schema; parser Gitleaks/Semgrep; validation và test case. | Parser xử lý được các file mẫu; lỗi input được ghi log rõ ràng; schema có version. |
| **S1-04** | Context extractor | Lấy snippet ± N dòng, hàm chứa lỗi, caller/callee, import, cấu hình và context liên quan cho prompt. | Context package có giới hạn token; logic redact dữ liệu nhạy cảm; unit test. | Context đủ để review; không vượt ngân sách token; không gửi dữ liệu ngoài chính sách. |
| **S1-05** | Prompt triage | Thiết kế few-shot prompt theo loại rule như secret, injection, crypto và path traversal; ép output JSON theo schema cố định. | Prompt library; JSON schema gồm verdict, confidence, reasoning và evidence. | Output parse được ổn định; có fallback khi JSON lỗi; prompt/version được lưu cùng kết quả. |
| **S1-06** | Đánh giá và hiệu chỉnh | Đo precision, recall, F1, FP/FN; hiệu chỉnh prompt và ngưỡng confidence thành ba nhóm xử lý. | Báo cáo confusion matrix; threshold policy; danh sách lỗi điển hình. | FN ≤ mục tiêu thử nghiệm hoặc có kế hoạch cải thiện; threshold được chọn dựa trên benchmark. |
| **S1-07** | Tích hợp MVP | Ghép parser, extractor, LLM triage và report thành CLI chạy end-to-end trên một repository. | CLI; cấu hình mẫu; log; báo cáo kết quả đo lường. | Một lệnh chạy hoàn chỉnh; kết quả reproducible; có hướng dẫn sử dụng ngắn. |

#### Chính sách phân luồng theo confidence đề xuất

| Nhóm | Điều kiện tham khảo | Hành động |
|---|---|---|
| **Auto-suppress candidate** | Verdict FP, confidence rất cao và không thuộc nhóm rule có tác động nghiêm trọng | Không hiển thị trong báo cáo chính; vẫn lưu audit log; có thể yêu cầu sampling để kiểm soát FN. |
| **Manual review** | Confidence trung bình, context thiếu, output mâu thuẫn hoặc thuộc nhóm nhạy cảm | Chuyển AppSec review; hiển thị đầy đủ evidence và câu hỏi còn mở. |
| **High-confidence TP** | Verdict TP với confidence cao và evidence rõ ràng | Đưa vào backlog ưu tiên; tính risk score và sinh remediation. |

**Deliverable Sprint 1:** CLI chạy end-to-end trên 01 repository và báo cáo đánh giá trên benchmark.

---

### Sprint 2 — Logic-Bug Detection, Risk Scoring và Remediation

**Mục tiêu:** Phát hiện lỗi logic theo code flow/context, đánh giá rủi ro và sinh hướng dẫn khắc phục có thể áp dụng.

| ID | Nhóm công việc | Nội dung thực hiện | Kết quả đầu ra | Tiêu chí hoàn thành gợi ý |
|---|---|---|---|---|
| **S2-01** | Phân tích codebase | Dựng pipeline sinh CPG/AST; xác định entrypoint, route, authz check và data flow tới sink nhạy cảm. | Code graph/context graph; danh mục entrypoint và sink; trace có thể kiểm chứng. | Truy vết được đường đi từ entrypoint đến sink trên các service mục tiêu. |
| **S2-02** | Chunking repository lớn | Ưu tiên vùng code rủi ro cao như auth, payment, user data và admin API thay vì quét toàn bộ. | Risk-based chunk selector; ngân sách token/thời gian cho từng repository. | Có tiêu chí chọn vùng code; giảm khối lượng phân tích nhưng vẫn giữ coverage ưu tiên. |
| **S2-03** | Logic-bug agents/prompts | Xây prompt/agent theo lớp lỗi: missing authz/IDOR, mass assignment, race condition/TOCTOU, business rule bypass và insecure direct workflow. | Prompt/agent library; output schema; evidence gồm source, path, guard và sink. | Phát hiện được ít nhất 05 lớp lỗi; mỗi finding có đường dẫn suy luận có thể review. |
| **S2-04** | Xác thực finding | Review thủ công trên 03 service thật; tái hiện và viết PoC cho lỗi được xác nhận trong môi trường được phép. | Danh sách TP/FP; PoC; root-cause analysis; ticket remediation. | Có xác nhận của AppSec/service owner; PoC an toàn, không tác động production. |
| **S2-05** | Risk scoring engine | Kết hợp severity, reachability, exposure, data sensitivity và exploitability/difficulty. | Công thức điểm; mức Critical/High/Medium/Low; giải thích từng thành phần. | Cùng input cho cùng kết quả; trọng số có tài liệu; reviewer hiểu được lý do xếp hạng. |
| **S2-06** | Sinh remediation | Gợi ý fix dạng code diff và giải thích ngắn; dùng template theo loại lỗi và stack nội bộ. | Patch proposal; validation checklist; test case gợi ý; cảnh báo phần cần review. | Developer áp dụng được; diff đúng context; không tạo regression hiển nhiên trong test. |
| **S2-07** | Báo cáo ưu tiên | Tổng hợp finding theo risk score, service, owner, trạng thái và khuyến nghị xử lý. | Báo cáo xếp hạng; danh sách logic-bug đã xác thực; executive summary. | Finding TP có đủ score, priority, evidence và remediation. |

#### Công thức risk scoring tham khảo

| Thành phần | Thang điểm tham khảo | Ý nghĩa |
|---|---:|---|
| **Severity** | 1–5 | Mức độ tác động kỹ thuật nếu lỗi bị khai thác. |
| **Reachability** | 1–5 | Mức độ có thể đi từ entrypoint đến đoạn code/sink chứa lỗi. |
| **Exposure** | 1–5 | Internal-only, partner-facing hay internet-facing. |
| **Data sensitivity** | 1–5 | Mức nhạy cảm của dữ liệu hoặc chức năng bị ảnh hưởng. |
| **Exploitability** | 1–5 | Độ dễ khai thác, yêu cầu quyền, điều kiện đồng thời và độ phức tạp. |

**Công thức khởi điểm:**

```text
Risk Score = 0.25 × Severity
           + 0.25 × Reachability
           + 0.20 × Exposure
           + 0.20 × Data Sensitivity
           + 0.10 × Exploitability
```

> Trọng số cần được hiệu chỉnh bằng dữ liệu nội bộ và review của AppSec. Nên lưu cả điểm tổng và điểm thành phần để bảo đảm khả năng giải thích.

**Deliverable Sprint 2:** Báo cáo finding đã xếp hạng kèm remediation và danh sách logic-bug đã xác thực.

---

### Sprint 3 — Feedback Loop, Custom Rules, CI/CD và Bàn giao

**Mục tiêu:** Hoàn thiện vòng phản hồi FP, mở rộng rule nội bộ, tích hợp tự động vào Jenkins và đưa hệ thống vào vận hành.

| ID | Nhóm công việc | Nội dung thực hiện | Kết quả đầu ra | Tiêu chí hoàn thành gợi ý |
|---|---|---|---|---|
| **S3-01** | FP database | Thiết kế fingerprint bền với thay đổi code bằng normalized snippet hash, rule_id và path pattern; hỗ trợ expiry/re-review. | Data model; API/CLI mark-as-FP; audit trail; chính sách lifecycle. | Truy vết được người đánh dấu, lý do và thời điểm; hỗ trợ revoke/expire. |
| **S3-02** | Auto-suppression | Suppress finding đã xác nhận FP ở lần scan sau; đo sai lệch fingerprint khi format hoặc refactor. | Suppression engine; regression suite; metrics collision/mismatch. | Độ chính xác fingerprint ≥ 95%; finding FP không tái xuất hiện ngoài trường hợp cần re-review. |
| **S3-03** | Custom Semgrep rules | Sinh rule từ pattern TP lặp lại và logic-bug đã xác thực; bổ sung test dương/âm. | Tối thiểu 20 rule; fixtures; CI kiểm thử rule; tài liệu rule. | Rule vượt quality gate; đo được finding mới; không làm FP tăng ngoài ngưỡng chấp nhận. |
| **S3-04** | Tuning scanner | Tắt rule nhiễu, bổ sung allowlist và tinh chỉnh entropy cho Gitleaks. | Scanner policy; config versioned; changelog; before/after metrics. | Giảm noise có bằng chứng; không làm tăng FN vượt ngưỡng. |
| **S3-05** | Jenkins integration | Xây shared library với các stage scan → triage → risk gate → publish/comment kết quả trên MR/PR. | Jenkins shared library; pipeline mẫu; status check; artifact/report. | Pipeline chạy tự động; gate theo policy; hỗ trợ retry, timeout và fail-safe. |
| **S3-06** | Dashboard/report | Hiển thị finding theo service, trend FP rate, thời gian fix và backlog theo mức rủi ro. | Dashboard; dataset/ETL; bộ lọc service/time/severity/status. | Dữ liệu cập nhật đúng lịch; số liệu đối soát được với pipeline artifact. |
| **S3-07** | Chi phí và bảo mật LLM | Cache theo finding hash, giới hạn context, redact secret/PII, lựa chọn deployment và lưu audit. | Cost dashboard; data-flow diagram; security controls; retention policy. | Không gửi dữ liệu trái chính sách; có giới hạn chi phí; cache và log hoạt động đúng. |
| **S3-08** | Tài liệu và training | Soạn tài liệu vận hành, hướng dẫn developer, runbook và tổ chức training. | Operation guide; developer guide; troubleshooting; tài liệu training. | Team vận hành thực hiện được quy trình chuẩn; hoàn thành checklist bàn giao. |

**Deliverable Sprint 3:** Hệ thống tích hợp Jenkins, FP feedback loop, bộ ≥ 20 custom rules, dashboard, tài liệu và buổi bàn giao.

---

## 5. Ma trận đầu ra theo sprint

| Đầu ra | Sprint 1 | Sprint 2 | Sprint 3 |
|---|:---:|:---:|:---:|
| Baseline Gitleaks/Semgrep trên 20–30 repo | ✅ |  |  |
| Benchmark 200–300 finding có ground truth | ✅ | Mở rộng | Dùng regression |
| Unified parser SARIF/JSON | ✅ | Cải tiến | Ổn định hóa |
| Context extractor | ✅ | Mở rộng AST/CPG | Tối ưu chi phí |
| LLM triage và threshold policy | ✅ | Tinh chỉnh | Productionize |
| Logic-bug detection | Thiết kế | ✅ | Rule hóa pattern |
| Risk scoring | Phác thảo | ✅ | Tích hợp gate/dashboard |
| Code-level remediation | Prototype | ✅ | Template hóa và theo dõi áp dụng |
| FP database và suppression | Thiết kế | Có thể thử nghiệm | ✅ |
| Custom Semgrep rules | Thu thập pattern | Draft rule | ✅ ≥ 20 rules |
| Jenkins shared library | Yêu cầu tích hợp | Thiết kế | ✅ |
| Dashboard/report | Báo cáo CLI | Báo cáo ưu tiên | ✅ Dashboard |
| Tài liệu và training | README MVP | Tài liệu kỹ thuật | ✅ Bàn giao đầy đủ |

---

## 6. Schema finding thống nhất đề xuất

| Trường | Bắt buộc | Mô tả |
|---|:---:|---|
| `finding_id` | ✅ | ID duy nhất của finding trong hệ thống. |
| `scanner` | ✅ | Nguồn phát hiện, ví dụ Gitleaks, Semgrep hoặc Logic-Bug Engine. |
| `rule_id` | ✅ | Mã rule hoặc loại detector. |
| `repository` | ✅ | Repository chứa finding. |
| `commit_sha` | ✅ | Commit được scan. |
| `file_path` | ✅ | Đường dẫn file chuẩn hóa. |
| `start_line` / `end_line` | ✅ | Vị trí finding trong file. |
| `snippet` | ✅ | Đoạn code đã redact nếu cần. |
| `severity` | ✅ | Severity từ scanner hoặc severity đã chuẩn hóa. |
| `metadata` |  | Ngôn ngữ, service, owner, tags, CWE/OWASP và thông tin bổ sung. |
| `context` |  | Hàm chứa lỗi, caller/callee, route, guard, config và data-flow. |
| `verdict` | ✅ | TP, FP hoặc NEEDS_REVIEW. |
| `confidence` | ✅ | Điểm tin cậy đã được calibration. |
| `reasoning` | ✅ | Lý do ngắn gọn, dựa trên evidence; tránh lưu chain-of-thought nội bộ. |
| `evidence` | ✅ | Dữ liệu kiểm chứng như source, sink, guard và code path. |
| `risk_score` | Với TP | Điểm rủi ro tổng và điểm thành phần. |
| `remediation` | Với TP | Mô tả cách khắc phục, diff đề xuất và test cần bổ sung. |
| `fingerprint` | ✅ | Fingerprint phục vụ deduplicate và suppression. |
| `status` | ✅ | New, Triaged, Confirmed, Suppressed, In Progress, Fixed hoặc Accepted Risk. |
| `model_version` / `prompt_version` | Với LLM | Phục vụ audit và tái lập kết quả. |

---

## 7. RACI rút gọn đề xuất

| Hoạt động | AppSec | DevSecOps/Platform | Development Team | Tech Lead/Service Owner | Project Owner |
|---|:---:|:---:|:---:|:---:|:---:|
| Gán nhãn benchmark | **R/A** | C | C | C | I |
| Xây parser và CLI | C | **R** | R | C | I |
| Xây context/AST/CPG pipeline | **R** | R | C | C | I |
| Xác thực finding/PoC | **R** | C | C | **A** | I |
| Duyệt risk scoring policy | **R** | C | C | C | **A** |
| Áp dụng remediation | C | I | **R** | **A** | I |
| Tích hợp Jenkins | C | **R/A** | C | I | I |
| Vận hành FP database | **A** | **R** | C | I | I |
| Duyệt custom rules | **R/A** | C | C | C | I |
| Nghiệm thu và bàn giao | R | R | C | C | **A** |

> **R:** Responsible · **A:** Accountable · **C:** Consulted · **I:** Informed

---

## 8. Rủi ro dự án và biện pháp kiểm soát

| Rủi ro | Tác động | Biện pháp kiểm soát |
|---|---|---|
| Ground truth không nhất quán giữa reviewer | Sai số khi đo precision/recall và chọn threshold | Có guideline gán nhãn, review chéo, adjudication và đo mức đồng thuận. |
| LLM phân loại tự tin nhưng sai | Tăng false negative nếu auto-suppress | Threshold bảo thủ; không auto-suppress nhóm critical; sampling audit; fallback manual review. |
| Context quá dài hoặc thiếu dữ kiện | Chi phí cao hoặc kết luận thiếu chính xác | Risk-based chunking; token budget; context ranking; chỉ lấy dependency/config liên quan. |
| Rò rỉ source code, secret hoặc PII | Vi phạm chính sách bảo mật | Redaction trước khi gửi; private deployment; allowlist dữ liệu; mã hóa; retention và audit log. |
| Fingerprint không bền khi refactor | FP cũ xuất hiện lại hoặc suppress nhầm | Normalization; path pattern; semantic anchors; expiry; regression test trên refactor mẫu. |
| Remediation tạo regression | Developer mất niềm tin hoặc gây lỗi mới | Diff chỉ là đề xuất; chạy unit/integration/security test; bắt buộc code review. |
| Custom rule làm tăng FP | Tăng tải review và giảm adoption | Test dương/âm; quality gate; rollout theo nhóm repo; theo dõi precision từng rule. |
| Thời gian chạy pipeline quá lâu | Team bypass hoặc tắt security gate | Cache; incremental scan; timeout; chạy song song; policy gate theo risk. |
| Chi phí LLM vượt dự toán | Không thể mở rộng toàn bộ repository | Cache theo hash; model routing; giới hạn context; batch; theo dõi cost/repo/scan. |

---

## 9. Checklist nghiệm thu cuối dự án

- [ ] Có baseline volume, FP rate và thời gian review trên 20–30 repository đại diện.
- [ ] Có benchmark khoảng 200–300 finding với ground truth, version và guideline gán nhãn.
- [ ] CLI/pipeline xử lý được SARIF/JSON từ Gitleaks và Semgrep.
- [ ] Báo cáo triage có verdict, confidence, reasoning ngắn gọn và evidence.
- [ ] Giảm ít nhất 60% finding cần review thủ công.
- [ ] FP rate sau triage không vượt 15%.
- [ ] FN của triage không vượt 10% trên benchmark.
- [ ] Thời gian triage trung bình không vượt 15 phút/scan theo môi trường đo đã thống nhất.
- [ ] Phát hiện ít nhất 05 lớp logic-bug ngoài baseline rule-based.
- [ ] Có PoC xác thực trên ít nhất 03 service thật trong môi trường được phép.
- [ ] Mọi TP đều có risk score, thứ tự ưu tiên và remediation ở mức code.
- [ ] FP suppression hoạt động ở lần scan tiếp theo.
- [ ] Độ chính xác fingerprint đạt ít nhất 95%.
- [ ] Có tối thiểu 20 custom Semgrep rule kèm test case.
- [ ] Jenkins pipeline chạy tự động và áp dụng risk gate đúng policy.
- [ ] Dashboard hiển thị đúng số liệu và đối soát được với pipeline artifact.
- [ ] Có tài liệu cài đặt, vận hành, troubleshooting, developer guide và security policy.
- [ ] Hoàn thành training và ký biên bản bàn giao.

---

## 10. Hướng dẫn sử dụng và chỉnh sửa file Markdown

### Xem file

Có thể mở trực tiếp bằng Visual Studio Code, GitHub, GitLab, Azure DevOps Wiki hoặc bất kỳ trình đọc Markdown nào.

### Quy ước cập nhật

1. Giữ nguyên các mã định danh như `S1-01`, `KPI-01`, `DLV-01` để dễ liên kết với backlog và báo cáo.
2. Khi thay đổi KPI, cập nhật đồng thời tại phần **Tiêu chí hoàn thành**, **Checklist nghiệm thu** và pipeline quality gate.
3. Thay `X giờ/scan` bằng baseline thực tế sau khi hoàn thành khảo sát Sprint 1.
4. Bổ sung cột **Owner**, **Start Date**, **Due Date** và **Status** nếu dùng tài liệu này để theo dõi thực thi.
5. Lưu prompt version, model version, scanner config và benchmark version để kết quả có thể tái lập.
6. Không đưa source code, secret, token, dữ liệu khách hàng hoặc PII chưa được redact vào báo cáo chia sẻ rộng.

### Quy ước trạng thái đề xuất

| Trạng thái | Ý nghĩa |
|---|---|
| `NOT_STARTED` | Chưa bắt đầu. |
| `IN_PROGRESS` | Đang thực hiện. |
| `BLOCKED` | Bị chặn; cần ghi rõ blocker và owner xử lý. |
| `IN_REVIEW` | Đang review kỹ thuật hoặc nghiệm thu. |
| `DONE` | Đã hoàn thành và có bằng chứng. |

---

## 11. Các thông tin cần chốt trước Kick-off

| Nội dung cần chốt | Gợi ý quyết định |
|---|---|
| Thời lượng từng sprint | Chốt theo số người, stack và số service mục tiêu. |
| Danh sách 20–30 repository đại diện | Bảo đảm đa dạng ngôn ngữ, mức độ quan trọng và exposure. |
| Ba service dùng để xác thực logic-bug | Ưu tiên auth, payment, user data hoặc admin API; có owner phối hợp. |
| Môi trường LLM | SaaS, private endpoint hay self-hosted; xác định data boundary và retention. |
| Người phê duyệt ground truth | AppSec lead hoặc hội đồng reviewer thống nhất. |
| Risk gate | Xác định mức điểm làm fail build, warning hoặc tạo ticket. |
| Hệ thống dashboard | Chọn nền tảng phù hợp hạ tầng hiện có và nguồn dữ liệu pipeline. |
| Kênh comment MR/PR | GitHub, GitLab, Bitbucket hoặc hệ thống nội bộ. |
| Chính sách accepted risk và suppression expiry | Xác định approver, thời hạn và lịch re-review. |

---

**Phiên bản tài liệu:** 1.0  
**Trạng thái:** Draft for Review  
**Chủ sở hữu tài liệu:** _Điền tên Project Owner_  
**Ngày cập nhật:** _YYYY-MM-DD_
