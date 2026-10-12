# Báo cáo Kiểm toán Hiện trạng Mã nguồn (Source Code Audit Report)

**Ngày thực hiện:** 2026-10-12  
**Mục tiêu:** Kiểm toán chi tiết hiện trạng các thành phần của hệ thống SAST Triage Platform phục vụ viết báo cáo nghiên cứu và cải tiến độ tin cậy.  
**Nguyên tắc:** Mỗi nhận định đều dựa trên mã nguồn thực tế (file:hàm/dòng), phân loại chính xác giữa:
- **Đã cài + có test**
- **Đã cài nhưng chưa test**
- **Chưa có**

---

## 1. Kiểm toán Hiện trạng theo Từng Mục (A - D)

### Phần A. Khung Báo Cáo Nghiên Cứu
| Mã | Nội dung | Hiện trạng | Vị trí mã nguồn | Đánh giá & Ghi chú |
|---|---|---|---|---|
| **A1** | Khung bài báo `paper.md` và `claims.md` | **Chưa có** | `docs/paper/` (chưa tồn tại) | Cần khởi tạo cấu trúc paper chuẩn: Abstract, Intro, Related Work, Threat Model, System Design, Experimental Setup, Results, Ablation, Limitations, Reproducibility. |
| **A2** | Script trực quan hóa (bảng, matplotlib charts) | **Chưa có** | `scripts/` (chưa có script vẽ chart) | Cần script đọc kết quả thật sinh ra reliability diagram, bảng so sánh baseline, latency chart. |

---

### Phần B. Minh Chứng Độ Tin Cậy & Bộ Đánh Giá
| Mã | Nội dung | Hiện trạng | Vị trí mã nguồn | Đánh giá & Ghi chú |
|---|---|---|---|---|
| **B1** | Bộ đánh giá có nhãn (Benchmark Dataset) | **Đã cài framework + có test; chưa có dataset JSON thật** | `src/sast_triage/evaluation/benchmark.py:load_benchmark`<br>`src/sast_triage/evaluation/metrics.py:evaluate_batch`<br>`tests/test_evaluation.py` | Framework load benchmark, chia split (development, calibration, held_out) đã có. Kho dữ liệu `benchmarks/Real-Vuln-Benchmark` có sẵn ground-truth thật từ OWASP PyGoat, DVPWA, VAmPI,... Cần tạo file `benchmark.json` chuẩn hóa từ các repo này kèm nhãn TP/FP và split theo repo. |
| **B2** | So sánh baseline (Scanner-only, LLM-only, Full) | **Đã cài một phần, chưa có script so sánh baseline** | `scripts/benchmark_realvuln_joern.py`<br>`src/sast_triage/evaluation/regression.py` | Có script chạy pipeline qua repo, nhưng chưa có script so sánh 3 baseline trên cùng 1 dataset để đo Precision, Recall, F1, % Manual Review. |
| **B3** | Calibration model_confidence (reliability diagram, ECE) | **Chưa có** | `src/sast_triage/evaluation/metrics.py` | `metrics.py` mới chỉ tính precision, recall, f1, false_negative_rate. Chưa có hàm tính ECE (Expected Calibration Error) hay calibration curve. |
| **B4** | Kiểm toán False Negative & Shadow Mode | **Chưa có** | `src/sast_triage/policy/engine.py:apply_policy` | Chưa có cơ chế shadow mode ghi nhận quyết định giả định trước khi enforce, chưa có script sampling 5-10% các finding bị gán `FP_CANDIDATE`. |
| **B5** | Red-team Prompt Injection Test (>= 15 mẫu) | **Đã cài 1 phần + có test (1 mẫu escape tag)** | `src/sast_triage/triage/prompt_builder.py:_build_user_message:117`<br>`tests/test_prompt_and_output.py:test_prompt_builder_escapes_delimiter_spoofing` | Đã có logic escape `<` thành `\u003c` để chống giả thẻ `</UNTRUSTED_INPUT_JSON>`. Tuy nhiên chưa có test suite >= 15 ca red-team kiểm thử: injection qua comment, string, biến, chỉ thị ghi đè verdict. |
| **B6** | Canary Secret Leak Test & Mở rộng Redaction | **Đã cài + có test (nhưng thiếu pattern mở rộng & entropy)** | `src/sast_triage/redaction.py:redact_exact_secret`<br>`src/sast_triage/context/sanitizer.py:sanitize_extracted_context:68-75`<br>`tests/test_redaction.py` | Canary test cho gitleaks đã có. Nhưng regex `_CRED_QUOTED_REGEX` bỏ sót các tên biến quan trọng: `db_pass`, `auth_key`, `secret_key`, `api_secret`. Chưa có phát hiện chuỗi entropy cao. |
| **B7** | Đo độ phủ Joern trên Python | **Đã cài backend + có test; chưa có script đo độ phủ** | `src/sast_triage/analysis/joern.py:JoernAnalysisBackend`<br>`tests/test_analysis_backends.py` | Joern backend hoạt động tốt, nhưng chưa có script thống kê tỷ lệ CPG build thành công, tỷ lệ rỗng/lỗi, tỷ lệ timeout. |
| **B8** | Chi phí & độ trễ thật (Token, time/finding) | **Đã cài telemetry thô, chưa có script phân tích chi phí** | `src/sast_triage/triage/telemetry.py`<br>`src/sast_triage/cache/decision_cache.py` | Telemetry đo duration có ghi nhận. Chưa đo số token prompt/completion thực tế, chi phí USD, hiệu quả hit cache. Con số 70-80% token reduction trong tài liệu chưa có bằng chứng. |
| **B9** | Case studies (3-5 finding minh họa) | **Chưa có document hóa** | `benchmarks/BenchmarkOutput/realvuln-v2-joern/runs/` | Các report JSON từ PyGoat có sẵn nhiều finding thực tế, nhưng chưa được trích dẫn làm 4 ca điển hình: TP đúng, FP đúng, ca hệ thống sai, ca chuyển MANUAL_REVIEW. |
| **B10** | Tài liệu tin cậy & Data Flow | **Đã cài một phần** | `Dockerfile`<br>`compose.yaml`<br>`docs/threat-model.md` | Đã có Dockerfile, compose, threat model. Cần đồng bộ các cam kết trust boundary và loại bỏ các tuyên bố chưa chứng minh. |
| **B11** | Sandbox cho scanner & xuất SARIF | **Chưa có** | `src/sast_triage/reporting/` | Hiện tại mới hỗ trợ xuất JSON, MD, HTML. Chưa hỗ trợ format chuẩn SARIF cho CI/CD. |

---

### Phần C. Cải Tiến Độ Chính Xác Của Model Triage
| Mã | Nội dung | Hiện trạng | Vị trí mã nguồn | Đánh giá & Ghi chú |
|---|---|---|---|---|
| **C1** | Đưa luật tất định từ prompt vào code | **Đã cài một phần + có test; còn nhiều luật ở prompt** | `src/sast_triage/policy/engine.py:_tp_has_deterministic_support:106-160`<br>`src/sast_triage/triage/system_prompt.py:116-149` | Một số luật (source_user_controlled, source_reaches_sink) đã có ở code. Nhưng các luật: gán đè hằng số -> LIKELY_FP, MD5/SHA1 mục đích sử dụng (checksum vs security) vẫn phụ thuộc mô tả dài dòng trong prompt v15. |
| **C2** | Output có cấu trúc, evidence-first | **Đã cài dạng text tự do + có test; chưa có cấu trúc chuẩn** | `src/sast_triage/models.py:TriageDecision:343-354`<br>`src/sast_triage/triage/output_validator.py` | `TriageDecision.evidence` hiện là `list[str]`. Model có thể sinh verdict trước rồi bịa text evidence. Cần đưa `StructuredEvidence(file, line, symbol, role)` và đặt evidence lên trước verdict trong schema. |
| **C3** | Verifier tất định sau LLM (Post-LLM Verifier) | **Chưa có** | `src/sast_triage/context/local_verifier.py`<br>`src/sast_triage/policy/engine.py` | `local_verifier.py` hiện chạy TRƯỚC LLM để đưa fact vào snippet. Chưa có bộ verifier chạy SAU LLM để đối chiếu: mọi (file, line, symbol) LLM trích dẫn có tồn tại trong context không; nếu LLM bảo "có sanitizer" mà inspect_security_control không thấy thì hạ về `MANUAL_REVIEW`. |
| **C4** | Siết cổng an toàn hướng FP (Tighten FP Gate) | **Đã cài nhưng còn lỗ hổng logic (`!= False`) + có test** | `src/sast_triage/policy/engine.py:394`<br>`src/sast_triage/policy/engine.py:402-404` | **Lỗ hổng logic quan trọng:** Tại dòng 394, `if _fp_has_deterministic_support(...) is False:` cho phép giá trị `None` (chưa biết / không có cấu trúc) đi qua thành `FP_CANDIDATE` cho các finding Low/Medium! Cần đổi thành yêu cầu `is True` tường minh. Ngoài ra `BOUNDED_LOCAL_NEGATIVE_PROOF` cần áp dụng cả cho Medium đối với các CWE nguy hiểm (CWE-89, 78, 22, 502). |
| **C5** | Kết quả tool 3 trạng thái (FOUND / NOT_FOUND_COMPLETE / UNKNOWN) | **Đã cài 2 trạng thái + None; chưa chuẩn hóa 3 trạng thái có lý do** | `src/sast_triage/analysis/base.py:GraphEvidence:48-67`<br>`src/sast_triage/context/evidence_service.py` | `GraphEvidence` dùng các cờ bool hoặc None rải rác (`source_reaches_sink: bool | None`, `path_complete: bool`). Khi Joern không tìm thấy hàm hoặc CPG thiếu, hiện trạng không phân biệt rõ ràng giữa "chắc chắn không có đường" và "không phân tích được hàm mục tiêu". Cần enum 3 trạng thái rõ ràng. |
| **C6** | Tách prompt chuyên biệt theo nhóm lỗi | **Chưa có (đang dùng monolithic prompt v15)** | `src/sast_triage/triage/system_prompt.py:build_system_message` | Prompt hiện tại là 1 prompt v15 gom chung SQLi, Path traversal, Insecure hash, Logic IDOR, Cookie flags,... gây loãng attention. |
| **C7** | Suy luận bằng tiếng Anh, tóm tắt tiếng Việt sau | **Chưa có** | `src/sast_triage/triage/system_prompt.py:150-156` | Model đang phải vừa suy luận bảo mật vừa trực tiếp sinh tiếng Việt trong 1 lượt gọi, dễ làm giảm chất lượng suy luận logic. |
| **C8** | Tăng độ tin cậy ca khó (Self-consistency / Cascade) | **Chưa có** | `src/sast_triage/triage/` | Hiện tại chạy 1 lần suy luận duy nhất (greedy/temperature=0). Chưa có self-consistency hay cascade lên model mạnh hơn. |
| **C9** | Chống prompt injection nhiều lớp (Injection Detection Flag) | **Đã cài 1 lớp (escape tag) + có test; chưa có lớp heuristic/schema** | `src/sast_triage/triage/prompt_builder.py:117` | Mới có escape tag `<` và `>`. Chưa có bộ phát hiện mẫu injection trong snippet mã nguồn để gắn cờ tăng rủi ro / buộc `MANUAL_REVIEW`. |
| **C10**| Few-shot retrieval ví dụ tương tự | **Chưa có** | `src/sast_triage/triage/prompt_builder.py` | Chưa có cơ chế nhúng few-shot tương tự theo CWE. |

---

### Phần D. Thiết Kế Lại Agent
| Mã | Nội dung | Hiện trạng | Vị trí mã nguồn | Đánh giá & Ghi chú |
|---|---|---|---|---|
| **D1** | Đổi tên/mô tả thực tế: Bounded Evidence Collector + LLM Reasoner | **Đã cài nhưng đặt tên sai thực tế** | `src/sast_triage/context/evidence_agent.py:GraphEvidenceExpansionAgent:22-85` | Class mang tên `GraphEvidenceExpansionAgent` nhưng thực chất chỉ là workflow tất định 100% với hàm `_next_tool()` chạy bằng chuỗi if-elif, không có LLM chọn tool. Cần đổi tên và mô tả tài liệu cho đúng bản chất kỹ thuật: "Bounded Evidence Collector (Tầng 1)" và "LLM Triage Reasoner (Tầng 2)". |
| **D2** | Evidence Schema theo nhóm lỗi thay cho `_sufficient()` chung | **Đã cài điều kiện chung + có test; chưa có schema từng nhóm** | `src/sast_triage/context/evidence_agent.py:_sufficient:60-71` | `_sufficient()` hiện tại kiểm tra chung cho mọi finding (trừ intrinsic): chỉ đòi `source_type is not None`, `source_reaches_sink is True`, `path_complete`, `reachability_resolved`. Chưa có điều kiện dừng riêng cho IDOR, Mass assignment, TOCTOU, Crypto. |
| **D3** | Bổ sung AST bounded tool cho lỗi logic | **Đã cài trong Logic Bug Analyzer, chưa tích hợp thành tool evidence chuẩn** | `src/sast_triage/logic/analyzer.py`<br>`src/sast_triage/logic/index.py` | Module 2 logic analyzer đã có AST visit tìm decorator auth, model schema, lock. Cần chuẩn hóa thành tool có thể truy vấn kèm kết quả 3 trạng thái. |
| **D4** | Vòng NEEDS_EVIDENCE có giới hạn cho LLM | **Chưa có** | `src/sast_triage/triage/` | LLM hiện chỉ trả về LIKELY_TP, LIKELY_FP, NEEDS_REVIEW trong 1 shot. Chưa hỗ trợ LLM trả về yêu cầu bằng chứng bổ sung từ allowlist. |
| **D5** | Truyền sự kiện kèm nguồn gốc (Provenance) rõ ràng | **Đã cài một phần (provenance tuple) + có test** | `src/sast_triage/context/evidence_models.py:EvidencePackage:129`<br>`src/sast_triage/analysis/base.py:GraphEvidence:66` | Đã có trường `provenance: tuple[str, ...]` nhưng chưa tách bạch từng fact với tool/truy vấn cụ thể khi render sang prompt. |
| **D6** | Ngân sách động thay cho 5 bước/60s cố định | **Chưa có** | `src/sast_triage/context/evidence_agent.py:31-36` | Các tham số `max_iterations=5, max_tool_calls=5, timeout_seconds=60.0` hiện là hardcoded mặc định. |
| **D7** | Tracing từng bước thu thập bằng chứng | **Đã cài một phần (tool_names tuple) + có test** | `src/sast_triage/context/evidence_agent.py:GraphEvidenceExpansionResult:14-20` | Đã lưu số lượng và tên các tool đã gọi, nhưng chưa lưu chi tiết input query và trạng thái từng bước để debug/audit. |
| **D8** | Tối ưu dựng CPG & Cache kết quả tool | **Đã cài trong joern backend + có test** | `src/sast_triage/analysis/joern.py:JoernAnalysisBackend` | Đã có cache CPG theo commit và tái sử dụng CPG session cho toàn bộ finding của repo. Cần kiểm tra hiệu năng thực tế. |

---

## 2. Danh Sách Tuyên Bố Sai Lệch / Cần Sửa Trong Tài Liệu

| Tài liệu / Vị trí | Tuyên bố hiện tại | Thực tế trong code | Hành động khắc phục |
|---|---|---|---|
| `docs/domain-models.md`<br>`docs/architecture.md`<br>`docs/sprint-1-scope.md` | Dùng tên `AUTO_SUPPRESS_FP` | `src/sast_triage/models.py:102`<br>Dùng tên `FP_CANDIDATE` | Đồng bộ toàn bộ tài liệu về tên `FP_CANDIDATE`. Làm rõ đây là nhãn phân loại hệ thống, không tự ý xóa bỏ finding khỏi báo cáo. |
| `docs/architecture.md`<br>`docs/xay-dung-bai-toan-sprint-1-2.md` | "GraphEvidenceExpansionAgent: Agent 2 tầng chọn tool mở rộng CPG" | `src/sast_triage/context/evidence_agent.py:73-84`<br>Workflow tất định (`if-elif`) hoàn toàn không có LLM chọn tool. | Đổi tên/mô tả thành "Bounded Evidence Collector (Tầng 1)" và "LLM Triage Reasoner (Tầng 2)". Không dùng từ "agent" gây hiểu lầm. |
| `docs/xay-dung-bai-toan-sprint-1-2.md`<br>`LLM-Augmented SAST Project Plan.md` | "Giảm 70-80% token so với gửi toàn bộ file" | Chưa từng có script đo lường số token trước và sau trên tập dữ liệu chuẩn. Con số là ước tính lý thuyết. | Xóa bỏ tuyên bố % cụ thể; ghi nhận "CHƯA ĐO" cho đến khi script B8 đo đạc chính thức trên repo thật. |
| `docs/security-policy.md`<br>`README.md` | "Hallucination-resistant", "An toàn tuyệt đối trước prompt injection" | Chỉ có rubric prompt và escape thẻ `<`/`>`. LLM vẫn có thể suy luận sai (hallucination) nếu thiếu post-verifier, và prompt injection trong comment vẫn có thể tác động đến reasoning. | Sửa thành: "Áp dụng phòng thủ theo chiều sâu (defense-in-depth): escape tag JSON, fail-closed policy gates, và kiểm tra bằng chứng tất định". Bỏ các từ "tuyệt đối" hoặc "hoàn toàn chống ảo giác". |

---

## 3. Thứ Tự Triển Khai Tiếp Theo (Theo Kế Hoạch Đã Định)

1. **Khởi tạo Khung Báo Cáo & Sổ Tuyên Bố:**
   - Tạo `docs/paper/paper.md` và `docs/paper/claims.md`.
   - Tạo nhật ký `docs/progress.md`.
2. **Thực hiện Nhóm P0 theo thứ tự nghiêm ngặt:**
   - **B1 & B2:** Xây dựng dataset benchmark thực tế từ `benchmarks/Real-Vuln-Benchmark` (OWASP PyGoat, DVPWA, VAmPI,...) chia tách theo repo (`development`, `calibration`, `held_out`), tạo script chạy baseline so sánh (Scanner-only, LLM-only, Full system).
   - **C5 & C4:** Cài đặt 3 trạng thái cho kết quả tool (FOUND / NOT_FOUND_COMPLETE / UNKNOWN), siết chặt cổng FP tại `engine.py` (yêu cầu `is True` tường minh, siết negative proof cho Medium các CWE nguy hiểm).
   - **C2, C3, C1:** Chuẩn hóa StructuredEvidence cho output LLM, cài đặt verifier tất định sau LLM, chuyển các luật tất định từ prompt vào code.
   - **B3, B4, B5:** Đo calibration (reliability diagram, ECE), kiểm toán False Negative & shadow mode, tạo bộ 15 mẫu Red-Team Prompt Injection test.
   - **D1 & D2:** Chuẩn hóa tên Bounded Evidence Collector + LLM Reasoner, cài đặt Evidence Schema theo từng nhóm lỗi.
