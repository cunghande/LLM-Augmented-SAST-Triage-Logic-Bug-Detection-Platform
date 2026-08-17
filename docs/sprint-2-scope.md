# Sprint 2 — Five-class logic-bug detection

## Mục tiêu

Sprint 2 mở rộng pipeline Sprint 1 bằng một detector Python chạy trên AST và
repository index có giới hạn. Detector tạo finding mới cho đúng năm lớp trong
kế hoạch gốc, sau đó đưa mọi finding qua cùng Safe Context, provider, policy và
reporter của Sprint 1.

Năm lớp được hỗ trợ:

1. missing authorization / IDOR (`CWE-639`);
2. mass assignment (`CWE-915`);
3. race condition / TOCTOU (`CWE-367`);
4. business-rule bypass (`CWE-840`);
5. insecure workflow (`CWE-841`).

Detector phải được bật tường minh bằng `--logic-detector python-five-logic`.
Phần FastAPI missing-authz chuyên biệt không nằm trên nhánh `main` của phạm vi
này.

## Ánh xạ với kế hoạch gốc

| Hạng mục | Hiện thực |
|---|---|
| S2-01 | AST Python, entrypoint Flask/FastAPI/Django, source–guard–sink trace và repository index source-free. |
| S2-02 | Khi chạm giới hạn file, ưu tiên đường dẫn auth, admin, payment, user, workflow và application route trước test/example. |
| S2-03 | Năm detector độc lập; prompt v12 dùng proof obligations, counter-evidence và phân biệt authentication/authorization, validation/atomicity, state transition hợp lệ. |
| S2-04 | Benchmark trên repository thật có ground truth; PoC trên service nội bộ vẫn cần AppSec/service owner phê duyệt. |
| S2-05 | Điểm rủi ro lưu cả tổng và năm thành phần theo công thức của plan. |
| S2-06 | Mỗi finding có remediation và validation checklist theo lớp lỗi. Patch vẫn là đề xuất cần developer review. |
| S2-07 | JSON/Markdown giữ risk level, risk score, evidence trace và remediation trong metadata an toàn. |

## Evidence và an toàn

Các kỹ thuật evidence mới được dùng lại từ phần nghiên cứu trước:

- khoanh vùng theo entrypoint và vùng code rủi ro;
- biểu diễn source → guard → sink thay vì chỉ gửi một dòng code;
- deterministic verification card trước khi LLM kết luận;
- prompt theo lớp lỗi với các negative distinction cụ thể;
- remediation và checklist gắn với nguyên nhân gốc.

Repository index và `LogicCandidate` chỉ giữ identifier, đường dẫn tương đối,
số dòng, loại flow và điểm số. Raw source chỉ tồn tại cục bộ trong context layer,
được sanitize trước khi provider nhận `TriageInput`.

## Chạy demo một dòng

Điều kiện: `.venv` đã kích hoạt và PowerShell đang ở
`D:\Code\target-repos`. Chỉ thay cả hai chỗ `<TEN_REPO>`:

```powershell
python -m sast_triage scan-and-triage --repository .\<TEN_REPO> --output-dir ..\triage-runs\<TEN_REPO>-sprint2 --analysis-backend native --module2 --logic-detector python-five-logic --provider fake
```

`triage-runs` và thư mục run con được CLI tự tạo. `fake` dùng để demo pipeline
offline; đổi thành `real` để dùng Modal đã cấu hình, hoặc `ollama` để dùng model
local.

## Benchmark và cách đọc số liệu

Script đánh giá:

```powershell
python scripts\benchmark_logic_bugs.py --ground-truth-root benchmarks\ExternalTargets\Real-Vuln-Benchmark\ground-truth --repos-root benchmarks\ExternalTargets\Real-Vuln-Benchmark\repos --output benchmarks\BenchmarkOutput\sprint2-five-logic\realvuln-full-v4-strix-evidence.json
```

Dataset là repository bên ngoài có ground truth review, không phải fixture tự
tạo. Chỉ location dương/âm được map rõ vào năm lớp mới tham gia confusion
matrix. Candidate ngoài các location đã gán nhãn được ghi là `unreviewed_candidates`;
không được tự coi là TP hoặc FP.

Kết quả v4 hiện tại trên 25 repository, 63 case phù hợp:

| Chỉ số | Giá trị |
|---|---:|
| TP / FP / FN / TN | 42 / 0 / 7 / 14 |
| Precision | 1,0000 |
| Recall | 0,8571 |
| F1 | 0,9231 |

Đây là kết quả detector xác định trên các location đã review, không phải kết
quả của LLM thật. Benchmark còn 377 candidate ngoài vùng nhãn cần review thủ
công trước khi công bố false-positive rate toàn repository.

## Điều kiện kết thúc

Phần kỹ thuật được coi là đạt khi full test và Ruff đạt, CLI sinh đủ năm lớp,
finding không bị mất khi provider lỗi, và artifact benchmark tái lập được.

Validation ngày 2026-08-17:

- full regression: `475 passed, 2 skipped`;
- Ruff: đạt trên `src`, `tests`, `modal_apps`, `scripts`;
- CLI integration với fake provider: sinh đủ năm lớp và không có processing error;
- benchmark v4 tái lập đúng TP/FP/FN/TN `42/0/7/14`.

Pilot LLM thật trên Modal/Qwen3-14B-AWQ cũng đã chạy 7 case có ground truth
(mỗi lớp một positive và hai detector false positive): 7/7 hoàn thành, không có
`TRIAGE_ERROR`, nhưng model abstain 6/7 case. Verdict dứt khoát duy nhất là một
mass-assignment TP đúng; coverage chỉ 14,29%. Vì mẫu decisive chỉ có một case,
không được dùng selective accuracy 100% để tuyên bố chất lượng model.

Sau khi thêm proof obligations và counter-evidence theo hướng evidence-first,
prompt v12 được chạy lại trên đúng năm positive case: verdict dứt khoát tăng từ
1/5 lên 2/5, cả hai đúng, coverage tăng 20% lên 40%, không có `TRIAGE_ERROR`.
Hai negative cũ được verifier loại trước LLM vì tìm thấy authorization guard thật.

Nghiệm thu tổ chức theo S2-04 chưa thể tự động hóa: cần AppSec/service owner
review ít nhất ba service thật, xác nhận TP/FP và chỉ chạy PoC trong môi trường
được phép. Vì vậy trạng thái nên báo là **engineering complete / formal
acceptance pending** cho tới khi có biên bản review đó.
