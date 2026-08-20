# Bản đồ mã nguồn

Tài liệu này là điểm bắt đầu ngắn nhất để đọc dự án. Các tài liệu trong
`architecture.md` và `sprint-1-system-flow.md` chứa thiết kế chi tiết hơn.

## Luồng chạy duy nhất

```text
CLI
 └─ application/run.py
     ├─ runners/scanners.py       chạy Semgrep và Gitleaks
     ├─ parsers/                  tạo NormalizedFinding
     ├─ analysis/joern.py         tạo CPG và source-to-sink evidence
     ├─ logic/index.py            index riêng cho detector logic nghiệp vụ
     └─ pipeline/batch.py         xử lý tuần tự mọi finding
         └─ pipeline/finding.py
             ├─ context/          đọc, chọn scope, sanitize, tạo evidence
             ├─ triage/           tạo prompt, gọi provider, validate output
             ├─ policy/engine.py  quyết định cuối của hệ thống
             └─ reporting/        xuất JSON và Markdown
```

`triage` và `scan-and-triage` chỉ khác cách tạo scanner artifact. Cả hai phải đi
qua cùng `triage_batch`; không thêm pipeline thứ hai.

## Cấu trúc cấp cao

```text
D:\Code\
├── AI security\           source công cụ
│   ├── src/sast_triage/   package CLI và pipeline sản phẩm
│   ├── tests/             unit/integration/security regression test
│   ├── docs/              kiến trúc và hướng dẫn vận hành
│   ├── modal_apps/        compatibility entrypoint/benchmark Modal
│   ├── benchmarks/        OWASP dataset, artifact và kết quả đánh giá
│   ├── pyproject.toml     dependency và cấu hình test
│   └── README.md          onboarding cho người nhận source
├── target-repos\          checkout đầu vào; không thuộc source công cụ
└── triage-runs\           artifact/report; không thuộc source công cụ
```

`benchmarks/` không phải code runtime. `BenchmarkPython` là dataset có ground
truth; `BenchmarkRun` chứa scanner artifact; `BenchmarkOutput` chứa báo cáo đã
được sinh. Không dùng test fixture trong `tests/fixtures` để công bố precision,
recall hoặc F1.

## Trách nhiệm từng package

| Package | Chứa gì | Không nên chứa |
|---|---|---|
| `application` | Điều phối một CLI run, provider session, artifact binding | Dataflow hoặc policy rule |
| `runners` | Lệnh scanner, version và config ID | Parse finding |
| `parsers` | Scanner JSON → domain model | Đọc source repository |
| `analysis` | Joern CPG, source/sink dataflow và call graph | Raw source projection hoặc policy rule |
| `context` | Safe source access, sanitize và evidence projection | Gọi LLM hoặc quyết định policy |
| `triage` | Prompt/provider/output validation | Raw source hoặc scanner artifact |
| `policy` | Chuyển model opinion thành system action | Gọi provider |
| `pipeline` | Thứ tự xử lý và error recovery | Logic scanner riêng lẻ |
| `reporting` | Defense-in-depth trước khi ghi report | Prompt/response thô |
| `evaluation` | Dataset mapping và metric | Fixture dùng làm benchmark model |

## Cách đọc package `context`

`context` lớn nhất vì đây là security boundary. Đọc theo thứ tự:

1. `reader.py` — resolve path và chỉ đọc file nằm trong repository.
2. `selection.py` — chọn line window có giới hạn; không tự phân tích dataflow.
3. `sanitizer.py` — redact và tạo `SanitizedContext`.
4. `evidence_agent.py` — mở rộng Joern evidence bằng ba query có ngân sách.
5. `evidence_service.py` — projection allowlist duy nhất gửi provider.

Phân tích cấu trúc, call graph và source-to-sink thuộc duy nhất về `analysis/joern.py`.
Index trong `logic/index.py` chỉ phục vụ detector logic nghiệp vụ và không thay Joern.

Module 1 và Module 2 không chạy thành hai agent cạnh tranh. Module 2 chỉ bổ sung
evidence hoặc finding đã chứng minh được; mọi kết quả vẫn đi qua cùng pipeline,
provider và policy theo thứ tự.

## Khi cần thay đổi một tính năng

| Muốn thay đổi | File bắt đầu |
|---|---|
| Thêm option CLI | `cli.py`, sau đó `application/run.py` |
| Thêm Semgrep ruleset/config | `runners/scanners.py` |
| Map field scanner mới | `parsers/semgrep.py` hoặc `parsers/gitleaks.py` |
| Thêm source/sink Python | `analysis/joern.py` |
| Cải thiện assignment/dataflow | `analysis/joern.py` |
| Cải thiện cross-file/call graph | `analysis/joern.py` |
| Cải thiện detector logic nghiệp vụ | `logic/analyzer.py`, `logic/index.py` |
| Đổi rubric cho LLM | `triage/system_prompt.py` |
| Đổi payload gửi LLM | `triage/prompt_builder.py` |
| Đổi JSON Schema Qwen | `triage/modal_provider.py` |
| Đổi image/model/GPU Modal | `triage/qwen14b_modal_app.py` |
| Đổi ngưỡng TP/FP/review | `policy/engine.py` |
| Đổi report | `reporting/json_reporter.py`, `markdown_reporter.py` |
| Đổi benchmark Modal | `modal_apps/qwen14b_benchmark.py` |

## Contract không được phá vỡ

Sáu domain model public trong `models.py` phải tiếp tục tách biệt:
`NormalizedFinding`, `SanitizedContext`, `TriageInput`, `TriageDecision`,
`PolicyDecision` và `TriageResult`. Raw source chỉ được tồn tại trong local scope
của context layer; không thêm raw source vào model, log, prompt hoặc report.
