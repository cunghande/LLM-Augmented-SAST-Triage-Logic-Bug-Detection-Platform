# LLM-Augmented SAST Triage

Công cụ CLI hỗ trợ reviewer phân loại finding bảo mật từ Semgrep và Gitleaks.
Pipeline quét repository, chuẩn hóa finding, đọc context an toàn, tạo evidence
same-file/cross-file, gọi LLM, áp dụng policy bảo thủ và xuất báo cáo JSON cùng
Markdown.

> LLM chỉ đưa ra đề xuất. Hệ thống không tự động xóa hoặc làm mất finding; khi
> bằng chứng chưa đủ, kết quả được chuyển sang `MANUAL_REVIEW`.

## Phạm vi hiện tại

- Đầu vào chính: repository Python; Semgrep vẫn có thể quét thêm ngôn ngữ nếu
  ruleset được cấu hình, nhưng Evidence Engine và Module 2 hiện chỉ hiểu Python.
- Scanner: Semgrep Community Edition và Gitleaks.
- Provider: fake (offline), Ollama hoặc Qwen3-14B-AWQ trên Modal.
- Module 2: index Python theo component, symbol và call-site; trace source-to-sink
  cross-file có giới hạn.
- Xử lý tuần tự trong Sprint 1; không chạy finding song song.
- Notebook `.ipynb` chưa được phân tích trực tiếp; cần chuyển sang `.py` trước.

## Luồng hệ thống

```text
Repository
  → Semgrep + Gitleaks
  → NormalizedFinding
  → Safe context + redaction
  → Evidence Agent + Module 2 index
  → TriageInput
  → LLM verdict đã validate
  → PolicyDecision
  → report.json + report.md
```

`triage` và `scan-and-triage` dùng chung pipeline. Module 1 và Module 2 cũng
không phải hai pipeline cạnh tranh: Module 2 chỉ bổ sung finding/evidence
cross-file trước khi mọi finding đi qua cùng provider và policy.

## Bắt đầu nhanh trên Windows

### 1. Yêu cầu

- Python 3.11, 3.12 hoặc 3.13 (khuyến nghị 3.12).
- Git.
- Semgrep và Gitleaks trong `PATH`.
- Tài khoản Modal có credit/quota nếu chạy Qwen3-14B thật.

Kiểm tra:

```powershell
python --version
git --version
semgrep --version
gitleaks version
```

Nếu `python --version` không nằm trong khoảng 3.11–3.13, hãy cài Python 3.12
và bảo đảm lệnh `python` trỏ tới đúng bản đó trước khi tạo `.venv`.

Semgrep hỗ trợ cài bằng Python trên Windows. Gitleaks cung cấp binary Windows
tại trang Releases chính thức. Xem hướng dẫn chi tiết trong
[`docs/cli-usage.md`](docs/cli-usage.md).

### 2. Cài dự án

Mở PowerShell tại thư mục source:

```powershell
cd "D:\Code\AI security"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

Backend mặc định là `native`. Muốn thử Joern CPG, cần Docker Desktop và cài thêm
`python -m pip install -e ".[dev,joern]"`; xem [hướng dẫn Joern](docs/joern-analysis.md).

### 3. Xác thực Modal một lần

```powershell
python -m modal setup
python -m modal token info
```

Bỏ qua bước này nếu chỉ dùng `--provider fake` hoặc Ollama.

### 4. Chuẩn bị repository mục tiêu

Không clone target vào source công cụ. Đặt source, target và output thành ba thư
mục ngang hàng:

```text
D:\Code\
├── AI security\       source công cụ
├── target-repos\      repository cần quét
└── triage-runs\       CLI tự tạo artifact và báo cáo
```

Chỉ cần tự tạo `target-repos`; `triage-runs` được CLI tạo tự động:

```powershell
New-Item -ItemType Directory -Force "D:\Code\target-repos"
cd "D:\Code\target-repos"
git clone https://github.com/cunghande/Sequential-Recommender
```

Nếu repository đã tồn tại, không clone lại.

### 5. Chạy Qwen3-14B bằng một lệnh

Khi `.venv` đang được kích hoạt và PowerShell đang ở `target-repos`:

```powershell
python -m sast_triage Sequential-Recommender
```

Lệnh rút gọn tự chọn:

- `Qwen/Qwen3-14B-AWQ` trên Modal B200;
- Semgrep `p/python` và `p/security-audit`;
- Gitleaks built-in rules;
- Module 2 bật;
- output mới có timestamp, không ghi đè run cũ.

Output có dạng:

```text
D:\Code\triage-runs\Sequential-Recommender-qwen14b-YYYYMMDD-HHMMSSZ\
├── report.md
├── report.json
├── run-metadata.json
└── scanner-artifacts\
    ├── semgrep.json
    └── gitleaks.json
```

Cold start Modal có thể mất khoảng 4–7 phút. Chờ đến khi CLI in `[7/7]` và
`exit_code=0`.

## Đọc kết quả

- `report.md`: báo cáo chính cho reviewer/mentor.
- `report.json`: dữ liệu đầy đủ cho đánh giá tự động.
- `run-metadata.json`: commit, scanner version/config, model và binding.
- `scanner-artifacts/`: artifact nội bộ; không nên gửi ra ngoài vì có thể chứa
  source snippet hoặc dữ liệu nhạy cảm.

Policy action:

| Action | Ý nghĩa |
|---|---|
| `AUTO_ACCEPT` | Evidence đủ để chấp nhận lỗi thật theo policy. |
| `AUTO_REJECT` | Evidence đủ để xác định cảnh báo giả theo policy. |
| `MANUAL_REVIEW` | Chưa đủ evidence hoặc có bất đồng cần con người xem. |
| `TRIAGE_ERROR` | Finding gặp lỗi xử lý nhưng vẫn được giữ trong báo cáo. |

`LIKELY_TP`/`LIKELY_FP` là ý kiến của LLM; action phía trên mới là quyết định
cuối của hệ thống.

## Cấu trúc source

```text
.
├── src/sast_triage/
│   ├── application/          điều phối một CLI run và provider session
│   ├── analysis/             backend native/Joern CPG và projection an toàn
│   ├── runners/              chạy Semgrep/Gitleaks
│   ├── parsers/              scanner JSON → NormalizedFinding
│   ├── context/              safe read, AST, sanitize, evidence, Module 2
│   ├── pipeline/             xử lý một finding và toàn batch
│   ├── triage/               system prompt, provider, schema validation
│   ├── policy/               LLM verdict → system action
│   ├── reporting/            report JSON/Markdown an toàn
│   └── evaluation/           benchmark loader và metric
├── modal_apps/               entrypoint/runner Modal và benchmark
├── tests/                    unit, integration và security regression test
├── benchmarks/               dataset/artifact/báo cáo benchmark có kiểm soát
├── docs/                     tài liệu kiến trúc và vận hành
├── pyproject.toml            package, dependency và cấu hình test
└── README.md                 điểm bắt đầu này
```

Ba file nên đọc đầu tiên:

1. `src/sast_triage/entrypoint.py` — lệnh rút gọn và tóm tắt output.
2. `src/sast_triage/application/run.py` — điều phối scanner, Module 2, provider,
   checkpoint và reporter.
3. `src/sast_triage/pipeline/finding.py` — xử lý một finding từ context đến
   policy.

Xem thêm [`docs/code-map.md`](docs/code-map.md) để lần theo từng component.

## Kiểm thử

```powershell
cd "D:\Code\AI security"
.\.venv\Scripts\Activate.ps1
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m pytest -p no:cacheprovider -q --basetemp=.pytest-tmp-local
python -m ruff check src tests modal_apps
```

Trạng thái kiểm tra gần nhất: `446 passed, 2 skipped`; Ruff đạt. Validation thật
với Sequential-Recommender xử lý thành công 4/4 finding, 0 triage error, binding
`VERIFIED`, exit code `0`.

## Nguyên tắc bảo mật

- Raw source chỉ tồn tại trong context layer và không nằm trong public model.
- Secret thô từ Gitleaks không đi vào prompt, log hoặc report.
- Context gửi provider luôn được sanitize và coi là dữ liệu không đáng tin cậy.
- Prompt/response LLM thô không được lưu trong báo cáo.
- Output LLM bị ràng buộc JSON Schema và được validate lại.
- Provider lỗi không làm finding biến mất.
- Report mặc định không chứa đường dẫn repository tuyệt đối.

## Tài liệu

- [Hướng dẫn CLI đầy đủ](docs/cli-usage.md)
- [Thiết lập và chạy Joern CPG](docs/joern-analysis.md)
- [Báo cáo Joern v9 trên B200](benchmarks/BenchmarkOutput/qwen3-14b-awq-triage-benchmark-v9-joern-b200.md)
- [Baseline Joern v8 trước cải tiến](benchmarks/BenchmarkOutput/qwen3-14b-awq-triage-benchmark-v8-joern-b200.md)
- [Bản đồ mã nguồn](docs/code-map.md)
- [Luồng hệ thống Sprint 1](docs/sprint-1-system-flow.md)
- [Kiến trúc](docs/architecture.md)
- [Domain model](docs/domain-models.md)
- [Chính sách bảo mật](docs/security-policy.md)
- [Thiết lập Qwen3-14B trên Modal](docs/MODAL_QWEN14B_SETUP.md)
