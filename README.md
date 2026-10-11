# LLM-Augmented SAST Triage

Công cụ CLI hỗ trợ reviewer phân loại finding bảo mật từ Semgrep và Gitleaks.
Pipeline quét repository, chuẩn hóa finding, đọc context an toàn, tạo evidence
same-file/cross-file, gọi LLM, áp dụng policy bảo thủ và xuất báo cáo JSON,
Markdown cùng HTML độc lập.

> LLM chỉ đưa ra đề xuất. Hệ thống không tự động xóa hoặc làm mất finding; khi
> bằng chứng chưa đủ, kết quả được chuyển sang `MANUAL_REVIEW`.

## Phạm vi hiện tại

- Đầu vào chính: repository Python; Semgrep vẫn có thể quét thêm ngôn ngữ nếu
  ruleset được cấu hình, nhưng Evidence Engine và Module 2 hiện chỉ hiểu Python.
- Scanner: Semgrep Community Edition và Gitleaks.
- Provider: fake (offline), Ollama hoặc Qwen3-14B-AWQ trên Modal.
- Module 2: index Python theo component, symbol, call-site và `FunctionSummary`
  source-free (parameter→sink, parameter→return, control); trace source-to-sink
  cross-file có giới hạn và nhận diện entrypoint Flask/FastAPI/Django thông dụng.
- Sprint 2: detector `python-idor-business-logic` tập trung vào missing
  authorization/IDOR và business-rule bypass. Các pattern ưu tiên là truy cập
  tài liệu khác chủ sở hữu, giá/số lượng giỏ hàng không đáng tin cậy và truy vấn
  danh sách thiếu giới hạn phân trang; mỗi candidate có trace, risk factors và
  remediation an toàn.
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
  → report.json + report.html
```

`triage` và `scan-and-triage` dùng chung pipeline. Module 1 và Module 2 cũng
không phải hai pipeline cạnh tranh: Module 2 bổ sung evidence cross-file cho
finding của scanner trước khi mọi finding đi qua cùng provider và policy.
Discovery bounded của Module 2 được bật mặc định; dùng
`--no-module2-discovery` khi cần chạy benchmark chỉ-scanner.

`FunctionSummary` là nền cho Sprint 2/3: Sprint 2 dùng nó để chứng minh flow
cross-file tốt hơn; Sprint 3 có thể dùng lại cùng index để mở rộng discovery.
Summary chỉ chứa identifier, đường dẫn tương đối, dòng và loại flow/control;
không chứa source code hoặc literal bí mật.

## Chạy bằng Docker sau khi clone (khuyến nghị)

Máy mới chỉ cần Git, Docker Desktop/Engine đang chạy Linux containers và khoảng
8 GB RAM dành cho Docker. Image ứng dụng đã chứa Python 3.12, Semgrep 1.170.0,
Gitleaks 8.30.1 và Docker CLI; Compose build riêng Joern 4.0.600 đã pin checksum.

Windows PowerShell:

```powershell
git clone <URL_REPOSITORY_CUA_DU_AN> sast-triage
cd sast-triage
.\scripts\run-docker.ps1 -TargetRepository "D:\Code\target-repo"
```

Linux/macOS:

```bash
git clone <URL_REPOSITORY_CUA_DU_AN> sast-triage
cd sast-triage
chmod +x scripts/run-docker.sh
./scripts/run-docker.sh /absolute/path/to/target-repo
```

Script tự động:

1. build image ứng dụng và image Joern;
2. kiểm tra Docker, Joern, Semgrep và Gitleaks;
3. mount target read-only;
4. tạo output mới có timestamp trong `triage-runs/`;
5. chạy Joern source-to-sink, Semgrep, Gitleaks và logic detector.

Mặc định dùng `provider=fake` để kiểm tra end-to-end mà không cần tài khoản ngoài.
Để dùng Qwen trên Modal, đặt `MODAL_TOKEN_ID`, `MODAL_TOKEN_SECRET` trong environment
rồi chạy:

```powershell
.\scripts\run-docker.ps1 -TargetRepository "D:\Code\target-repo" -Provider real
```

```bash
./scripts/run-docker.sh /absolute/path/to/target-repo "" real
```

Không commit Modal credential. Có thể copy `.env.example` thành `.env` khi muốn gọi
Compose trực tiếp. Compose mount Docker socket để app tạo container Joern sibling;
chỉ chạy cấu hình này với source dự án mà bạn tin cậy.

## Chạy CLI native

Phần này hướng dẫn chạy trực tiếp bằng Python thay vì app container. Docker vẫn
phải hoạt động vì Joern chạy trong container riêng.

### 1. Yêu cầu chung

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

### 2. Cài dự án trên Windows

Mở PowerShell tại thư mục source:

```powershell
cd "D:\Code\AI security"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

Joern CPG là backend phân tích duy nhất và cần Docker Desktop; dependency client
đã nằm trong cài đặt chuẩn. Xem [hướng dẫn Joern](docs/joern-analysis.md).

### 3. Xác thực Modal một lần

```powershell
python -m modal setup
python -m modal token info
```

Bỏ qua bước này nếu chỉ dùng `--provider fake` hoặc Ollama.

### 4. Chuẩn bị repository mục tiêu trên Windows

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

### 5. Chạy bằng CLI trên Windows

Khi `.venv` đang được kích hoạt và PowerShell đang ở `target-repos`, chỉ cần
một lệnh để chạy Qwen, Joern, Module 2 discovery và logic detector:

```powershell
python -m sast_triage Sequential-Recommender
python -m sast_triage benchmarks
python -m sast_triage extremely-vulnerable-flask-app
```

### 6. Chạy bằng CLI trên Linux

Mỗi khi mở terminal mới, kích hoạt lại virtual environment trước khi chạy CLI.
Ví dụ dưới đây giả định source công cụ ở `/home/cungdv/code/AI security` và
repository mục tiêu ở `/home/cungdv/code/target-repos`.

```bash
# Bước 1: Kích hoạt virtual environment (bắt buộc cho mỗi terminal mới)
source "/home/cungdv/code/AI security/.venv/bin/activate"

# Bước 2: Chuyển đến thư mục chứa repository mục tiêu
cd /home/cungdv/code/target-repos

# Bước 3: Chạy triage đầy đủ cho repository cần quét
python -m sast_triage extremely-vulnerable-flask-app
```

Lệnh rút gọn ở trên tự bật Qwen3-14B-AWQ trên Modal, Semgrep, Gitleaks, Joern,
Evidence Agent, same-file/cross-file discovery và detector logic IDOR/business
rule. Cần hoàn tất `python -m modal setup` và bảo đảm Docker Engine đang chạy.

Lệnh này tự chọn:

- `Qwen/Qwen3-14B-AWQ` trên Modal B200;
- Semgrep `p/python` và `p/security-audit`;
- Gitleaks built-in rules;
- Module 2 index, cross-file discovery và detector IDOR/business logic;
- decision cache 7 ngày tại thư mục `triage-cache/<repository>` cạnh
  `target-repos`;
- telemetry cache/token/latency và chi phí B200 ước tính 6,25 USD/GPU-giờ;
- output mới có timestamp, không ghi đè run cũ.

Đơn giá là snapshot phục vụ ước tính và có thể ghi đè bằng
`--provider-cost-per-hour-usd`; số tiền trong report không phải hóa đơn Modal.

Nếu chỉ muốn quét scanner cơ bản, có thể tắt discovery và detector:

```powershell
python -m sast_triage Sequential-Recommender `
  --no-module2-discovery `
  --logic-detector off
```

Output có dạng:

```text
D:\Code\triage-runs\Sequential-Recommender-qwen14b-YYYYMMDD-HHMMSSZ\
├── report.json
├── report.html
├── run-metadata.json
└── scanner-artifacts\
    ├── semgrep.json
    └── gitleaks.json
```

Cold start Modal có thể mất khoảng 4–7 phút. Chờ đến khi CLI in `[7/7]` và
`exit_code=0`.

## Đọc kết quả

- `report.html`: báo cáo security trực quan, có thể mở trực tiếp hoặc in thành PDF.
- `report.json`: dữ liệu đầy đủ cho đánh giá tự động.
- `run-metadata.json`: commit, scanner version/config, model và binding.
- `scanner-artifacts/`: artifact nội bộ; không nên gửi ra ngoài vì có thể chứa
  source snippet hoặc dữ liệu nhạy cảm.

Policy action:

| Action | Ý nghĩa |
|---|---|
| `LIKELY_TP` | Có khả năng là lỗ hổng thật; vẫn cần reviewer xác nhận. |
| `FP_CANDIDATE` | Ứng viên cảnh báo giả có evidence phù hợp; không tự động đóng. |
| `MANUAL_REVIEW` | Chưa đủ evidence hoặc có bất đồng cần con người xem. |
| `TRIAGE_ERROR` | Finding gặp lỗi xử lý nhưng vẫn được giữ trong báo cáo. |

`LIKELY_TP`/`LIKELY_FP` là ý kiến của LLM; action phía trên mới là quyết định
cuối của hệ thống.

## Cấu trúc source

```text
.
├── src/sast_triage/
│   ├── application/          điều phối một CLI run và provider session
│   ├── analysis/             backend Joern CPG và projection an toàn
│   ├── runners/              chạy Semgrep/Gitleaks
│   ├── parsers/              scanner JSON → NormalizedFinding
│   ├── context/              safe read, AST, sanitize, evidence, Module 2
│   ├── pipeline/             xử lý một finding và toàn batch
│   ├── triage/               system prompt, provider, schema validation
│   ├── policy/               LLM verdict → system action
│   ├── reporting/            report JSON/Markdown/HTML an toàn
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

Trạng thái test và benchmark gần nhất được ghi tại
[`docs/sprint-2-scope.md`](docs/sprint-2-scope.md) để tránh giữ số liệu cũ ở nhiều
nơi.

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
- [Phạm vi và benchmark Sprint 2](docs/sprint-2-scope.md)
- [Trạng thái triển khai Sprint 2](docs/sprint-2-status.md)
- [Trạng thái triển khai Sprint 3](docs/sprint-3-status.md)
- [Kế hoạch triển khai hiện tại](docs/current-project-plan.md)
- [Threat model](docs/threat-model.md)
- [Thiết lập và chạy Joern CPG](docs/joern-analysis.md)
- [Runbook debug toàn pipeline](docs/debug-runbook.md)
- [Chính sách cache và lưu trữ dữ liệu LLM](docs/llm-cache-retention-policy.md)
- [Bản đồ mã nguồn](docs/code-map.md)
- [Luồng hệ thống Sprint 1](docs/sprint-1-system-flow.md)
- [Kiến trúc](docs/architecture.md)
- [Domain model](docs/domain-models.md)
- [Chính sách bảo mật](docs/security-policy.md)
- [Thiết lập Qwen3-14B trên Modal](docs/MODAL_QWEN14B_SETUP.md)
