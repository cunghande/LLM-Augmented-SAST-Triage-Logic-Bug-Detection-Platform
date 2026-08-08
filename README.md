# LLM-Augmented SAST Triage

Công cụ CLI quét Python repository bằng Semgrep và Gitleaks, trích xuất ngữ cảnh
an toàn, dùng LLM để đề xuất phân loại và áp dụng policy thận trọng trước khi
xuất báo cáo JSON/Markdown.

LLM chỉ hỗ trợ reviewer. Công cụ không tự động xóa hoặc đóng finding.

## Bắt đầu nhanh

Yêu cầu:

- Python 3.11, 3.12 hoặc 3.13;
- Semgrep và Gitleaks có trong `PATH` nếu dùng `scan-and-triage`;
- Ollama chỉ cần thiết khi muốn dùng LLM cục bộ;
- tài khoản Modal đã chạy `python -m modal setup` khi dùng `--provider real`.

Thiết lập trên PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Chạy smoke test không gọi LLM thật:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output `
  --provider fake
```

Chạy bằng Ollama:

```powershell
ollama pull qwen3:8b
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output `
  --provider ollama
```

Chạy Qwen3-14B-AWQ trên Modal (không cần endpoint/model env):

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output-modal `
  --provider real
```

Nếu Modal hết quota/credit, CLI giữ checkpoint an toàn. Sau khi khởi động
Ollama, tiếp tục các finding chưa xong bằng:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output-modal `
  --provider ollama `
  --resume
```

Kết quả nằm trong thư mục output:

- `report.md`: báo cáo chính dành cho reviewer;
- `report.json`: dữ liệu có cấu trúc cho chương trình khác;
- `run-metadata.json`: thông tin giúp tái lập lần chạy;
- `scanner-artifacts/`: output nội bộ của scanner, có thể chứa dữ liệu nhạy cảm.

Xem hướng dẫn đầy đủ tại [docs/cli-usage.md](docs/cli-usage.md). Tài liệu
[luồng hệ thống Sprint 1](docs/sprint-1-system-flow.md) giải thích chi tiết từng
file/hàm từ repository đến LLM, policy và báo cáo. Thiết lập Qwen trên Modal được
mô tả tại [docs/MODAL_QWEN14B_SETUP.md](docs/MODAL_QWEN14B_SETUP.md).

## Cấu trúc dự án

```text
.
├── src/sast_triage/          Mã nguồn CLI và pipeline chính
│   ├── application/          Điều phối CLI, scanner, provider và output
│   ├── parsers/              Parse, normalize Semgrep/Gitleaks
│   ├── context/              Đọc source, chọn scope, sanitize, tạo evidence
│   ├── triage/               Prompt, provider và validate output LLM
│   ├── policy/               Policy thận trọng sau quyết định LLM
│   ├── pipeline/             Điều phối từng finding và toàn batch
│   ├── runners/              Chạy Semgrep/Gitleaks tuần tự
│   ├── reporting/            Sinh report JSON và Markdown an toàn
│   └── evaluation/           Dataset và metric benchmark
├── tests/                    Kiểm thử unit/integration và canary chống rò rỉ
├── benchmarks/               Dataset, scanner artifact và báo cáo benchmark
├── modal_apps/               Qwen3-14B-AWQ và runner benchmark trên Modal
├── docs/                     Kiến trúc, bảo mật và hướng dẫn sử dụng
└── pyproject.toml            Package, dependency và cấu hình test
```

Luồng chính:

```text
Repository → Semgrep/Gitleaks → NormalizedFinding → Context đã sanitize
           → LLM verdict → Policy action → report.json + report.md
```

Khi cần tìm code, bắt đầu từ ba file sau:

- `cli.py`: nhận tham số và xử lý exit code;
- `application/run.py`: điều phối toàn bộ lần chạy;
- `pipeline/finding.py`: xử lý một finding từ context đến policy.

## Kiểm thử dự án

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m pytest -p no:cacheprovider
python -m ruff check src tests modal_apps
```

## Nguyên tắc bảo mật quan trọng

- Raw source chỉ tồn tại cục bộ trong lớp xử lý context.
- Secret thô không được đưa vào model public, prompt, log hoặc report.
- Prompt và response LLM thô không được lưu trong report.
- Output LLM luôn được validate theo schema.
- Provider lỗi sẽ fail closed thành `TRIAGE_ERROR`.
- `FP_CANDIDATE` vẫn cần con người xác minh.
