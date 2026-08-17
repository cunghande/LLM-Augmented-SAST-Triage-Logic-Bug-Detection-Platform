# Hướng dẫn CLI

Tài liệu này dành cho người nhận source lần đầu: cài môi trường, chuẩn bị target,
chạy CLI, đọc báo cáo và xử lý các lỗi thường gặp. Ví dụ dùng PowerShell trên
Windows và Python 3.12.

## 1. Mô hình thư mục

Giữ source công cụ, repository mục tiêu và kết quả chạy tách biệt:

```text
D:\Code\
├── AI security\       source của SAST Triage
├── target-repos\      repository được đưa vào scanner
└── triage-runs\       artifact, checkpoint và report theo từng run
```

Không clone target hoặc ghi output vào `AI security` vì scanner có thể quét lại
source/report của công cụ. Không ghi output vào target vì sẽ làm checkout dirty
và có thể đưa artifact nhạy cảm vào commit.

`target-repos` do người dùng tạo một lần. Với lệnh rút gọn, `triage-runs` được
CLI tự tạo.

## 2. Yêu cầu hệ thống

### 2.1 Công cụ bắt buộc

- Python `>=3.11,<3.14`; khuyến nghị Python 3.12.
- Git.
- Semgrep trong `PATH`.
- Gitleaks trong `PATH`.
- Kết nối Internet để tải ruleset Semgrep và chạy Modal lần đầu.

Kiểm tra:

```powershell
python --version
git --version
semgrep --version
gitleaks version
```

Nếu `python --version` không nằm trong khoảng 3.11–3.13, cài Python 3.12 và
đảm bảo lệnh `python` trỏ tới đúng bản đó trước khi tạo `.venv`.

Nếu Semgrep chưa có, cài theo cách Python chính thức trên Windows:

```powershell
python -m pip install semgrep
semgrep --version
```

Gitleaks cung cấp binary Windows tại
[GitHub Releases](https://github.com/gitleaks/gitleaks/releases). Giải nén
`gitleaks.exe`, thêm thư mục chứa executable vào `PATH`, mở PowerShell mới rồi
kiểm tra:

```powershell
gitleaks version
Get-Command gitleaks | Select-Object Source
```

Tài liệu tham khảo chính thức:

- [Semgrep Community Edition](https://semgrep.dev/products/community-edition/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Modal user account setup](https://modal.com/docs/guide/modal-user-account-setup)

### 2.2 Cài source dự án

```powershell
cd "D:\Code\AI security"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

Kiểm tra package và CLI:

```powershell
python -c "import sast_triage; print(sast_triage.__version__)"
python -m sast_triage --help
python -m sast_triage scan-and-triage --help
```

### 2.3 Xác thực Modal

Chỉ cần cho provider `real`:

```powershell
python -m modal setup
python -m modal token info
```

Không đưa Modal token vào source, `.env`, report hoặc ảnh chụp màn hình.

## 3. Chạy nhanh nhất với Qwen3-14B

### 3.1 Clone target

```powershell
New-Item -ItemType Directory -Force "D:\Code\target-repos"
cd "D:\Code\target-repos"
git clone https://github.com/cunghande/Sequential-Recommender
```

Nếu Git báo:

```text
destination path 'Sequential-Recommender' already exists
```

thì repository đã được clone; không chạy `git clone` lần nữa.

Kiểm tra checkout:

```powershell
git -C .\Sequential-Recommender branch --show-current
git -C .\Sequential-Recommender rev-parse HEAD
git -C .\Sequential-Recommender status --short
```

`status --short` nên không in gì.

### 3.2 Chạy một lệnh

Khi `.venv` đang active và PowerShell đang ở `D:\Code\target-repos`:

```powershell
python -m sast_triage Sequential-Recommender
```

Nếu đang đứng trong source công cụ, truyền đường dẫn tương đối:

```powershell
cd "D:\Code\AI security"
python -m sast_triage ..\target-repos\Sequential-Recommender
```

Nếu chưa activate `.venv`, gọi Python của dự án trực tiếp:

```powershell
cd "D:\Code\target-repos"
& "D:\Code\AI security\.venv\Scripts\python.exe" -m sast_triage Sequential-Recommender
```

Ba cách trên tương đương. Lệnh rút gọn tự cấu hình:

```text
provider       = real
model          = Qwen/Qwen3-14B-AWQ
GPU            = B200
Semgrep config = p/python + p/security-audit
Gitleaks       = built-in config
Module 2       = enabled
```

Mỗi lần chạy tạo output mới:

```text
D:\Code\triage-runs\<repo>-qwen14b-YYYYMMDD-HHMMSSZ
```

Do có timestamp, lệnh rút gọn không ghi đè run cũ.

### 3.3 Tiến trình bình thường

```text
[1/7] Kiểm tra repository/output
[2/7] Chạy Semgrep và Gitleaks
[3/7] Parse finding và lập Module 2 index
[4/7] Khởi động provider
[5/7] Triage từng finding và ghi checkpoint
[6/7] Ghi report
[7/7] Hoàn tất
```

Cold start B200/vLLM có thể mất 4–7 phút. Các dòng `Loading images`, tải shard,
compile, FlashInfer warm-up và CUDA graph capture là bình thường. Không bấm
`Ctrl+C` khi chưa có lỗi rõ ràng.

## 4. Các provider

| Provider | Mục đích | Cần thêm |
|---|---|---|
| `fake` | Kiểm tra scanner/pipeline/report offline | Không cần LLM |
| `ollama` | LLM chạy trên máy | Ollama và model local |
| `real` | Qwen3-14B-AWQ trên Modal B200 | Modal account/token/credit |

### 4.1 Fake provider

Fake provider không đo chất lượng model; chỉ dùng smoke test kỹ thuật:

```powershell
python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\Sequential-Recommender-fake" `
  --provider fake `
  --semgrep-config p/python `
  --semgrep-config p/security-audit `
  --module2 `
  --no-overwrite
```

### 4.2 Ollama

```powershell
ollama pull qwen3:8b
$env:SAST_TRIAGE_LLM_MODEL = "qwen3:8b"

python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\Sequential-Recommender-ollama" `
  --provider ollama `
  --semgrep-config p/python `
  --semgrep-config p/security-audit `
  --module2 `
  --no-overwrite
```

### 4.3 Modal/Qwen3-14B với lệnh đầy đủ

Dùng lệnh đầy đủ khi muốn tự chọn output hoặc cần resume:

```powershell
$env:MODAL_GPU = "B200"

python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\Sequential-Recommender-modal-manual" `
  --provider real `
  --repository-identifier Sequential-Recommender `
  --semgrep-config p/python `
  --semgrep-config p/security-audit `
  --module2 `
  --no-overwrite
```

Không cần chạy `modal deploy`; provider tự mở một App session, sử dụng model
cache trong Modal Volume và scale GPU về 0 khi hoàn thành.

## 5. Hai chế độ CLI

### 5.1 `scan-and-triage`

Chạy scanner rồi triage. Đây là chế độ thông thường:

```powershell
python -m sast_triage scan-and-triage `
  --repository <repo-path> `
  --output-dir <run-path> `
  --provider fake|ollama|real
```

### 5.2 `triage`

Dùng artifact Semgrep/Gitleaks có sẵn, không chạy scanner:

```powershell
python -m sast_triage triage `
  --repository "D:\Code\target-repos\MyRepo" `
  --semgrep-json "D:\Artifacts\semgrep.json" `
  --gitleaks-json "D:\Artifacts\gitleaks.json" `
  --output-dir "D:\Code\triage-runs\MyRepo-artifact-run" `
  --provider fake `
  --no-overwrite
```

Artifact bên ngoài repository mặc định có binding `UNVERIFIED`; đây là lý do
`scan-and-triage` được ưu tiên cho demo.

## 6. Option quan trọng

| Option | Ý nghĩa |
|---|---|
| `--repository` | Đường dẫn target repository. |
| `--output-dir` | Thư mục riêng của một run đầy đủ. |
| `--provider` | `fake`, `ollama` hoặc `real`. |
| `--prompt-version` | Mặc định `triage-prompt-v11`; v11 thêm tiêu chí phân biệt guard hợp lệ cho năm lớp logic bug. Dùng v10/v9 chỉ để tái lập baseline cũ. |
| `--repository-identifier` | ID tương đối ghi vào metadata; mặc định là tên repo. |
| `--analysis-backend` | `native` (mặc định) hoặc `joern` (Docker, thử nghiệm). |
| `--semgrep-config` | Có thể lặp nhiều lần để thêm ruleset/YAML. |
| `--gitleaks-config` | Config Gitleaks tùy chọn. |
| `--module2` / `--no-module2` | Bật/tắt cross-file index và evidence Python. Mặc định bật. |
| `--module2-discovery` | Thử nghiệm Sprint 3: cho phép Module 2 thêm finding mới; mặc định tắt để benchmark chỉ đo finding của scanner. |
| `--logic-detector` | `off` (mặc định) hoặc `python-five-logic` để phát hiện năm lớp lỗi logic Sprint 2. |
| `--overwrite` / `--no-overwrite` | Cho phép/chặn ghi đè file report. |
| `--resume` | Dùng lại scanner artifact và checkpoint của cùng output dir. |

Xem toàn bộ option:

```powershell
python -m sast_triage scan-and-triage --help
python -m sast_triage triage --help
```

Thiết lập image, smoke test và troubleshooting của `--analysis-backend joern`
được mô tả tại [joern-analysis.md](joern-analysis.md).

## 7. Module 2 và monorepo

Module 2 hiện index file `*.py` và nhận diện component qua:

```text
pyproject.toml
setup.cfg
setup.py
```

Nó lưu symbol, call-site, file tương đối và số dòng; không lưu raw source trong
repository index. Giới hạn mặc định:

- tối đa 20.000 file Python;
- mỗi file tối đa 1 MiB;
- bỏ `.git`, `.venv`, `venv`, `node_modules`, `.tox`, symlink;
- trace tối đa 5 tầng;
- Evidence Agent tối đa 5 tool call.

Module 2 chưa phải taint engine toàn diện như Semgrep Pro/CodeQL. Dynamic
dispatch, reflection, monkey patching hoặc framework wiring phức tạp có thể cần
review thủ công.

Mặc định, Module 2 chỉ tạo index/evidence cho finding Semgrep và Gitleaks. Nó
không làm thay đổi tập finding của scanner. Chỉ dùng `--module2-discovery` khi
muốn thử nghiệm discovery Sprint 3 và báo cáo riêng kết quả đó.

## 8. Output và cách đọc báo cáo

Một run `scan-and-triage` có cấu trúc:

```text
run-directory\
├── report.md
├── report.json
├── run-metadata.json
└── scanner-artifacts\
    ├── semgrep.json
    └── gitleaks.json
```

Trong khi chạy có thể xuất hiện `triage-checkpoint.json`; file này tự xóa sau
khi report và metadata được ghi thành công.

### 8.1 File nào dùng cho việc gì?

- `report.md`: đọc bằng mắt, dùng khi trình bày mentor.
- `report.json`: tích hợp chương trình hoặc benchmark.
- `run-metadata.json`: kiểm tra commit, trạng thái worktree, binding, model,
  scanner version/config và số finding lỗi.
- `scanner-artifacts/`: dùng debug nội bộ, không gửi ra ngoài mặc định.

### 8.2 Model verdict

| Verdict | Ý nghĩa |
|---|---|
| `LIKELY_TP` | LLM nghiêng về lỗi thật. |
| `LIKELY_FP` | LLM nghiêng về cảnh báo giả. |
| `NEEDS_REVIEW` | LLM không đủ cơ sở kết luận. |

### 8.3 Policy action

| Action | Ý nghĩa |
|---|---|
| `AUTO_ACCEPT` | Policy có đủ evidence để chấp nhận finding. |
| `AUTO_REJECT` | Policy có đủ evidence để loại finding. |
| `MANUAL_REVIEW` | Cần con người xem vì evidence thiếu/xung đột. |
| `TRIAGE_ERROR` | Lỗi xử lý; finding vẫn được giữ. |

Không đánh đồng `LIKELY_FP` với `AUTO_REJECT`: policy có thể giữ finding ở
`MANUAL_REVIEW` nếu LLM đoán FP nhưng deterministic evidence chưa chứng minh.

### 8.4 Kiểm tra run hợp lệ

```powershell
$runPath = "D:\Code\triage-runs\Sequential-Recommender-qwen14b-..."
$metadata = Get-Content "$runPath\run-metadata.json" -Raw | ConvertFrom-Json
$report = Get-Content "$runPath\report.json" -Raw | ConvertFrom-Json

$metadata | Select-Object repository_identifier, commit_sha, working_tree_state,
  artifact_repository_match, triage_provider, model_version,
  total_findings_parsed, findings_triaged_ok, findings_with_errors

$report.results |
  Group-Object { $_.policy_decision.action } |
  Select-Object Name, Count
```

Run demo tốt nên có:

```text
artifact_repository_match = VERIFIED
model_version              = Qwen/Qwen3-14B-AWQ
findings_with_errors       = 0
report result count        = total_findings_parsed
```

## 9. Checkpoint và resume

Nếu Modal hết credit/quota/capacity, CLI trả exit code `5` và giữ checkpoint.
Chạy lại bằng đúng repository, output directory, prompt/schema và scanner config:

```powershell
python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\RUN-BI-GIAN-DOAN" `
  --provider real `
  --semgrep-config p/python `
  --semgrep-config p/security-audit `
  --module2 `
  --resume
```

Có thể chuyển phần finding còn lại sang Ollama:

```powershell
python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\RUN-BI-GIAN-DOAN" `
  --provider ollama `
  --semgrep-config p/python `
  --semgrep-config p/security-audit `
  --module2 `
  --resume
```

Trong `scan-and-triage`, resume dùng lại `scanner-artifacts`; scanner không chạy
lại. Checkpoint không chứa raw source, prompt hoặc response thô.

## 10. Exit code

| Code | Ý nghĩa |
|---:|---|
| `0` | Hoàn tất; vẫn cần đọc warning và policy action. |
| `2` | Cấu hình/repository/checkpoint/provider không hợp lệ. |
| `3` | Scanner hoặc parser gặp lỗi. |
| `4` | Không thể kiểm tra hoặc ghi báo cáo. |
| `5` | Modal hết quota/credit/capacity; có thể resume. |

Trong PowerShell:

```powershell
python -m sast_triage Sequential-Recommender
$LASTEXITCODE
```

Luôn kiểm tra cả exit code và `findings_with_errors` trong metadata.

## 11. Xử lý lỗi thường gặp

### `CLI_INVALID_REPOSITORY`

Tên repo được resolve theo thư mục hiện tại. Nếu đang ở source:

```powershell
python -m sast_triage ..\target-repos\Sequential-Recommender
```

### Git báo target đã tồn tại

Không clone lại. Chạy CLI với thư mục đã có.

### `semgrep` hoặc `gitleaks` không được nhận diện

```powershell
Get-Command semgrep | Select-Object Source
Get-Command gitleaks | Select-Object Source
```

Sửa `PATH`, mở PowerShell mới rồi kiểm tra version trước khi chạy CLI.

### Modal đứng lâu ở `[4/7]`

Cold start gồm tải image, model shard, compile và GPU warm-up. Chờ tối đa khoảng
7–10 phút trước khi coi là bất thường. Không chạy nhiều phiên B200 song song.

### `PartialParsing` từ Semgrep

Finding khác vẫn được giữ, nhưng file liên quan có thể chưa được phân tích đầy
đủ. Ghi rõ warning khi trình bày kết quả.

### Repository chủ yếu là `.ipynb`

CLI chưa phân tích notebook trực tiếp. Chuyển notebook thành script trước:

```powershell
jupyter nbconvert --to script .\notebooks\example.ipynb
```

Sau đó quét bản `.py` trong một checkout/output riêng.

## 12. Checklist demo cho mentor

Trước buổi demo:

```powershell
cd "D:\Code\AI security"
.\.venv\Scripts\Activate.ps1
python --version
semgrep --version
gitleaks version
python -m modal token info
python -m pytest -p no:cacheprovider -q --basetemp=.pytest-tmp-demo
python -m ruff check src tests modal_apps
```

Kiểm tra target:

```powershell
git -C "D:\Code\target-repos\Sequential-Recommender" status --short
```

Chạy:

```powershell
cd "D:\Code\target-repos"
python -m sast_triage Sequential-Recommender
```

Khi hoàn tất, mở `report.md` trong run mới nhất. Giữ một report validation an
toàn làm phương án dự phòng nếu Modal cold start hoặc quota gặp vấn đề.

## 13. Kiểm thử dành cho người phát triển

```powershell
cd "D:\Code\AI security"
.\.venv\Scripts\Activate.ps1
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m pytest -p no:cacheprovider -q --basetemp=.pytest-tmp-local
python -m ruff check src tests modal_apps
```

Kết quả test và benchmark Sprint 2 gần nhất được lưu trong
[`sprint-2-scope.md`](sprint-2-scope.md); không dùng số test cũ trong tài liệu này
làm bằng chứng nghiệm thu.

Đọc kiến trúc tại [`code-map.md`](code-map.md) và
[`sprint-1-system-flow.md`](sprint-1-system-flow.md).

## 14. Demo Sprint 2 — năm lớp logic bug

Khi `.venv` đã kích hoạt và PowerShell đang ở `D:\Code\target-repos`, chạy một
dòng dưới đây. Chỉ thay cả hai chỗ `<TEN_REPO>` bằng đúng tên thư mục repo:

```powershell
python -m sast_triage scan-and-triage --repository .\<TEN_REPO> --output-dir ..\triage-runs\<TEN_REPO>-sprint2 --analysis-backend native --module2 --logic-detector python-five-logic --provider fake
```

Ví dụ với `FastAPI-App`:

```powershell
python -m sast_triage scan-and-triage --repository .\FastAPI-App --output-dir ..\triage-runs\FastAPI-App-sprint2 --analysis-backend native --module2 --logic-detector python-five-logic --provider fake
```

`--output-dir` không cần tồn tại trước; CLI tự tạo. Để dùng LLM thật trên Modal,
đổi duy nhất `--provider fake` thành `--provider real` sau khi
`python -m modal token info` chạy thành công. Detector Sprint 2 hiện yêu cầu
backend `native` và Module 2 bật.

Xem phạm vi, năm lớp lỗi và cách đọc benchmark tại
[`sprint-2-scope.md`](sprint-2-scope.md).
