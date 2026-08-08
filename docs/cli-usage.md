# Hướng dẫn chạy CLI

## 1. Chuẩn bị môi trường

Công cụ hỗ trợ Python từ 3.11 đến 3.13. Trên PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Kiểm tra CLI:

```powershell
python -m sast_triage --help
python -m sast_triage scan-and-triage --help
```

Chế độ `scan-and-triage` yêu cầu hai executable sau có trong `PATH`:

```powershell
semgrep --version
gitleaks version
```

CLI không tự tải hoặc cài scanner.

## 2. Chọn provider

### Fake provider

Dùng để kiểm tra pipeline, parser, context, policy và reporter mà không gọi mạng
hoặc tốn chi phí LLM. Không dùng kết quả fake provider để đánh giá độ chính xác.

### Ollama

Dùng LLM cục bộ qua API tương thích OpenAI. Mặc định CLI sử dụng `qwen3:8b`:

```powershell
ollama pull qwen3:8b
ollama serve
```

Có thể ghi đè cấu hình:

```powershell
$env:SAST_TRIAGE_LLM_API_KEY = "ollama"
$env:SAST_TRIAGE_LLM_BASE_URL = "http://localhost:11434/v1"
$env:SAST_TRIAGE_LLM_MODEL = "qwen3:8b"
$env:SAST_TRIAGE_LLM_TIMEOUT_SECONDS = "180"
$env:SAST_TRIAGE_LLM_REASONING_EFFORT = "medium"
```

`SAST_TRIAGE_LLM_REASONING_EFFORT` nhận `none`, `low`, `medium`, `high` hoặc
`max` nếu provider hỗ trợ.

### Real provider: Qwen3-14B trên Modal

`--provider real` nay gọi trực tiếp `Qwen/Qwen3-14B-AWQ` trên Modal. CLI tự
kiểm tra/tải model vào Volume, không cần cấu hình endpoint hay model qua biến môi
trường. Mỗi máy chỉ cần xác thực Modal một lần:

```powershell
python -m modal setup
```

Mặc định Modal dùng một H100, giữ container trong 300 giây trong app session,
tắt thinking và dùng prefix cache. Thời gian 1–2 phút chỉ là mục tiêu cho repo
ít finding khi GPU/model đã warm; scanner, cold start, hàng đợi và số finding vẫn có
thể làm lần chạy lâu hơn.

## 3. Quét repository rồi triage

Đây là luồng sử dụng thông thường.

Chạy thử bằng fake provider:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output\smoke-test `
  --provider fake `
  --repository-identifier my-project
```

Chạy bằng Ollama:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output\ollama `
  --provider ollama `
  --repository-identifier my-project
```

Chạy Qwen3-14B trên Modal:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output\modal-qwen14b `
  --provider real `
  --repository-identifier my-project
```

Không dùng cùng một `output-dir` cho hai lần chạy nếu muốn giữ cả hai kết quả.

## 4. Triage artifact scanner có sẵn

Dùng chế độ này khi Semgrep và Gitleaks đã được chạy trước đó:

```powershell
python -m sast_triage triage `
  --repository .\duong-dan-repo-python `
  --semgrep-json .\artifacts\semgrep.json `
  --gitleaks-json .\artifacts\gitleaks.json `
  --output-dir .\output\artifact-run `
  --provider fake
```

Artifact phải thuộc đúng repository. Nếu không xác minh được liên kết,
policy sẽ chuyển kết quả sang hướng thận trọng hơn.

## 5. Đọc output

Mỗi lần chạy thành công hoặc thành công một phần tạo:

```text
output-dir/
├── report.md
├── report.json
├── run-metadata.json
└── scanner-artifacts/       chỉ có ở chế độ scan-and-triage
```

- `report.md`: dành cho security reviewer; nên đọc file này trước.
- `report.json`: output máy đọc, gồm metadata, finding, quyết định LLM và policy.
- `run-metadata.json`: phiên bản prompt/model/policy, bộ đếm và thời gian chạy.
- `scanner-artifacts/`: dữ liệu scanner thô; phải bảo vệ vì có thể chứa secret.

Khi provider Modal hết quota/credit/capacity, CLI trả exit code `5` và giữ
`triage-checkpoint.json`. Checkpoint chỉ có finding ID, decision đã validate,
policy và lỗi an toàn; không có raw source, prompt hay response thô. Tiếp tục bằng
Ollama với cùng repository, output directory và artifact:

```powershell
python -m sast_triage scan-and-triage `
  --repository .\duong-dan-repo-python `
  --output-dir .\output\modal-qwen14b `
  --provider ollama `
  --resume
```

Trong `scan-and-triage`, `--resume` không chạy lại scanner; nó bind và tái sử dụng
`scanner-artifacts` của lần chạy bị gián đoạn. Checkpoint tự xóa sau khi cả ba
report/metadata đã ghi thành công.

CLI hiển thị tiến trình theo bảy stage: validate, scanner/artifact, parse, provider,
triage từng finding, ghi report và hoàn tất. Tiến trình chỉ in số lượng và
policy action an toàn; không in source, secret, prompt hay response LLM. Lỗi vận hành
in `LỖI [error_code]` cùng thông báo an toàn, không in traceback.

Trong mỗi finding:

```text
finding          Scanner phát hiện điều gì
context_summary  Phạm vi context an toàn đã phân tích
triage_decision  LLM nhận định gì
policy_decision  Hệ thống quyết định xử lý thế nào
processing_errors Lỗi của riêng finding
```

`scanner_errors` ở cấp cao nhất chứa lỗi scanner/artifact không thuộc riêng một
finding. `triage_decision = null` nghĩa là provider không tạo được output hợp lệ.

## 6. Exit code

| Mã | Ý nghĩa |
|---:|---|
| `0` | Chạy thành công. |
| `2` | Cấu hình hoặc input không hợp lệ. |
| `3` | Scanner/artifact có lỗi; report vẫn có thể đã được tạo. |
| `4` | Không ghi được report an toàn. |
| `5` | Modal hết quota/credit/capacity; checkpoint đã được lưu để resume. |

Luôn kiểm tra cả exit code và `scanner_errors` trong report. Trên Windows,
Gitleaks hiện có thể trả file path tuyệt đối; parser sẽ fail closed và ghi
`PARSE_RECORD_INVALID_FIELD` thay vì làm lộ hoặc triage nhầm finding.

## 7. Báo cáo dành cho reviewer

`report.md` sắp xếp finding theo mức cần xử lý: `TRIAGE_ERROR`,
`MANUAL_REVIEW`, `LIKELY_TP`, rồi `FP_CANDIDATE`; trong cùng nhóm, severity cao
được đưa lên trước.

Phần “Phân tích của LLM” gồm verdict, confidence, kết luận, evidence, thông tin
còn thiếu và giả định. Phần policy do chương trình tạo theo quy tắc cố định,
không phải nội dung LLM. Báo cáo không chứa raw source, prompt thô, response LLM
thô, traceback hoặc đường dẫn repository tuyệt đối.

## 8. Qwen trên Modal

Modal Qwen3-14B là provider `real` mặc định của CLI. Xem
[MODAL_QWEN14B_SETUP.md](MODAL_QWEN14B_SETUP.md) để biết chi tiết Volume, GPU,
chi phí, benchmark và cách kiểm tra app đã scale về 0.
