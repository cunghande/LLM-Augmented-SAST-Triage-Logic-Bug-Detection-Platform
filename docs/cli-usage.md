# Cách sử dụng CLI

Sử dụng lệnh `sast-triage` đã được cài đặt hoặc chạy thông qua `python -m sast_triage`.

## Phân tích các artifact bằng Fake Provider

Chạy triage từ các tệp kết quả JSON đã được Semgrep và Gitleaks tạo sẵn:

```powershell
python -m sast_triage triage `
  --repository <duong-dan-repository> `
  --semgrep-json <duong-dan-semgrep.json> `
  --gitleaks-json <duong-dan-gitleaks.json> `
  --output-dir <thu-muc-dau-ra> `
  --provider fake
```

## Chạy scanner rồi triage

```powershell
python -m sast_triage scan-and-triage `
  --repository <duong-dan-repository> `
  --output-dir <thu-muc-dau-ra> `
  --provider fake
```

Semgrep và Gitleaks phải được cài đặt sẵn; CLI không tự tải scanner.

## Real provider với Ollama

```powershell
$env:SAST_TRIAGE_LLM_API_KEY = "ollama"
$env:SAST_TRIAGE_LLM_BASE_URL = "http://localhost:11434/v1"
$env:SAST_TRIAGE_LLM_MODEL = "qwen3:8b"
$env:SAST_TRIAGE_LLM_TIMEOUT_SECONDS = "180"
$env:SAST_TRIAGE_LLM_REASONING_EFFORT = "medium"
```

Prompt mặc định là `triage-prompt-v3`. `SAST_TRIAGE_LLM_REASONING_EFFORT`
nhận `none`, `low`, `medium`, `high`, hoặc `max` nếu provider hỗ trợ.

Exit code: `0` thành công, `2` lỗi cấu hình/input, `3` lỗi scanner hoặc
artifact nhưng vẫn có report, và `4` lỗi ghi report.
