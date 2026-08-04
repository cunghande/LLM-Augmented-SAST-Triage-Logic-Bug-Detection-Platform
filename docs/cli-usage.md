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