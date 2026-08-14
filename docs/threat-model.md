# Threat model

## Tài sản cần bảo vệ

- Source code và credential trong repository.
- Secret thô có trong Gitleaks artifact.
- Tính toàn vẹn của verdict, policy action và báo cáo.
- Ràng buộc giữa scanner artifact và đúng repository được triage.

## Trust boundary

| Biên | Dữ liệu không tin cậy | Control bắt buộc |
|---|---|---|
| Scanner artifact → parser | JSON, path, message, metadata, secret | Schema/allowlist; không giữ raw record hoặc raw secret |
| Repository → Safe Context | Source, symlink, encoding, prompt payload trong code | Resolve/containment; giới hạn kích thước; sanitize/redact |
| Safe Context → provider | Finding facts và sanitized context | Canonical JSON envelope; giới hạn context; đánh dấu untrusted |
| Provider → pipeline | JSON có thể sai hoặc độc hại | Output schema; cấm policy field; không thực thi output |
| Pipeline → report | Kết quả có thể còn dữ liệu nhạy cảm | Explicit projection; deep leak check; không raw prompt/response |

## Mối đe dọa và xử lý

| Mối đe dọa | Tác động | Control/response |
|---|---|---|
| Secret leakage | Credential xuất hiện trong model, log, prompt hoặc report | Redact sớm; canary tests; reporter kiểm tra phòng thủ sâu |
| Prompt injection trong source/message | Model bị hướng dẫn trả verdict sai | Tách system instruction; JSON hóa payload; adversarial tests; policy bảo thủ |
| Path traversal/symlink escape | Đọc source ngoài repository | Resolve path và containment thực; lỗi chuyển review/error |
| Artifact-repository mismatch | Finding repo A dùng context repo B | Binding verification trước triage; mismatch thành `TRIAGE_ERROR` |
| Malformed scanner artifact | Crash hoặc tạo finding sai | Parser validation và lỗi an toàn theo record |
| Malformed/hostile LLM output | Bypass policy hoặc làm mất finding | Strict schema; forbidden fields; `triage_decision=null`; `TRIAGE_ERROR` |
| Provider timeout/outage | Finding biến mất hoặc bị coi là FP | Giữ finding; safe `ProcessingError`; không auto-dismiss |
| Report/log leakage | Source, secret, traceback hoặc absolute path bị phát tán | Allowlisted projection; leak scan trước khi ghi |

## Giả định và giới hạn

- Source code luôn được coi là dữ liệu đối kháng, kể cả comment và string literal.
- Sanitization giảm rủi ro nhưng không chứng minh model miễn nhiễm prompt injection.
- Confidence do model tự báo không phải xác suất đã calibration.
- Joern/Module 2 là experimental cho tới khi vượt stage gate bằng held-out benchmark.
