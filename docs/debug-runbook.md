# Runbook debug pipeline SAST Triage

Tài liệu này dùng để chẩn đoán pipeline theo đúng thứ tự
scanner → binding → context/evidence → Joern → LLM → policy → reporter.
Chỉ debug trên repository và môi trường được phép.

## Nguyên tắc an toàn

- Không dán raw source, secret, token Modal hoặc scanner artifact thô vào ticket.
- Không bật log chứa prompt/response LLM thô.
- Traceback chỉ được giữ cục bộ sau redaction; reporter chỉ ghi `safe_message`.
- Dùng đường dẫn tương đối, finding ID, error code, version và hash khi trao đổi.
- Không sửa verdict hoặc xóa finding để làm pipeline trả exit code thành công.

## Kiểm tra nhanh

Chạy từ thư mục gốc dự án:

```powershell
$env:PYTHONPATH = "src"
$env:PYTHONUTF8 = "1"
python --version
semgrep --version
gitleaks version
docker version
python -m sast_triage scan-and-triage --help
```

Kiểm tra chất lượng code:

```powershell
python -m pytest -q --basetemp .tmp/pytest-debug
python -m ruff check src tests modal_apps
```

Khi cần cô lập lỗi, chạy lần lượt:

1. `--provider fake` để loại trừ Modal/LLM.
2. `--no-module2` để xác định lỗi Joern/CPG.
3. `--no-module2-discovery --logic-detector off` để chỉ kiểm tra scanner.
4. Bật lại từng thành phần và dùng output directory mới cho mỗi lần chạy.

## Scanner Semgrep và Gitleaks

Triệu chứng thường gặp:

| Triệu chứng | Kiểm tra | Hành động |
|---|---|---|
| `SCANNER_EXECUTABLE_NOT_FOUND` | Chạy lệnh version | Cài đúng binary hoặc dùng Docker image của dự án |
| `SCANNER_TIMEOUT` | Kiểm tra kích thước repo và timeout | Loại thư mục build/venv, tăng timeout có kiểm soát |
| `SCANNER_PROCESS_FAILED` | Kiểm tra config ID và syntax config | Validate ruleset; không chép stderr có secret vào báo cáo |
| Không có finding mong đợi | Kiểm tra ruleset và file đã scan | Chạy rule validation trên fixture dương/âm trước repository thật |

`scanner-artifacts/` chỉ phục vụ debug cục bộ. Trước khi chia sẻ phải loại absolute
path, raw match và mọi giá trị secret.

## Repository–artifact binding

Trong `report.json`, kiểm tra:

```text
run_metadata.artifact_repository_match
run_metadata.commit_sha
run_metadata.input_artifact_hashes
```

Nếu binding là `UNVERIFIED`, `PARTIAL` hoặc `MISMATCH`, không cố ép policy phân
loại tự động. Ưu tiên `scan-and-triage` để scanner và triage dùng cùng repository
trong một run.

## Context, redaction và evidence

Kiểm tra theo finding trong `report.json`:

```text
context_summary
evidence_details.complete
evidence_details.source_reaches_sink
evidence_details.paths
evidence_details.completeness.missing_information
processing_errors
```

Các lỗi path traversal, absolute path hoặc symlink escape phải được giữ nguyên
thành lỗi an toàn. Không bỏ containment check để lấy thêm context.

Với Gitleaks, không kỳ vọng mọi finding có source-to-sink: bản thân secret là
artifact nhạy cảm. File nguồn vẫn phải được redact trước khi gửi provider.

## Joern và CPG

Kiểm tra Docker trước:

```powershell
docker info
docker image inspect sast-triage-joern:4.0.600
docker ps --filter ancestor=sast-triage-joern:4.0.600
```

Trong metadata, xác nhận:

```text
analysis_backend = joern
analysis_backend_version = 4.0.600
cpg_build_status = complete
analysis_config_id
```

Nếu CPG lỗi, kiểm tra Docker Desktop đang dùng Linux containers, image đúng
version và target được mount read-only. Không coi AST projection là bằng chứng
Joern hoàn chỉnh. Dynamic dispatch, reflection và framework wiring phức tạp có
thể vẫn cần `MANUAL_REVIEW`.

## LLM Modal/Qwen

Kiểm tra xác thực và quota:

```powershell
python -m modal token info
python -m modal billing summary
```

Chạy smoke prompt độc lập:

```powershell
python -m modal run modal_apps/qwen14b_modal.py
```

Các nhóm lỗi cần phân biệt:

- Auth/credential: đăng nhập lại Modal; không ghi token vào log.
- Resource exhausted/budget: kiểm tra credit, workspace budget và GPU quota.
- Timeout/cold start: tách thời gian khởi động model khỏi provider latency.
- Output schema: giữ finding, ghi `TRIAGE_ERROR`; không parse response bằng heuristic
  không kiểm soát.

Đối chiếu `model_version`, `prompt_version`, `provider_duration_ms` và
`triage_input_digest`; không lưu hoặc yêu cầu raw prompt/raw response.

## Decision cache và telemetry

Kiểm tra `decision_cache_status`, `cache_hit`, `input_tokens`, `output_tokens`,
`token_count_method`, `estimated_cost_usd` và `cost_model_version` ở từng kết quả.
Ở cấp run, kiểm tra hit/miss, token provider, P50/P95 latency và tổng chi phí.

- Cache không hit: xác nhận repository content, provider/model, prompt, output schema,
  policy và risk-scoring version không đổi; kiểm tra TTL chưa hết.
- Cache hit nhưng vẫn thấy Modal cold start: xác nhận không còn finding cache miss.
- Chi phí là `null`: truyền `--provider-cost-per-hour-usd`; đây là ước tính theo
  wall time, không phải hóa đơn của provider.
- Token là ước tính `utf8-bytes-div-4-v1`, không phải tokenizer/billing truth.
- Entry lỗi schema, hết hạn hoặc chứa giá trị bị cấm bị coi là miss và không được dùng.

Xóa cache mà không xóa file khác trong thư mục:

```powershell
python -m sast_triage cache-clear --cache-dir <CACHE_DIR> --expired-only
python -m sast_triage cache-clear --cache-dir <CACHE_DIR>
```

Không sửa trực tiếp SQLite để ép hit. Xem thời hạn và quy trình thu hồi tại
[llm-cache-retention-policy.md](llm-cache-retention-policy.md).

## Policy và MANUAL_REVIEW

`MANUAL_REVIEW` không đồng nghĩa pipeline lỗi. Kiểm tra `policy_decision.reasons`:

- Evidence chưa chứng minh source → sink.
- Context thiếu hoặc bị truncate/redact.
- LLM yêu cầu review.
- Verdict FP không đủ điều kiện bảo thủ.
- Artifact binding chưa xác minh đầy đủ.

Không đổi policy chỉ để giảm số manual review. Mọi thay đổi phải có regression
test và đánh giá trên calibration trước khi chạy held-out.

## Risk score và remediation

Mỗi kết quả pipeline mới có:

```text
risk_score
risk_level
risk_factors
risk_scoring_version
remediation
validation_checklist
```

`deterministic-risk-v1` dùng trọng số 0,25 severity + 0,25 reachability + 0,20
exposure + 0,20 data sensitivity + 0,10 exploitability. Đây là điểm ưu tiên,
không phải xác suất khai thác và không thay thế verdict/policy.

Nếu điểm bất thường, kiểm tra lần lượt severity đã normalize, path category,
`source_reaches_sink`, trạng thái evidence và rule/CWE. Không chỉnh tay score
trong report. Remediation là đề xuất cần code review, không phải patch tự động.

## Reporter

Một run thành công phải sinh đủ:

```text
report.json
report.md
report.html
run-metadata.json
```

Trước khi chia sẻ, tìm dấu hiệu rò rỉ:

```powershell
rg -n -i "raw_source|sanitized_snippet|prompt_raw|response_raw|traceback" <OUTPUT_DIR>
```

Không chia sẻ `scanner-artifacts/` theo mặc định. Nếu reporter từ chối ghi vì
forbidden field/value, sửa nguồn rò rỉ; không tắt defense-in-depth check.

## Gói thông tin an toàn khi báo lỗi

Chỉ thu thập:

- command đã loại token và absolute path không cần thiết;
- tool/model/prompt/policy/analysis version;
- run ID, finding ID, scanner, rule ID và relative path;
- safe error code/message;
- binding, CPG status, timing và artifact hash;
- đoạn report đã redact, không kèm raw source/prompt/response.

Nếu vẫn chưa xác định được nguyên nhân, giữ finding ở `MANUAL_REVIEW` hoặc
`TRIAGE_ERROR` và chuyển gói thông tin an toàn cho người phụ trách AppSec/Platform.
