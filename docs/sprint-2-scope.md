# Sprint 2 — FastAPI authorization logic detector

Sprint 2 có một detector bắt buộc: phát hiện endpoint FastAPI nhạy cảm thiếu
function-level authorization. IDOR/BOLA chỉ là stretch goal và chưa được bật
trong bản triển khai này.

## Phạm vi đã triển khai

- Route/dependency index cho `FastAPI`, `APIRouter`, route decorators,
  `Depends`, `Security`, router-level dependencies và `include_router` trong
  phạm vi bounded native index.
- Phân biệt authentication với authorization; authentication-only không được
  coi là authorization.
- Ba trạng thái phân tích nội bộ: `PROTECTED`, `MISSING_AUTHZ_CANDIDATE`,
  `UNKNOWN`.
- Candidate được chuẩn hóa thành rule
  `module2.fastapi.missing-function-authz`, CWE-862.
- Detector chạy qua `NormalizedFinding`, SafeContext, TriageProvider, Policy
  và reporter hiện có.
- CLI flag: `--logic-detector off|fastapi-missing-authz`; mặc định `off`.

## Quy tắc an toàn

- Không suy luận thiếu authorization chỉ vì không thấy một tên hàm guard khi
  context là dynamic, middleware hoặc không đầy đủ; trường hợp đó là
  `UNKNOWN`.
- Route public, health, login, docs và metrics không trở thành candidate nếu
  không có dấu hiệu nhạy cảm khác.
- Index chỉ lưu identifier, đường dẫn tương đối, line và classification; raw
  source không đi qua public model.
- Finding không bị tự động xóa hoặc suppress.

## Benchmark

Benchmark detector logic tách khỏi benchmark triage LLM. Manifest dùng schema
`LogicAuthzDataset`, có development/calibration/held_out split, repository
identifier, route line, label và trạng thái audit. Fixture benchmark không được
dùng để tuyên bố quality claim.

Chạy benchmark offline:

```powershell
python scripts/benchmark_fastapi_authz.py `
  --manifest benchmarks/LogicAuthz/fastapi-fixture.json `
  --output benchmarks/BenchmarkOutput/sprint2-fastapi-authz-fixture.json
```

Held-out quality gate của detector thật:

- Precision >= 0.85.
- Recall >= 0.80.
- F1 >= 0.82.
- Không false positive trên router-level dependency negative controls.
- Held-out đã freeze và binary cases có review độc lập/adjudication.
- Dataset claim-bearing phải có ít nhất hai repository FastAPI độc lập.

Benchmark hồi quy pipeline triage 20 repository × 3 paired repetitions vẫn là
đánh giá riêng sau khi detector offline vượt gate. Các chỉ số cần giữ: unsafe FP,
selective accuracy, coverage, manual-review rate, verdict stability và
policy-action stability.

## Ngoài phạm vi

- Năm loại logic bug tổng quát.
- IDOR/BOLA cho đến khi detector bắt buộc vượt gate.
- Race condition/TOCTOU, cross-service authorization và dynamic policy proof.
- Auto-fix, auto-suppression hoặc CI/CD gate.

## Qualification status — detector v2

- Qualification dataset: 80 case (35 natural RealVuln v2 + 45 controlled
  mutations), cân bằng 40 positive / 40 negative.
- Detector result: TP=40, FP=0, FN=0, TN=39, UNKNOWN=1; precision=100%,
  recall=100%, F1=100% trên dataset này.
- Held-out: 38 case; TP=20, FP=0, FN=0, TN=18, UNKNOWN=0.
- Ba run deterministic giống hệt từng byte.
- Paired offline regression: 20 repo × 3 repetitions × 2 branches, 120 run;
  common verdict và policy-action stability đều 100%, không có pipeline error.
- Security suite: 175 passed, 2 skipped; full suite: 488 passed, 2 skipped.
- Governance gate còn chờ independent two-reviewer audit; real-LLM regression
  chưa chạy vì môi trường không có provider credential. Không tuyên bố quality
  claim ngoài dataset trước khi hai điều kiện này hoàn tất.
