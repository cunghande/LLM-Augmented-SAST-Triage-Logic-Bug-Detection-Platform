# Sprint 2 final qualification report

## Kết luận

Phần kỹ thuật tự động của Sprint 2 đã hoàn tất. Detector bắt buộc vượt toàn bộ
ngưỡng metric trên qualification dataset 80 case, pipeline regression và security
tests đều đạt. Sprint 2 **chưa thể đóng theo governance gate** vì còn thiếu audit
độc lập hai reviewer. Real-LLM regression cũng chưa chạy vì môi trường không có
Modal CLI/token, OpenAI key hoặc local Ollama provider được cấu hình.

## Detector qualification

| Chỉ số | Kết quả | Gate |
|---|---:|---:|
| Dataset | 80 case | >= 80 |
| Positive / negative | 40 / 40 | >= 40 / 40 |
| TP / FP / FN / TN | 40 / 0 / 0 / 39 | — |
| UNKNOWN | 1 (1.25%) | báo riêng |
| Precision | 100% | >= 85% |
| Recall | 100% | >= 80% |
| F1 | 100% | >= 82% |
| False-positive rate | 0% | — |

Held-out có 38 case: TP=20, FP=0, FN=0, TN=18, UNKNOWN=0. Ba lần chạy
qualification giống hệt từng byte, SHA-256
`5cd0ab987beee016b92889c956f7ab38204be258b1b68b6dd729b6ae358425f0`.

Dataset gồm 35 endpoint tự nhiên RealVuln v2 và 45 mutation tạo trong thư mục
tạm từ handler FastAPI thật. Mutation source không được lưu vào artifact; manifest
chỉ chứa provenance, route location, split, theme và expected label.

## Pipeline regression 20 x 3

- 20 repository FastAPI, 3 repetitions, baseline/candidate paired: 120 runs.
- Semgrep và Gitleaks thành công trên 20/20 repository.
- Common-finding verdict stability: 100%.
- Common-finding policy-action stability: 100%.
- Repetition verdict/policy stability: 100%.
- Pipeline/provider error runs: 0; TRIAGE_ERROR: 0.
- Baseline trung bình 1.5 finding/repo; candidate 14 finding/repo.
- Runtime pipeline trung bình: baseline 0.924 s, candidate 1.146 s/run.

Regression dùng fake provider vì không có real-provider credential. Fake provider
đưa mọi finding vào MANUAL_REVIEW, nên baseline có 90 và candidate có 840 manual
reviews trên tổng 60 run mỗi branch. Đây là pipeline regression, không phải bằng
chứng LLM coverage/accuracy hoặc chi phí model thật.

## Security và leak tests

- Full suite: 488 passed, 2 skipped, 0 failed.
- Security-focused suite: 175 passed, 2 skipped, 0 failed.
- Deep scan 12 qualification artifacts: 0 absolute-path/secret-pattern match.
- Ruff: PASS.

## Việc còn cần con người/hạ tầng ngoài

1. Hai reviewer độc lập điền `ground-truth-audit.json`, ghi rationale và adjudicate
   mọi disagreement. Hiện 80/80 case là `UNREVIEWED`.
2. Khi có Modal/Ollama/real-provider credential, chạy lại paired regression để đo
   selective accuracy, auto coverage, manual-review reduction và chi phí thật.
3. Chỉ sau hai bước trên mới đổi `quality_claim_supported` thành true và đóng Sprint 2.

IDOR/BOLA vẫn là stretch goal, không phải điều kiện đóng detector bắt buộc.
