# Qwen3-14B-AWQ triage benchmark — prompt v8 / B200

- Model: `Qwen/Qwen3-14B-AWQ`
- GPU requested: `B200`
- Prompt: `triage-prompt-v8`
- Scanner artifact/config: `benchmarks/BenchmarkRun/semgrep-p-python.json` / `p/python`
- Scoreable findings: 93
- Ground truth: 77 vulnerable, 16 benign
- Schema success: 100.00%
- Decisive coverage: 94.62%
- Selective accuracy: 90.91%
- Accuracy with abstentions/errors unresolved: 86.02%
- Balanced accuracy with abstentions/errors unresolved: 76.70%
- Unsafe vulnerable FP candidates: 0
- Automatic policy resolution: 72.04%
- Elapsed including cold start: 320.16 s
- First request including cold start: 146.81 s
- Steady-state mean: 1.8 s/finding

## Nhận xét kết quả

- LLM phân loại đúng 80/93 finding; trong 88 finding có verdict rõ ràng, 80 finding được phân loại đúng.
- Khả năng nhận diện vulnerable: 70/77 finding được phân loại đúng là `LIKELY_TP`.
- Khả năng nhận diện benign: 10/16 finding được phân loại đúng là `LIKELY_FP`.
- 5/93 finding được chuyển sang `NEEDS_REVIEW` thay vì kết luận tự động.
- Policy không đưa finding vulnerable nào vào `FP_CANDIDATE`.

## Giới hạn

`NEEDS_REVIEW` and provider errors are abstentions/unresolved. This is a single
triage run on scoreable scanner findings, not a scanner precision/recall claim.
OWASP label được map ở cấp test case; một case có nhiều finding có thể làm metric
unsafe-FP bảo thủ hơn độ đúng ở cấp finding.
