# Sprint 1 Benchmark Labeling Guideline

Benchmark records use one of four labels:

- `TP`: the finding is confirmed relevant and actionable.
- `FP`: the finding is confirmed not applicable in the target code.
- `DISPUTED`: reviewers do not agree and the record must not be used as a
  binary quality outcome.
- `INSUFFICIENT_CONTEXT`: the available evidence cannot support a label.

Each record must identify the repository/sample, scanner, artifact reference,
finding instance, reviewer rationale, evidence reference, split and benchmark
version. Raw source, secrets, tokens and raw scanner artifacts do not belong in
the benchmark dataset.

Reviewers should use cross-review and adjudication for disputed records. A
policy action is not a ground-truth label: `MANUAL_REVIEW` and `TRIAGE_ERROR`
must not be silently counted as FP or FN.

## Split discipline

- `development`: may be inspected while implementing evidence extraction.
- `calibration`: may be used to choose a prompt/policy version, but changes must
  be frozen before held-out evaluation.
- `held_out`: must not be inspected to tune prompts, rules or thresholds.

The loader rejects any other split, duplicate finding IDs and record-level
benchmark version mismatches. Metrics are reported separately for every split.
A model-quality claim is supported only when a real provider is evaluated on a
non-synthetic dataset with matched held-out records.

For the claim-bearing sample, use two independent reviewers when possible.
Record disagreement as `DISPUTED`; an adjudicator must document the final
rationale before converting a disputed record to TP or FP. If staffing permits
only one reviewer, state that limitation instead of presenting the labels as
independently verified ground truth.

## OWASP Benchmark Python scoring

Use `load_owasp_expected_results()` and `score_owasp_findings()` for OWASP
`expectedresults-*.csv` files. A finding is scored only when both its
`BenchmarkTestNNNNN` identity and mapped vulnerability category match the
expected row. A finding for another category in the same file is out of scope,
not a detection of that benchmark case.

The built-in Semgrep mapping is versioned as
`semgrep-python-category-map-v1`. Report this mapping version, the benchmark
version, scanner configuration, out-of-scope count, and reproducible command.
Scanner detection metrics and LLM triage metrics remain separate; report
`NEEDS_REVIEW` as abstention coverage instead of converting it to TP or FP.
