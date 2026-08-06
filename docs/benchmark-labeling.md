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
