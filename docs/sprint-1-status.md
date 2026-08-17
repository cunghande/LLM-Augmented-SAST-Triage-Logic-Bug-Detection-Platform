# Sprint 1 Implementation Status

This document records implemented behavior only. It does not claim the KPI
targets from the project plan without a real benchmark and real-provider run.

Implemented Sprint 1 components:

- Semgrep and Gitleaks JSON normalization with Gitleaks early redaction.
- Safe repository reading, Python scope selection, line-window fallback and
  context sanitization.
- Fake provider, safe prompt boundary, structured decision validation and an
  optional OpenAI-compatible real provider with offline transport injection.
- Conservative policy, per-finding errors, artifact/repository binding state.
- Explicit safe JSON and Markdown report projections with atomic writes.
- Safe Semgrep/Gitleaks subprocess runners.
- Artifact `triage` and `scan-and-triage` CLI modes.
- Small versioned benchmark loader and deterministic evaluation metrics.

The Fake provider is for deterministic pipeline tests only. No model-quality
claim is supported by a Fake-provider evaluation run.

## Benchmark checkpoint — 2026-08-14

Prompt v10 was run with the native backend and Qwen3-14B-AWQ on Modal B200 over
93 scoreable OWASP Benchmark Python findings:

- 93/93 schema-valid decisions; zero provider errors and zero minimal-schema recoveries.
- 38 decisive model verdicts, all correct: 40.86% coverage and 100% selective accuracy.
- 23/77 vulnerable findings recognized; the remaining 54 were `NEEDS_REVIEW`.
- 15/16 benign findings recognized; one was `NEEDS_REVIEW`.
- Policy actions: 12 `LIKELY_TP`, 2 `FP_CANDIDATE`, 79 `MANUAL_REVIEW`.
- Zero vulnerable finding was placed in `FP_CANDIDATE`.

The operational and safety gates passed, but Sprint 1 quality acceptance is not
closed: manual review remains 84.95%, the run is single-shot, and OWASP Python
is a public synthetic benchmark rather than a curated independently reviewed
held-out repository dataset. See the [v10 native benchmark report](../benchmarks/BenchmarkOutput/qwen3-14b-awq-triage-benchmark-v10-native-b200.md).
