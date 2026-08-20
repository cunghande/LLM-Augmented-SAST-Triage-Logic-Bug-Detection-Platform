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

## Benchmark status

Historical benchmark artifacts and metrics were cleared during the Joern-only
transition. No current quality claim is recorded until a new repository and
ground truth are supplied and the benchmark is rerun.
