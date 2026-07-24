# Architecture

## Core Flow

```text
Target repo
  -> scanner outputs
  -> finding normalizer
  -> context extractor
  -> LLM triage
  -> risk scoring
  -> reports and feedback loop
```

## Main Components

- Scanner adapters: parse Semgrep, Gitleaks, and future scanner formats.
- Finding schema: normalize all scanner findings into one internal model.
- Context extractor: collect relevant code, routes, config, and dependency context.
- Triage engine: classify findings as TP, FP, or NEEDS_REVIEW.
- Risk engine: rank confirmed findings by impact and reachability.
- Feedback store: remember confirmed false positives and suppress repeat noise.

