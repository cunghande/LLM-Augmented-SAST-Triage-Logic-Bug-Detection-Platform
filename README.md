# LLM-Augmented SAST Platform

Workspace for building an LLM-assisted SAST triage and logic-bug detection platform.

## Layout

```text
.
├── benchmark/          # Labeled findings and evaluation datasets
├── config/             # Scanner, model, and platform configuration
├── docs/               # Architecture, runbooks, and project notes
├── reports/            # Generated triage and evaluation reports
├── repos/              # Target repositories cloned for analysis
├── rules/              # Semgrep and custom detection rules
├── scans/              # Raw scanner outputs
├── scripts/            # Local automation scripts
├── src/                # Platform source code
└── tests/              # Unit, integration, and fixture tests
```

## First Milestone

1. Clone one target repository into `repos/`.
2. Run Semgrep and Gitleaks against that repository.
3. Store raw outputs under `scans/`.
4. Normalize findings into the unified schema.
5. Build the first CLI triage path end to end.

