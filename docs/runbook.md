# Runbook

## Baseline Scan

1. Clone a target repository into `repos/`.
2. Run scanners and save raw output into `scans/<repo-name>/`.
3. Normalize scanner output.
4. Generate a triage report in `reports/`.

## Data Handling

- Do not commit secrets, customer data, or private source code snapshots.
- Redact sensitive snippets before sending them to any external model endpoint.
- Keep raw scanner artifacts local unless sharing has been approved.

