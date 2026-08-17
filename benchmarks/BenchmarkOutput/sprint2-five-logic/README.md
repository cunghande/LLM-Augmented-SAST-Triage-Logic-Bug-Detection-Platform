# Sprint 2 five-class detector benchmark

## Dataset and metric policy

- Dataset: `Real-Vuln-Benchmark` repositories and reviewed ground truth already
  cloned under `benchmarks/ExternalTargets`.
- Scope: 25 repositories; 63 explicitly mapped cases (49 positive, 14 negative).
- Only reviewed locations whose label maps to one of the five Sprint 2 classes
  enter the confusion matrix.
- Predictions elsewhere are `unreviewed_candidates`, not assumed TP or FP.
- These are deterministic detector metrics, not real-LLM quality metrics.

## Before/after

| Run | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| v1, initial five-class implementation | 23 | 6 | 26 | 8 | 0.7931 | 0.4694 | 0.5897 |
| v3, evidence/propagation + risk-priority refinements | 42 | 2 | 7 | 12 | 0.9545 | 0.8571 | 0.9032 |

The improvement comes from bounded request-value propagation, semantic authz
guard recognition, subject-scoped lookup checks, atomic-control distinctions,
and workflow proof checks. It is not evidence that all findings are correct:
v3 also produced 384 candidates outside reviewed benchmark locations.

## v3 by class

| Class | Positive/negative cases | TP | FP | FN | TN | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Missing authz / IDOR | 10 / 14 | 9 | 2 | 1 | 12 | 0.8571 |
| Mass assignment | 20 / 0 | 18 | 0 | 2 | 0 | 0.9474 |
| Race / TOCTOU | 1 / 0 | 1 | 0 | 0 | 0 | 1.0000 |
| Business-rule bypass | 15 / 0 | 11 | 0 | 4 | 0 | 0.8462 |
| Insecure workflow | 3 / 0 | 3 | 0 | 0 | 0 | 1.0000 |

Classes without reviewed negative cases do not have independently validated
precision. The race and workflow sample sizes are especially small.

## Artifacts

- `realvuln-full-v1.json`: baseline before refinements.
- `realvuln-full-v2.json`: refinement run before the final file-priority check.
- `realvuln-full-v3.json`: final rerun after risk-based file prioritization.
- `realvuln-pilot-v1.json`: early two-repository pilot; not used as final metric.
