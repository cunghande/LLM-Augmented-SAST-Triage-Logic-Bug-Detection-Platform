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
| v4, Strix-inspired counter-evidence verification | 42 | 0 | 7 | 14 | 1.0000 | 0.8571 | 0.9231 |
| v5, retrieval-resolution evidence | 42 | 0 | 7 | 14 | 1.0000 | 0.8571 | 0.9231 |

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
- `realvuln-full-v4-strix-evidence.json`: counter-evidence rerun that recognizes
  exact local and authorization-namespace object guards.
- `realvuln-full-v5-retrieval.json`: regression run after adding safe
  retrieval-resolution facts; detector metrics remain unchanged.
- `realvuln-pilot-v1.json`: early two-repository pilot; not used as final metric.
- `realvuln-llm-pilot-v1.json`: seven-case pilot using the real Modal
  `Qwen/Qwen3-14B-AWQ` provider and prompt v11.
- `realvuln-llm-pilot-v2-strix-evidence.json`: five-positive-case rerun using
  proof-obligation evidence and prompt v12.
- `realvuln-llm-pilot-v3-retrieval.json`: the same five-positive-case rerun
  using retrieval-resolution, class rubrics, and bounded prompt-v13 verification.

## Real-LLM pilot

The real-provider pilot selected one reviewed positive candidate from each of
the five classes and both reviewed negative candidates that the detector had
flagged. Results:

| Metric | Result |
|---|---:|
| Cases completed | 7 / 7 |
| Triage errors | 0 |
| Decisive verdicts | 1 |
| Correct decisive verdicts | 1 |
| Abstentions (`NEEDS_REVIEW`) | 6 |
| Selective accuracy | 100% (1/1) |
| Decisive coverage | 14.29% |

The one decisive result was a correct high-confidence `LIKELY_TP` for mass
assignment. Qwen abstained on the other four positive classes and both reviewed
detector false positives. Therefore this pilot proves the real provider works
without `TRIAGE_ERROR`, but it does **not** prove an accuracy improvement over
the deterministic detector. The selective-accuracy percentage has a denominator
of one and must not be presented as general model accuracy.

## Strix-inspired evidence comparison

The v4 verifier searches for class-specific counter-evidence before creating a
candidate. It recognized `require_application_view` and
`authz.load_job_for_view` as exact object-authorization controls, removing both
reviewed IDOR false positives without losing a reviewed TP. This raised detector
F1 from 0.9032 to 0.9231 on the same 63 mapped cases.

Prompt v12 adds explicit proof obligations, counter-evidence results, a bounded
attack hypothesis, and a safe reproduction plan. On the exact five positive
cases shared with the v11 pilot:

| Prompt/evidence | Decisive | Correct | Abstained | Coverage |
|---|---:|---:|---:|---:|
| v11 baseline | 1/5 | 1 | 4 | 20% |
| v12 proof obligations | 2/5 | 2 | 3 | 40% |
| v13 retrieval + bounded verifier | 3/5 | 3 | 2 | 60% |

The newly decisive case is race/TOCTOU. IDOR, business-rule bypass, and insecure
workflow still abstain because Qwen requests object-scope, domain-invariant, or
prior-state evidence beyond the bounded static trace. The result is an
improvement, but the five-case sample is too small for a general model-quality
claim. The two reviewed negatives are no longer LLM calls because v4 filters
them at the deterministic counter-evidence gate.

Prompt v13 resolves bounded static facts explicitly and makes at most one
second-pass verifier call for a logic finding that still returns
`NEEDS_REVIEW`. It made two verifier calls in this run. Business-rule bypass
became decisive and correct; IDOR and insecure workflow remained conservative
abstentions. There were no wrong decisive verdicts and no triage errors, but
the sample remains too small to claim general 100% model accuracy.
