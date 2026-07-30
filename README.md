# Modular LLM-Augmented SAST & Logic-Bug Analysis Pipeline

> **Product Status**: **RESEARCH PROTOTYPE**  
> *Production deployment requires completing holdout evaluation, shadow CI/CD integration, failure policy enforcement, model regression testing, patch validation, audit controls, and real-repository verification.*

---

## 📌 Architectural Overview (Dual-Branch Parallel Architecture)

```text
                                Raw Inputs
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌───────────────────────────────┐         ┌───────────────────────────────────┐
│  BRANCH A: SAST TRIAGE ENGINE │         │   BRANCH B: LOGIC-BUG DETECTOR    │
│  (Semgrep & Gitleaks Inputs)  │         │   (Direct Repository Analysis)    │
│               │               │         │                 │                 │
│ Parsing → Multi-tier Context  │         │ Lightweight Security Context      │
│  (AST / AST-Fallback Context) │         │ Graph (AST, Entrypoint, Guard,    │
│               │               │         │ Sink Analysis & Classification)   │
│  LLM Evaluation Engine        │         │                 │                 │
│ (TP / FP / NEEDS_MORE_CONTEXT)│         │ Generate LOGIC_BUG_CANDIDATE      │
└───────────────┬───────────────┘         └─────────────────┬─────────────────┘
                │                                           │
                └───────────────────┬───────────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │   FINDING MERGER    │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ RISK SCORING ENGINE │
                         │ (0-100 Rubric Scale)│
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ REMEDIATION ENGINE  │
                         │ (PATCH_CANDIDATE &  │
                         │  Validation Check)  │
                         └──────────┬──────────┘
```

---

## 🔬 Core Pipeline Features & Guarantees

1. **Terminology Rigor**: Modules without active planning loops are strictly designated as **Engines**, **Detectors**, **Extractors**, **Scorers**, or **Pipeline Stages**.
2. **Parallel Dual-Branch Architecture**:
   - **Branch A**: SAST triage engine processing Semgrep/Gitleaks into `UnifiedFinding`.
   - **Branch B**: Direct repository analysis emitting `LOGIC_BUG_CANDIDATE` items.
   - **Merger**: Combines finding streams prior to Risk Scoring and Remediation.
3. **Multi-Tier Context Extractor**:
   - Maps finding lines to AST nodes, class signatures, annotations, parameters, imports, local guards, and slicing heuristics.
   - Line window ($\pm 15$ lines) is strictly used as fallback when AST parsing fails, tagged with `context_quality = "FALLBACK"`.
4. **Lightweight Security Context Graph**:
   - AST-derived graphs are named `LightweightSecurityContextGraph` and document limitations (lacks full interprocedural CFG/CPG).
5. **Guard Taxonomy**:
   - Categorizes security guards into 7 types: `AUTHENTICATION`, `ROLE`, `OWNERSHIP`, `TENANT`, `STATE_TRANSITION`, `VALIDATION`, `TRANSACTION`.
   - Absence of guard produces a `LOGIC_BUG_CANDIDATE`, not vulnerability proof.
6. **Verifiable Evidence & Decision Metadata**:
   - Structured `EvidenceReference` (`file`, `line`, `symbol`, `source`, `sink`, `guard`, `code_path`).
   - Supports `NEEDS_MORE_CONTEXT` / `NEEDS_REVIEW` abstentions instead of LLM speculation.
7. **Secret Taxonomy**:
   - Gitleaks secrets classified under 7 categories: `VALID_SECRET`, `REVOKED_SECRET`, `TEST_CREDENTIAL`, `PLACEHOLDER`, `HISTORICAL_SECRET`, `FALSE_MATCH`, `UNKNOWN_VALIDITY`.
8. **Rubric-Based Risk Scoring**:
   - Normalized 0–100 scale based on explicit 1–5 component rubrics. Decision confidence **never** reduces high-impact risk scores.
9. **Remediation & Patch Validation**:
   - LLM patch outputs labeled as `PATCH_CANDIDATE` bound to `commit_sha`. Never auto-applied. Falls back to `GUIDANCE_ONLY` or `INSUFFICIENT_CONTEXT`.
10. **Fail-Safe Operation**:
    - Processing errors in LLM or AST preserve original findings for `MANUAL_REVIEW`.

---

## 🚀 Usage & CLI Reference

### 1-Click Parallel Pipeline

```bash
# Run dual-branch parallel pipeline on latest cloned repo
python3 -m src.cli run-pipeline --repo-dir repos/CN_WEB --scans-dir scans/CN_WEB --repo-name CN_WEB
```

### Versioned Rigorous Benchmark Evaluation

```bash
# Run holdout benchmark evaluation reporting N, FNR, abstention rate, and rule family metrics
python3 scripts/run_benchmark_eval.py --benchmark java --sample 50
```

### Unit Tests Execution

```bash
# Run all unit tests (12/12 PASS)
python3 -m unittest discover tests
```

---

## 📁 Source Directory Structure

```text
src/
├── core/
│   └── schema.py                # Central UnifiedFinding model, SecretTaxonomy, GuardCategory, DecisionMetadata
├── context/
│   └── extractor.py             # Multi-tier Context Extractor (AST + Slicing + File-aware Redaction)
├── parsers/
│   ├── gitleaks.py              # Gitleaks parser with SecretTaxonomy
│   └── semgrep.py               # Semgrep parser with Rule Family tags
├── triage/
│   ├── engine.py                # SAST Triage Engine (Branch A) with DecisionMetadata & EvidenceReference
│   ├── prompts.py               # Prompt library v2.0 with NEEDS_MORE_CONTEXT support
│   └── llm_client.py            # Dual-endpoint Ollama client
├── logic_bugs/
│   ├── ast_graph.py             # LightweightSecurityContextGraph (7 Guard Categories)
│   ├── detector.py              # Logic-Bug Detector (Branch B - LOGIC_BUG_CANDIDATE)
│   └── neo4j_exporter.py        # Graph visualization exporter
├── pipeline/
│   └── parallel_pipeline.py     # Orchestrator for Dual-Branch Analysis & Finding Merger
├── risk/
│   └── scorer.py                # Rubric-based Risk Scorer (0-100 scale)
├── remediation/
│   └── generator.py             # Remediation Engine (PATCH_CANDIDATE + validation)
└── reporters/
    ├── reporter.py              # JSON / Markdown / Priority Reports
    └── audit.py                 # Audit logging & security controls
```
