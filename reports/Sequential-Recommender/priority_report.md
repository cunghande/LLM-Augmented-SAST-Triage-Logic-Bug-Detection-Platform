# Security Priority Report — Sequential-Recommender

> **Generated**: 2026-07-24 | **Repository**: `Sequential-Recommender`

---

## Executive Summary

Platform scanned **Sequential-Recommender** and discovered **10 findings** from automated SAST scanners.
After LLM-augmented triage by **Qwen 3:8b**, the results were reduced and prioritized as follows:

| Metric | Value |
|---|---|
| Total Findings | **10** |
| True Positives (Confirmed) | **5** |
| False Positives (Suppressed) | **0** |
| Needs Manual Review | **5** |
| Critical Risk Findings | **0** |
| High Risk Findings | **3** |
| Medium Risk Findings | **2** |

---

## Priority Action List (Sorted by Risk Score)

| Priority | Finding ID | Rule / Bug Type | File:Line | Risk Score | Level | Remediation Summary |
|:---:|---|---|---|:---:|:---:|---|
| **#1** | `SG-69A95904404F` | `python.lang.security.deserialization.pickle.avoid-pickle` | `Sequential-Recommender/ml/colab_model_api.py:81` | **3.83** | 🟠 HIGH | Replace unsafe `pickle.load()` with safe JSON or safetensors... |
| **#2** | `SG-93DDDE3C211A` | `dockerfile.security.missing-user.missing-user` | `Sequential-Recommender/backend/Dockerfile:13` | **3.65** | 🟠 HIGH | Add a non-root USER directive to prevent privileged containe... |
| **#3** | `SG-8621617066D4` | `dockerfile.security.missing-user.missing-user` | `Sequential-Recommender/frontend/Dockerfile:24` | **3.65** | 🟠 HIGH | Add a non-root USER directive to prevent privileged containe... |
| **#4** | `SG-2F51D9DAFF0D` | `python.lang.security.deserialization.pickle.avoid-pickle` | `Sequential-Recommender/backend/services/recommender.py:76` | **3.33** | 🟡 MEDIUM | Replace unsafe `pickle.load()` with safe JSON or safetensors... |
| **#5** | `SG-CAE46A44427E` | `yaml.docker-compose.security.no-new-privileges.no-new-privileges` | `Sequential-Recommender/docker-compose.yml:4` | **3.20** | 🟡 MEDIUM | Remediate yaml.docker-compose.security.no-new-privileges.no-... |

---

## Recommended Next Steps

1. **Immediate Action (Critical/High)**: Address all Critical and High risk findings within 1 sprint.
2. **Scheduled Remediation (Medium)**: Address Medium risk findings in the next 2 sprints.
3. **Manual Review**: Verify all NEEDS_REVIEW findings with AppSec team.
4. **Re-scan**: After applying fixes, re-run the triage pipeline to confirm remediation.

---

*Full technical details available in `triage_result.json`, `risk_report.json`, and `remediation_report.json`.*