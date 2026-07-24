# LLM SAST Automated Triage Summary Report

Total Findings Processed: **10**

## Classification Breakdown
- **True Positives (TP)**: 5 (50.0%
- **False Positives (FP)**: 0 (0.0%
- **Needs Review**: 5 (50.0%

## Confidence Routing Action Groups
- Auto-suppress Candidates: 0
- High Confidence TPs: 3
- Manual Review Needed: 7

## Detailed Findings
| ID | Scanner | Rule ID | File:Line | Verdict | Confidence | Action Group |
|---|---|---|---|:---:|:---:|---|
| SG-93DDDE3C211A | semgrep | `dockerfile.security.missing-user.missing-user` | `D:\Code\AI security\repos\Sequential-Recommender\backend\Dockerfile:13` | **TP** | 0.85 | HIGH_CONFIDENCE_TP |
| SG-FC61806617D5 | semgrep | `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query` | `D:\Code\AI security\repos\Sequential-Recommender\backend\app\db\queries.py:20` | **NEEDS_REVIEW** | 0.50 | MANUAL_REVIEW |
| SG-4ED80B458C64 | semgrep | `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query` | `D:\Code\AI security\repos\Sequential-Recommender\backend\app\db\queries.py:22` | **NEEDS_REVIEW** | 0.60 | MANUAL_REVIEW |
| SG-1E814D18BCE2 | semgrep | `python.fastapi.security.wildcard-cors.wildcard-cors` | `D:\Code\AI security\repos\Sequential-Recommender\backend\app\main.py:13` | **NEEDS_REVIEW** | 0.50 | MANUAL_REVIEW |
| SG-2F51D9DAFF0D | semgrep | `python.lang.security.deserialization.pickle.avoid-pickle` | `D:\Code\AI security\repos\Sequential-Recommender\backend\services\recommender.py:76` | **TP** | 0.70 | MANUAL_REVIEW |
| SG-FD15B2B6EB93 | semgrep | `python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected` | `D:\Code\AI security\repos\Sequential-Recommender\backend\services\recommender.py:262` | **NEEDS_REVIEW** | 0.60 | MANUAL_REVIEW |
| SG-CAE46A44427E | semgrep | `yaml.docker-compose.security.no-new-privileges.no-new-privileges` | `D:\Code\AI security\repos\Sequential-Recommender\docker-compose.yml:4` | **TP** | 0.70 | MANUAL_REVIEW |
| SG-133FD7033798 | semgrep | `yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service` | `D:\Code\AI security\repos\Sequential-Recommender\docker-compose.yml:4` | **NEEDS_REVIEW** | 0.60 | MANUAL_REVIEW |
| SG-8621617066D4 | semgrep | `dockerfile.security.missing-user.missing-user` | `D:\Code\AI security\repos\Sequential-Recommender\frontend\Dockerfile:24` | **TP** | 0.95 | HIGH_CONFIDENCE_TP |
| SG-69A95904404F | semgrep | `python.lang.security.deserialization.pickle.avoid-pickle` | `D:\Code\AI security\repos\Sequential-Recommender\ml\colab_model_api.py:81` | **TP** | 0.85 | HIGH_CONFIDENCE_TP |
