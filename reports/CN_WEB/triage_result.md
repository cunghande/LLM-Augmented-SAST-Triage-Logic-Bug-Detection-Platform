# LLM SAST Automated Triage Summary Report

Total Findings Processed: **11**

## Classification Breakdown
- **True Positives (TP)**: 0 (0.0%
- **False Positives (FP)**: 10 (90.9%
- **Needs Review**: 1 (9.1%

## Confidence Routing Action Groups
- Auto-suppress Candidates: 10
- High Confidence TPs: 0
- Manual Review Needed: 1

## Detailed Findings
| ID | Scanner | Rule ID | File:Line | Verdict | Confidence | Action Group |
|---|---|---|---|:---:|:---:|---|
| SG-E7A645422EA1 | semgrep | `javascript.lang.security.audit.sqli.node-mysql-sqli.node-mysql-sqli` | `D:\Code\AI security\repos\CN_WEB\backend\scripts\run-database-files.js:81` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-2A8A99D9289E | semgrep | `javascript.lang.security.audit.sqli.node-mysql-sqli.node-mysql-sqli` | `D:\Code\AI security\repos\CN_WEB\backend\scripts\seed-large-products.js:127` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-572EC6296893 | semgrep | `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp` | `D:\Code\AI security\repos\CN_WEB\backend\src\services\aiRetrievalService.js:78` | **NEEDS_REVIEW** | 0.60 | MANUAL_REVIEW |
| SG-B51A4CC6AC64 | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:12` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-0EA0665D6E3A | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:13` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-C1698F53992F | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:14` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-2366D7329DBB | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:15` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-F7B199D31728 | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:16` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-B2076107D34C | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:17` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-4D05BB3C043F | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:18` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
| SG-0F7B14947234 | semgrep | `generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash` | `D:\Code\AI security\repos\CN_WEB\database\seeders\users.sql:19` | **FP** | 0.92 | AUTO_SUPPRESS_CANDIDATE |
