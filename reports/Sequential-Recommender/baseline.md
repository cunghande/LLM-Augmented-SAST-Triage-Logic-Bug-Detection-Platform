# Sequential-Recommender Baseline Report

Date: 2026-07-24

## Repository Overview

- **Target path**: `repos/Sequential-Recommender`
- **App type**: Sequential Recommender System (E-commerce AI Recommendation Platform)
- **Backend**: Python 3.10, FastAPI, PyTorch, MySQL, SQLAlchemy, Uvicorn
- **Frontend**: Next.js 18, React, Node.js
- **Security-relevant features**: User/item interaction tracking, GRU4Rec model inference, database seed scripts, Docker deployments.

## Scanner Status

| Tool | Status | Findings Discovered | Notes |
|---|---|---|---|
| Gitleaks | Passed | 0 Leaks | No hardcoded secrets/API keys found in repository history. |
| Semgrep | Passed | 10 Findings | Found Dockerfile missing USER, SQLAlchemy raw query, Pickle deserialization, FastAPI CORS wildcard. |

## Attack Surface & Findings Breakdown

| ID | Category | File:Line | Severity | Review Focus |
|---|---|---|---|---|
| SG-93DDDE3C211A | Dockerfile Security | `backend/Dockerfile:13` | HIGH | Lacks USER directive, runs container process as root. |
| SG-8621617066D4 | Dockerfile Security | `frontend/Dockerfile:24` | HIGH | Next.js runner stage lacks USER directive. |
| SG-69A95904404F | Deserialization (CWE-502) | `ml/colab_model_api.py:81` | MEDIUM | Uses `pickle.load()` on model artifacts. RCE potential. |
| SG-2F51D9DAFF0D | Deserialization (CWE-502) | `backend/services/recommender.py:76` | MEDIUM | Uses `pickle.load()` on local model artifacts. |
| SG-CAE46A44427E | Privilege Escalation | `docker-compose.yml:4` | MEDIUM | DB service lacks `no-new-privileges:true`. |
| SG-1E814D18BCE2 | Misconfiguration | `backend/app/main.py:13` | MEDIUM | FastAPI CORS uses `allow_origins=["*"]`. |
