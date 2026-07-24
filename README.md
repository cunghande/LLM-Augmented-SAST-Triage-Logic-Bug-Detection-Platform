# LLM-Augmented SAST Triage & Logic-Bug Detection Platform

> Nền tảng tự động tăng cường SAST bằng LLM (Qwen 3:8b local) — phân loại cảnh báo, phát hiện lỗi logic, đánh giá rủi ro và sinh bản vá mã nguồn.

---

## Cấu Trúc Dự Án

```text
AI security/
│
├── benchmark/                          # Bộ nhãn ground truth để đánh giá độ chính xác
│   ├── CN_WEB_ground_truth.json
│   ├── CN_WEB_logic_bugs_ground_truth.json
│   └── Sequential_Recommender_ground_truth.json
│
├── repos/                              # Repository mục tiêu cần phân tích
│   ├── CN_WEB/
│   └── Sequential-Recommender/
│
├── scans/                              # Output thô từ Semgrep và Gitleaks
│   ├── CN_WEB/
│   │   ├── gitleaks.json
│   │   ├── semgrep.json
│   │   └── semgrep.sarif
│   └── Sequential-Recommender/
│
├── reports/                            # Báo cáo triage và phân tích bảo mật
│   ├── CN_WEB/
│   │   ├── baseline.md                 # Khảo sát ban đầu
│   │   ├── triage_result.json/md       # Kết quả triage SAST (Sprint 1)
│   │   ├── risk_report.json            # Điểm rủi ro (Sprint 2)
│   │   ├── remediation_report.json     # Bản vá code (Sprint 2)
│   │   ├── logic_bugs.json             # Logic bugs phát hiện bởi CPG (Sprint 2)
│   │   ├── priority_report.md          # Báo cáo ưu tiên Executive Summary (Sprint 2)
│   │   └── manual_security_review.md   # Review thủ công AppSec (Sprint 2 - S2-04)
│   └── Sequential-Recommender/
│
├── src/                                # Mã nguồn nền tảng (Multi-Agent Platform)
│   ├── core/
│   │   └── schema.py                   # ⭐ Model trung tâm: UnifiedFinding & tất cả schema
│   ├── parsers/
│   │   ├── gitleaks.py                 # Parser Gitleaks JSON → UnifiedFinding
│   │   └── semgrep.py                  # Parser Semgrep JSON/SARIF → UnifiedFinding
│   ├── context/
│   │   └── extractor.py                # Trích xuất ngữ cảnh code ±15 dòng + secret redaction
│   ├── triage/
│   │   ├── llm_client.py               # ⭐ Client Ollama Qwen 3:8b (dual-endpoint + fallback)
│   │   ├── prompts.py                  # Thư viện system/user prompt cho triage SAST
│   │   └── engine.py                   # Agent 1 - SAST Triage Engine
│   ├── logic_bugs/
│   │   ├── ast_graph.py                # ⭐ CPG/AST Code Graph Extractor (Entrypoint→Guard→Sink)
│   │   ├── analyzer.py                 # Lọc route rủi ro cao từ CPG
│   │   ├── prompts.py                  # Prompt cho Logic-Bug Detection (5 lớp lỗi)
│   │   └── detector.py                 # Agent 2 - Logic-Bug Detection Engine
│   ├── risk/
│   │   └── scorer.py                   # Agent 3a - Risk Scoring Engine (5 thành phần)
│   ├── remediation/
│   │   └── generator.py                # Agent 3b - Code Diff Patch Generator
│   ├── reporters/
│   │   └── reporter.py                 # Sinh JSON/Markdown/Priority reports
│   └── cli.py                          # ⭐ CLI entrypoint (9 lệnh)
│
├── tests/                              # Unit tests (9/9 pass)
│   ├── test_parsers.py
│   ├── test_extractor.py
│   ├── test_triage_engine.py
│   ├── test_ast_graph.py
│   ├── test_risk_scorer.py
│   └── test_remediation.py
│
├── scripts/
│   └── run_scans.py                    # Script chạy Semgrep + Gitleaks tự động
│
├── LLM-Augmented SAST Project Plan.md  # Kế hoạch Sprint đầy đủ
└── requirements.txt                    # Python dependencies
```

---

## Kiến Trúc Hệ Thống (Multi-Agent Platform)

```text
Input (Repos + Scan Files)
         │
         ▼
  ┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
  │ Agent 1     │     │ Agent 2          │     │ Agent 3           │
  │ SAST Triage │     │ Logic-Bug        │     │ Risk & Remediation│
  │ ─────────── │     │ Detection        │     │ ─────────────────  │
  │ Semgrep/    │     │ ─────────────── │     │ Risk Scoring      │
  │ Gitleaks    │     │ AST/CPG Graph    │     │ Code Diff Patch   │
  │ → TP/FP/NR  │     │ → IDOR/MASS/... │     │ → Priority Report │
  └─────────────┘     └──────────────────┘     └───────────────────┘
         │                    │                          │
         └────────────────────┴──────────────────────────┘
                              │
                    Unified Finding Schema
                              │
                    JSON + Markdown Reports
```

---

## Hướng Dẫn Cài Đặt

### Yêu cầu hệ thống
- Python 3.10+
- [Ollama](https://ollama.com/) đã cài đặt
- Semgrep CLI (`pip install semgrep`)
- Gitleaks ([tải về tại đây](https://github.com/gitleaks/gitleaks/releases))

### Bước 1: Clone và cài dependencies

```bash
git clone https://github.com/cunghande/LLM-Augmented-SAST-Triage-Logic-Bug-Detection-Platform.git
cd "LLM-Augmented-SAST-Triage-Logic-Bug-Detection-Platform"
pip install -r requirements.txt
```

### Bước 2: Khởi động LLM local (Qwen 3:8b)

```bash
# Pull model (lần đầu)
ollama pull qwen3:8b

# Khởi động Ollama server
ollama serve

# (Terminal khác) Kiểm tra model sẵn sàng
ollama run qwen3:8b
```

### Bước 3: Clone repository mục tiêu

```bash
# Ví dụ clone CN_WEB
git clone https://github.com/cunghande/CN_WEB repos/CN_WEB

# Hoặc clone Sequential-Recommender
git clone https://github.com/cunghande/Sequential-Recommender repos/Sequential-Recommender
```

### Bước 4: Kiểm tra cài đặt

```bash
# Chạy bộ unit tests — phải đạt 9/9 PASS
python -m unittest discover tests
```

---

## Hướng Dẫn Sử Dụng (CLI Reference)

### Bước đầy đủ từ A → Z cho 1 repository

```bash
# 1. Quét Semgrep + Gitleaks
python scripts/run_scans.py --repo CN_WEB

# 2. Triage SAST findings bằng Qwen 3:8b
python -m src.cli triage \
  --scans-dir scans/CN_WEB \
  --repo-dir repos/CN_WEB \
  --repo-name CN_WEB \
  --output reports/CN_WEB/triage_result.json

# 3. Phát hiện Logic Bugs qua CPG
python -m src.cli detect-logic-bugs \
  --repo-dir repos/CN_WEB \
  --repo-name CN_WEB \
  --output reports/CN_WEB/logic_bugs.json

# 4. Tính điểm Risk Score
python -m src.cli score-risk \
  --input reports/CN_WEB/triage_result.json \
  --output reports/CN_WEB/risk_report.json

# 5. Sinh bản vá Code Diff
python -m src.cli generate-remediation \
  --input reports/CN_WEB/triage_result.json \
  --output reports/CN_WEB/remediation_report.json

# 6. Sinh Priority Report Executive Summary
python -m src.cli priority-report \
  --input reports/CN_WEB/triage_result.json \
  --repo-name CN_WEB \
  --output reports/CN_WEB/priority_report.md
```

---

### Danh sách đầy đủ tất cả lệnh CLI

| Lệnh | Chức năng |
|---|---|
| `python scripts/run_scans.py` | Quét tất cả repo trong `repos/` bằng Semgrep + Gitleaks |
| `python scripts/run_scans.py --skip-existing` | Bỏ qua repo đã có file scan sẵn |
| `python scripts/run_scans.py --repo CN_WEB` | Chỉ quét 1 repo cụ thể |
| `python -m src.cli triage ...` | Triage SAST findings bằng Qwen 3:8b |
| `python -m src.cli parse ...` | Chuẩn hóa file scan thô sang Unified Schema |
| `python -m src.cli evaluate ...` | Đo Precision / Recall / F1 với benchmark |
| `python -m src.cli detect-logic-bugs ...` | Phát hiện lỗi logic qua AST/CPG + LLM |
| `python -m src.cli score-risk ...` | Tính điểm rủi ro 5 thành phần |
| `python -m src.cli generate-remediation ...` | Sinh Code Diff Patch đề xuất vá lỗi |
| `python -m src.cli priority-report ...` | Sinh Priority Report xếp hạng theo Risk Score |
| `python -m unittest discover tests` | Chạy toàn bộ unit tests |

---

## Bộ Báo Cáo Chuẩn Cho Mỗi Repository

Mỗi repo sau khi phân tích sẽ có **7 file báo cáo** đầy đủ trong `reports/<tên_repo>/`:

| File | Loại | Sinh bởi |
|---|---|---|
| `baseline.md` | Markdown | Thủ công |
| `triage_result.json` | JSON | Agent 1 (Qwen 3:8b) |
| `triage_result.md` | Markdown | Agent 1 (Qwen 3:8b) |
| `logic_bugs.json` | JSON | Agent 2 (CPG + Qwen 3:8b) |
| `risk_report.json` | JSON | Agent 3a (Risk Scorer) |
| `remediation_report.json` | JSON | Agent 3b (Remediation Gen) |
| `priority_report.md` | Markdown | Reporter (tổng hợp) |
| `manual_security_review.md` | Markdown | AppSec chuyên gia |

---

## Sprint Progress

| Sprint | Mục tiêu | Trạng thái |
|---|---|:---:|
| **Sprint 1** | Baseline, Benchmark và Automated Triage MVP | ✅ 100% |
| **Sprint 2** | Logic-Bug Detection, Risk Scoring và Remediation | ✅ 100% |
| **Sprint 3** | FP Suppression Database, Custom Semgrep Rules | 🔜 Chưa bắt đầu |
| **Sprint 4** | Jenkins CI/CD Integration & Dashboard | 🔜 Chưa bắt đầu |
