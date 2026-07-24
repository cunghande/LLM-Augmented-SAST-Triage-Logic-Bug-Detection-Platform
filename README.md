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

---

## CLI Reference & Usage Commands

### 1. Khởi động LLM Local
Đảm bảo mô hình Qwen 3:8b trên Ollama đã chạy:
```bash
ollama run qwen3:8b
```

### 2. Quét SAST Mã Nguồn (`scripts/run_scans.py`)

- **Quét tất cả các repository** trong `repos/`:
  ```bash
  python scripts/run_scans.py
  ```

- **Bỏ qua các repository đã có file scan** (Tiết kiệm thời gian):
  ```bash
  python scripts/run_scans.py --skip-existing
  ```

- **Chỉ quét 1 repository cụ thể**:
  ```bash
  python scripts/run_scans.py --repo CN_WEB
  ```

### 3. Phân Loại Tự Động Bằng LLM Qwen 3:8b (`src.cli triage`)

- **Chạy Triage cho repository `CN_WEB`**:
  ```bash
  python -m src.cli triage --scans-dir scans/CN_WEB --repo-dir repos/CN_WEB --repo-name CN_WEB --output reports/CN_WEB/triage_result.json
  ```

- **Chạy Triage cho repository `Sequential-Recommender`**:
  ```bash
  python -m src.cli triage --scans-dir scans/Sequential-Recommender --repo-dir repos/Sequential-Recommender --repo-name Sequential-Recommender --output reports/Sequential-Recommender/triage_result.json
  ```

### 4. Chuẩn Hóa Dữ Liệu Scan Thô (`src.cli parse`)

- Parse file Gitleaks thô sang Unified JSON Schema:
  ```bash
  python -m src.cli parse --scanner gitleaks --input scans/CN_WEB/gitleaks.json --output scans/CN_WEB/unified_gitleaks.json
  ```

- Parse file Semgrep JSON thô sang Unified JSON Schema:
  ```bash
  python -m src.cli parse --scanner semgrep-json --input scans/CN_WEB/semgrep.json --output scans/CN_WEB/unified_semgrep.json
  ```

### 5. Đánh Giá Độ Chính Xác So Với Benchmark (`src.cli evaluate`)

- Đo đạc chỉ số Precision, Recall, F1 và Tỷ lệ lọc nhiễu FP %:
  ```bash
  python -m src.cli evaluate --triage-result reports/CN_WEB/triage_result.json --benchmark benchmark/CN_WEB_ground_truth.json
  ```

### 6. Kiểm Thử Tự Động (Unit Tests)

- Chạy bộ unit tests kiểm tra toàn bộ module nền tảng:
  ```bash
  python -m unittest discover tests
  ```


