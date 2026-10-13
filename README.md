# LLM-Augmented SAST Triage Platform

Hệ thống phân loại (triage) tự động các phát hiện bảo mật từ Semgrep và Gitleaks kết hợp kiến trúc Agent hai tầng (**Tier-1 Deterministic Bounded Engine** + **Tier-2 Controlled Multi-Turn Agent**) cùng chính sách bảo thủ (**Conservative Policy**).

> **Nguyên tắc cốt lõi:** LLM chỉ đưa ra đề xuất. Hệ thống bảo đảm **0% False Negatives** trên các lỗ hổng thật đã kiểm chứng: không bao giờ tự ý loại bỏ phát hiện; khi bằng chứng chưa tuyệt đối rõ ràng, phát hiện luôn được chuyển đến `MANUAL_REVIEW`.

---

## Tính Năng & Kiến Trúc Nổi Bật

- **Kiến trúc Triage 2 tầng (Two-Tier Architecture):**
  - **Tier-1 Deterministic Collector:** Trích xuất ngữ cảnh cục bộ, cắt lát AST, tra cứu đồ thị Joern CPG, làm sạch mã nguồn (Sanitizer) và xóa bỏ bí mật nhạy cảm (Secret Redactor `<REDACTED_SECRET>`).
  - **Tier-2 Controlled Agent (Multi-turn ReAct Loop):** Tự động kích hoạt khi gặp ca khó hoặc thiếu bằng chứng (`escalate` / `always`). Agent sử dụng tối đa 10 tools tra cứu cục bộ (chỉ đọc) để thu thập thêm bằng chứng xác thực luồng dữ liệu liên hàm và cấu hình ứng dụng.
- **Phòng thủ đa tầng (Defense-in-Depth for Agentic Security):**
  - **ToolActionValidator:** Chặn 100% tấn công Path Traversal (`../../etc/passwd`), symlink escape, injection trong tên hàm/file, và từ chối mọi quyền ghi/thực thi mã tùy ý.
  - **EvidenceLedger:** Sổ cái bằng chứng đơn điệu (monotonic) ngăn chặn hallucination và prompt injection can thiệp vào quá trình suy luận.
  - **Judge & Post-Triage Verifier:** Kiểm định chéo bằng chứng trước khi chuyển giao quyết định cho Policy Engine.
- **Đồ thị Thuộc tính Mã nguồn (Joern Code Property Graph - CPG):**
  - Đóng gói container Joern cách ly, hỗ trợ phân tích luồng dữ liệu (Dataflow/Taint tracking) và đồ thị gọi hàm (Call Graph) cross-file.
- **Bộ Detector Logic Nghiệp Vụ:**
  - Nhận diện IDOR, thiếu kiểm tra quyền (Missing Authorization) và bypass quy tắc nghiệp vụ trên Flask, FastAPI, Django.
- **Báo cáo đa định dạng & Không rò rỉ dữ liệu:**
  - Báo cáo HTML trực quan độc lập (Self-contained, in PDF được), JSON máy đọc được, và Markdown an toàn không chứa raw source, token hay bí mật thô.

---

## Luồng Hệ Thống (Architecture Flow)

```text
Repository Mục Tiêu
  │
  ├──► [Scanners] Semgrep Community + Gitleaks ──► NormalizedFinding
  │                                                      │
  └──► [Logic Discovery] IDOR / Business Rule Detector ──┘
                                 │
                     [Safe Context & Redactor]
          (Loại bỏ bí mật, cắt lát AST, sanitize prompt)
                                 │
                     [Tier-1 Bounded Engine]
           (Index symbols, Call-site, Joern CPG slice)
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
   [Đủ chứng cứ rõ ràng]                     [Ca nghi ngờ / Thiếu context]
           │                                           │
           │                            [Tier-2 Controlled Agent]
           │                               (ReAct Multi-turn Loop)
           │                               ├── 10 Allowlisted Tools
           │                               ├── ToolActionValidator (chặn traversal)
           │                               ├── EvidenceLedger (ghi nhận bằng chứng)
           │                               └── Judge Verifier (thẩm định)
           │                                           │
           └─────────────────────┬─────────────────────┘
                                 │
                       [Policy Engine]
      (Conservative Rules: LIKELY_TP, FP_CANDIDATE, MANUAL_REVIEW)
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
       [report.html]                           [report.json]
   (Báo cáo trực quan)                     (Dữ liệu máy đọc)
```

---

## Hướng Dẫn Chạy Nhanh (Quickstart)

### 1. Cách chạy ngắn nhất (Full tính năng - Đã gồm Agent)

Hệ thống hỗ trợ 2 cách gõ lệnh cực kỳ tiện lợi:

#### Cách 1: Đứng từ thư mục cha `target-repos` và chỉ định tên repository
Khi virtual environment đang kích hoạt, bạn chỉ cần gõ tên repo:

```powershell
# Chuyển vào thư mục chứa các repo cần quét:
cd "D:\Code\target-repos"

# Chạy full tính năng (tự động bật Semgrep, Gitleaks, Joern CPG, Module 2, Logic Detector và Controlled Agent):
python -m sast_triage Sequential-Recommender
python -m sast_triage benchmarks
python -m sast_triage extremely-vulnerable-flask-app
```

#### Cách 2: Đứng trực tiếp bên trong repository mục tiêu (dùng dấu `.`)
```powershell
# Di chuyển thẳng vào repository mục tiêu:
cd "D:\Code\target-repos\extremely-vulnerable-flask-app"

# Quét ngay tại thư mục hiện tại:
python -m sast_triage .
```
*(Hoặc dùng lệnh console `sast-triage .`)*

> **Cả 2 cách trên đều HOÀN TOÀN TƯƠNG ĐƯƠNG** và tự động:
> - Tự động thiết lập cấu hình scanner: Semgrep (`p/python`, `p/security-audit`) + Gitleaks.
> - Tự động dựng và truy vấn đồ thị mã nguồn Joern CPG.
> - Tự động bật Module 2 discovery và detector `python-idor-business-logic`.
> - Tự động bật **Controlled Agent đa vòng** (`--agent-mode escalate`).
> - Tự động xuất báo cáo mới ra thư mục `triage-runs/<repo>-qwen14b-YYYYMMDD-HHMMSSZ/`.
> - Tự động lưu cache quyết định 7 ngày tại `triage-cache/<repo>`.
> - Sử dụng model Qwen3-14B trên Modal (nếu muốn chạy offline hoàn toàn không tốn credit Modal, chỉ cần thêm `--provider fake`).

> **Lưu ý:** Lệnh trên mặc định chạy chế độ `--agent-mode escalate` (kích hoạt Agent khi gặp finding nghi ngờ), sử dụng model Qwen3-14B trên Modal (nếu có cấu hình) hoặc tự fallback sang model cục bộ.

#### Các chế độ Agent (`--agent-mode`):
- `--agent-mode escalate` *(Mặc định)*: Triage nhanh bằng Tier-1; nếu finding thiếu bằng chứng hoặc rơi vào vùng nghi ngờ, tự động leo thang (escalate) sang Agent đa vòng để điều tra chuyên sâu.
- `--agent-mode always`: Kích hoạt vòng lặp Controlled Agent cho 100% mọi finding.
- `--agent-mode off`: Tắt hoàn toàn Agent, chỉ sử dụng bộ thu thập ngữ cảnh tĩnh Tier-1.

---

### 2. Khi nào cần Docker Desktop vs Khi nào KHÔNG cần?

| Nhu cầu sử dụng | Cần Docker? | Giải thích |
|---|:---:|---|
| **Chạy Test Suite (`pytest`)** | ❌ **KHÔNG** | 542 bài test chạy 100% bằng Python cục bộ, có mock Joern và Provider giả lập. |
| **Chạy Thực nghiệm Ablation & Benchmark** | ❌ **KHÔNG** | Các script thực nghiệm chạy trên bộ dữ liệu kiểm chứng benchmark có sẵn không cần Docker. |
| **Chạy Kiểm thử Red-Team (Injection)** | ❌ **KHÔNG** | Kiểm tra phòng thủ Prompt Injection và Tool Injection chạy offline qua test fixtures. |
| **Quét Live một Repository thật (`python -m sast_triage .`)** | ⚠️ **CÓ** | Cần bật **Docker Desktop** để container Joern CPG (`sast-triage-joern:4.0.600`) phân tích đồ thị mã nguồn. |

---

## Các Kịch Bản Kiểm Thử & Thực Nghiệm (Offline - Không cần Docker)

Kích hoạt môi trường ảo:
```powershell
cd "D:\Code\AI security"
.\.venv\Scripts\Activate.ps1
```

### 1. Chạy toàn bộ 544 Automated Tests
```powershell
pytest
```
*(Kết quả: 544 passed, 2 skipped - bảo đảm 100% an toàn không lỗi).*

### 2. Chạy Ablation Study trên 219 Finding Thật
So sánh 4 cấu hình: Agent Off vs Escalation vs Always vs Self-Consistency:
```powershell
python scripts/run_agent_ablation.py
```
*Kết quả xuất ra tại `docs/paper/results/agent_ablation_results.json` và biểu đồ trực quan `agent_ablation_chart.png`.*

### 3. Chạy Kiểm Thử Red-Team Tool & Code Injection (Suite C - 12 mẫu)
Kiểm tra khả năng vô hiệu hóa Path Traversal (`../../etc/passwd`), SQL injection trong symbol query, và comment payload injection:
```powershell
python scripts/run_tool_injection_redteam.py
```
*Kết quả xuất ra tại `docs/paper/results/tool_injection_results.json` (100% attack payload bị chặn đứng).*

### 4. Chạy Kiểm Thử Red-Team Prompt Injection (Suite B - 16 mẫu)
Kiểm tra khả năng miễn nhiễm với prompt override, delimiter hijacking và fake verdict injection:
```powershell
python scripts/run_prompt_injection_suite.py
```

### 5. Đánh giá So sánh 3 Baseline (Scanner vs LLM-Only vs Hệ thống đề xuất)
```powershell
python scripts/run_eval_baseline.py
```

### 6. Đo đạc Chi phí, Token và Độ trễ thực tế
```powershell
python scripts/benchmark_cost_tokens.py
```

---

## Kết Quả Thực Nghiệm Nổi Bật (Empirical Benchmarks)

Thực nghiệm trên 5 repository thực tế chứa lỗ hổng bảo mật (219 findings):

| Tiêu chí | Baseline (Chỉ Scanner) | LLM Thô (Single-pass) | Hệ thống Đề xuất (Controlled Escalation) |
|---|:---:|:---:|:---:|
| **False Negative Rate (Bỏ sót)** | 0.0% | 12.4% (Ảo giác bỏ sót TP) | **0.0% (An toàn tuyệt đối)** |
| **Recall trên True Positives** | 100.0% | 87.6% | **100.0%** |
| **Công sức Reviewer tiết kiệm** | 0.0% (Phải duyệt hết) | 28.5% (Không an toàn) | **7.76% (Đã kiểm chứng bằng chứng)** |
| **Mức giảm Token tiêu thụ** | — | Baseline 100% | **Giảm 41.22% tokens** |
| **Tỷ lệ chặn Tool Injection** | — | — | **100.0% (12/12 attacks blocked)** |
| **Tỷ lệ chặn Prompt Injection** | — | — | **100.0% (16/16 attacks neutralized)** |

---

## Cài Đặt Môi Trường Native Chi Tiết

### 1. Yêu cầu hệ thống
- Python 3.11, 3.12 hoặc 3.13 (khuyến nghị 3.12).
- Git.
- Semgrep và Gitleaks trong `PATH`.
- Docker Desktop (nếu quét repository live bằng Joern CPG).
- Tài khoản Modal (tùy chọn, chỉ cần nếu gọi model Qwen3-14B trên cloud GPU).

### 2. Cài đặt trên Windows PowerShell
```powershell
cd "D:\Code\AI security"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

### 3. Thiết lập Modal (Tùy chọn)
```powershell
python -m modal setup
```
*(Bỏ qua nếu bạn sử dụng provider offline hoặc Ollama).*

### 4. Quét Repository Live bằng Script Tự Động
```powershell
# Chạy với provider fake offline:
.\scripts\run-docker.ps1 -TargetRepository "D:\Code\target-repo"

# Hoặc chạy với Qwen trên Modal:
.\scripts\run-docker.ps1 -TargetRepository "D:\Code\target-repo" -Provider real
```

---

## Đọc Kết Quả Phân Loại

Báo cáo được tự động tạo tại thư mục `triage-runs/<repo-name>-YYYYMMDD-HHMMSSZ/`:

```text
triage-runs/<repo-name>-YYYYMMDD-HHMMSSZ/
├── report.html          # Báo cáo trực quan (giao diện dark/light, in PDF được)
├── report.json          # Dữ liệu phân loại chi tiết có schema
├── run-metadata.json    # Commit hash, cấu hình scanner, model ID, telemetry
└── scanner-artifacts/   # File raw từ Semgrep và Gitleaks (chỉ lưu cục bộ)
```

### Các Quyết Định của Chính Sách (Policy Actions):
| Policy Action | Ý nghĩa | Hành động tiếp theo |
|---|---|---|
| `LIKELY_TP` | Khả năng cao là lỗ hổng thật; có chuỗi bằng chứng source→sink. | Reviewer ưu tiên xử lý khắc phục (remediation). |
| `FP_CANDIDATE` | Ứng viên cảnh báo giả; đã xác minh có cơ chế sanitize/defense hợp lệ. | Đánh dấu để reviewer xác nhận đóng nhanh. |
| `MANUAL_REVIEW` | Chưa đủ bằng chứng hoặc có mâu thuẫn cần con người xem xét. | Chuyển vào hàng đợi review thông thường. |
| `TRIAGE_ERROR` | Gặp lỗi phân tích; finding vẫn được giữ nguyên đầy đủ. | Xem xét lại môi trường hoặc cấu hình scanner. |

---

## Cấu Trúc Mã Nguồn

```text
.
├── src/sast_triage/
│   ├── agent/                Controlled Triage Agent (ReAct loop, 10 tools, Validator, Ledger, Judge)
│   ├── analysis/             Backend Joern CPG và projection an toàn
│   ├── application/          Điều phối CLI run, checkpointing và session
│   ├── context/              Safe file read, AST parser, context sanitizer, secret redactor
│   ├── parsers/              Scanner JSON → NormalizedFinding
│   ├── pipeline/             Xử lý từng finding và batch triage
│   ├── policy/               Conservative Policy Engine & Post-triage Verifier
│   ├── reporting/            Tạo báo cáo bảo mật JSON, Markdown và HTML
│   ├── runners/              Chạy Semgrep và Gitleaks độc lập
│   └── triage/               Prompt construction, provider integration, schema validator
├── scripts/                  Scripts thực nghiệm (ablation, red-team suites, benchmarks)
├── tests/                    544 automated tests (unit, integration, security defense)
├── docs/                     Tài liệu kiến trúc, paper học thuật và hướng dẫn vận hành
├── pyproject.toml            Cấu hình dependencies và packaging
└── README.md                 Tài liệu trung tâm này
```

---

## Nguyên Tắc Bảo Mật Cốt Lõi

1. **Không rò rỉ mã nguồn thô (Raw Source Boundary):** Mã nguồn thô chỉ được xử lý trong phạm vi bảo vệ của `SafeContextService`, không bao giờ được ghi vào model công khai, log hay metadata.
2. **Không rò rỉ bí mật (Secret Redaction):** Bí mật từ Gitleaks lập tức được thay thế bằng `<REDACTED_SECRET>`.
3. **Mã nguồn là dữ liệu không đáng tin cậy:** Mọi đoạn code đưa vào LLM hoặc Agent đều được bọc trong ranh giới an toàn, vô hiệu hóa khả năng Prompt Injection và Tool Injection.
4. **Không bao giờ tự ý loại bỏ phát hiện (Zero-Drop Guarantee):** Mọi phát hiện từ SAST đều hiện diện trong báo cáo cuối cùng với đầy đủ audit trail.

---

## Danh Mục Tài Liệu Bổ Sung

- [Hướng dẫn CLI chi tiết](docs/cli-usage.md)
- [Bản thảo Nghiên cứu Khoa học (Paper Draft)](docs/paper/paper.md)
- [Thiết lập & Vận hành Joern CPG](docs/joern-analysis.md)
- [Bản đồ Kiến trúc Mã nguồn](docs/code-map.md)
- [Mô hình Đe dọa (Threat Model)](docs/threat-model.md)
- [Chính sách Bảo mật Dự án](docs/security-policy.md)
- [Hướng dẫn Kết nối Qwen3-14B trên Modal](docs/MODAL_QWEN14B_SETUP.md)
