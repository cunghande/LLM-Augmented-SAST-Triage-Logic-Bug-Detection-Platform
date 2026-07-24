"""
Core Data Schema — UnifiedFinding & Supporting Models
======================================================
Định nghĩa tất cả Pydantic Models dùng chung trong toàn bộ nền tảng.
Mọi dữ liệu từ parsers, triage, risk scoring, và remediation đều
quy về schema này trước khi ghi ra JSON report.
"""

import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────────────────

class ScannerType(str, Enum):
    """Nguồn gốc phát hiện finding."""
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    LOGIC_BUG = "logic-bug"   # Phát hiện bởi Logic-Bug Agent (Sprint 2)
    MANUAL = "manual"


class Severity(str, Enum):
    """Mức độ nghiêm trọng kỹ thuật của lỗ hổng."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TriageVerdict(str, Enum):
    """Kết quả phân loại của LLM Qwen 3:8b."""
    TRUE_POSITIVE = "TP"          # Lỗi bảo mật thật, cần vá
    FALSE_POSITIVE = "FP"         # Cảnh báo sai, có thể bỏ qua
    NEEDS_REVIEW = "NEEDS_REVIEW" # Cần AppSec review thủ công thêm


class FindingStatus(str, Enum):
    """Trạng thái vòng đời của finding trong quy trình xử lý."""
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    SUPPRESSED = "SUPPRESSED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ActionGroup(str, Enum):
    """
    Chính sách phân luồng xử lý dựa trên confidence của LLM.
    Xem thêm: src/triage/engine.py → TriageEngine.triage_finding()
    """
    AUTO_SUPPRESS_CANDIDATE = "AUTO_SUPPRESS_CANDIDATE"  # FP tin cậy cao → tự suppress
    MANUAL_REVIEW = "MANUAL_REVIEW"                       # Confidence trung bình → AppSec review
    HIGH_CONFIDENCE_TP = "HIGH_CONFIDENCE_TP"             # TP tin cậy cao → ưu tiên vá ngay


# ─── Sub-models ───────────────────────────────────────────────────────────────

class FindingContext(BaseModel):
    """Ngữ cảnh code được trích xuất bởi Context Extractor (src/context/extractor.py)."""
    enclosing_function: Optional[str] = None   # Tên hàm/route bao quanh finding
    line_window: Optional[str] = None          # Khoảng dòng được lấy (VD: "L66-L96")
    surrounding_code: Optional[str] = None    # Đoạn code ±15 dòng xung quanh (đã redact secret)
    imports: List[str] = Field(default_factory=list)  # Danh sách import đầu file
    caller_callee_info: Optional[str] = None  # Thông tin caller/callee (nếu có)
    redacted: bool = False                    # True nếu đã redact dữ liệu nhạy cảm


class TriageResult(BaseModel):
    """Kết quả triage từ LLM (được nhúng trực tiếp vào UnifiedFinding)."""
    verdict: TriageVerdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    evidence: List[str] = Field(default_factory=list)
    action_group: ActionGroup = ActionGroup.MANUAL_REVIEW
    model_version: Optional[str] = None
    prompt_version: Optional[str] = None


class LogicBugTrace(BaseModel):
    """
    Vết truy vết CPG/AST được sinh bởi ast_graph.py (Sprint 2 - S2-01).
    Ghi lại đường đi: Entrypoint → Guards → Sensitive Sink.
    """
    bug_type: str                              # IDOR | MASS_ASSIGNMENT | BUSINESS_RULE_BYPASS | ...
    entrypoint: str                            # HTTP route/endpoint phát hiện lỗi
    guards: List[str] = Field(default_factory=list)  # Danh sách Auth middleware hiện có
    sensitive_sink: str                        # Thao tác DB/File nhạy cảm
    has_authz_guard: bool = False             # ⚠️ False = thiếu guard → nguy cơ cao
    trace_path: List[str] = Field(default_factory=list)  # Đường đi đầy đủ


class RiskScoreDetails(BaseModel):
    """
    Chi tiết điểm rủi ro theo 5 thành phần (Sprint 2 - S2-05).
    Công thức: Risk = 0.25×Sev + 0.25×Reach + 0.20×Exp + 0.20×Sens + 0.10×Exploit
    """
    overall_score: float = Field(..., ge=1.0, le=5.0)  # Điểm tổng hợp
    severity_score: float = 3.0          # Tác động kỹ thuật (1-5)
    reachability_score: float = 3.0      # Khả năng đến được sink (1-5)
    exposure_score: float = 3.0          # Mức độ phơi bày internet (1-5)
    data_sensitivity_score: float = 3.0  # Độ nhạy của dữ liệu bị ảnh hưởng (1-5)
    exploitability_score: float = 3.0    # Độ dễ khai thác (1-5)
    risk_level: Severity = Severity.MEDIUM  # CRITICAL ≥ 4.2 | HIGH ≥ 3.4 | MEDIUM ≥ 2.5


class RemediationPatch(BaseModel):
    """Đề xuất vá lỗi được sinh bởi RemediationGenerator (Sprint 2 - S2-06)."""
    fix_summary: str                        # Mô tả ngắn cách vá
    code_diff: str                          # Code diff đề xuất (unified patch format)
    recommended_test: Optional[str] = None  # Gợi ý test case để kiểm tra sau khi vá


# ─── Main Model ───────────────────────────────────────────────────────────────

class UnifiedFinding(BaseModel):
    """
    Model trung tâm của nền tảng — chuẩn hóa finding từ mọi scanner.

    Vòng đời:
      1. Parser   → finding_id, rule_id, file_path, snippet, severity
      2. Extractor→ context (surrounding_code, enclosing_function)
      3. LLM      → verdict, confidence, reasoning, evidence, action_group
      4. Scorer   → risk_score, risk_score_details
      5. Generator→ remediation, remediation_patch
    """
    # ── Thông tin cơ bản từ Scanner ──────────────────────────────────────────
    finding_id: str
    scanner: ScannerType
    rule_id: str
    repository: str
    commit_sha: Optional[str] = "HEAD"
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    severity: Severity = Severity.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)  # Message, CWE, OWASP từ scanner
    context: Optional[FindingContext] = None                # Được điền bởi extractor.py

    # ── Kết quả Triage từ LLM ────────────────────────────────────────────────
    verdict: Optional[TriageVerdict] = None      # TP | FP | NEEDS_REVIEW
    confidence: Optional[float] = None           # 0.0 - 1.0
    reasoning: Optional[str] = None              # Lý giải của Qwen 3:8b
    evidence: List[str] = Field(default_factory=list)
    action_group: Optional[ActionGroup] = None   # Phân luồng xử lý

    # ── Sprint 2 Additions ────────────────────────────────────────────────────
    logic_bug_trace: Optional[LogicBugTrace] = None       # CPG trace (S2-01)
    risk_score_details: Optional[RiskScoreDetails] = None  # Chi tiết điểm rủi ro (S2-05)
    remediation_patch: Optional[RemediationPatch] = None   # Code diff đề xuất (S2-06)

    # ── Risk & Remediation (dạng flat để JSON report dễ đọc) ──────────────────
    risk_score: Optional[float] = None           # Điểm rủi ro tổng hợp
    remediation: Optional[Dict[str, Any]] = None # Thông tin vá lỗi dạng dict

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    fingerprint: Optional[str] = None            # Hash duy nhất để chống trùng lặp
    status: FindingStatus = FindingStatus.NEW
    model_version: Optional[str] = None          # Phiên bản model LLM đã dùng
    prompt_version: Optional[str] = None         # Phiên bản prompt đã dùng

    def compute_fingerprint(self) -> str:
        """Tính fingerprint SHA-256 ổn định dựa trên rule_id + file_path + snippet."""
        clean_snippet = " ".join(self.snippet.strip().split())
        raw = f"{self.rule_id}:{self.file_path}:{clean_snippet}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint


class GroundTruthBenchmarkItem(BaseModel):
    """Item trong bộ benchmark ground truth dùng để đo đánh giá độ chính xác."""
    finding_id: str
    ground_truth_verdict: TriageVerdict
    reviewer_notes: Optional[str] = None
    confidence_level: Optional[str] = "HIGH"
