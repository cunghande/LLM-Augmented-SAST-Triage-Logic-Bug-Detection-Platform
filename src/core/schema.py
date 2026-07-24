import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScannerType(str, Enum):
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    LOGIC_BUG = "logic-bug"
    MANUAL = "manual"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class FindingStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    SUPPRESSED = "SUPPRESSED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ActionGroup(str, Enum):
    AUTO_SUPPRESS_CANDIDATE = "AUTO_SUPPRESS_CANDIDATE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    HIGH_CONFIDENCE_TP = "HIGH_CONFIDENCE_TP"


class FindingContext(BaseModel):
    enclosing_function: Optional[str] = None
    line_window: Optional[str] = None
    surrounding_code: Optional[str] = None
    imports: List[str] = Field(default_factory=list)
    caller_callee_info: Optional[str] = None
    redacted: bool = False


class TriageResult(BaseModel):
    verdict: TriageVerdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    evidence: List[str] = Field(default_factory=list)
    action_group: ActionGroup = ActionGroup.MANUAL_REVIEW
    model_version: Optional[str] = None
    prompt_version: Optional[str] = None


class UnifiedFinding(BaseModel):
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
    metadata: Dict[str, Any] = Field(default_factory=dict)
    context: Optional[FindingContext] = None
    
    # Triage outputs
    verdict: Optional[TriageVerdict] = None
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    action_group: Optional[ActionGroup] = None
    
    # Risk & Remediation
    risk_score: Optional[float] = None
    remediation: Optional[Dict[str, Any]] = None
    
    # Fingerprint & Lifecycle
    fingerprint: Optional[str] = None
    status: FindingStatus = FindingStatus.NEW
    
    model_version: Optional[str] = None
    prompt_version: Optional[str] = None

    def compute_fingerprint(self) -> str:
        """Compute stable fingerprint based on rule_id, file_path, and snippet content."""
        clean_snippet = " ".join(self.snippet.strip().split())
        raw = f"{self.rule_id}:{self.file_path}:{clean_snippet}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint


class GroundTruthBenchmarkItem(BaseModel):
    finding_id: str
    ground_truth_verdict: TriageVerdict
    reviewer_notes: Optional[str] = None
    confidence_level: Optional[str] = "HIGH"
