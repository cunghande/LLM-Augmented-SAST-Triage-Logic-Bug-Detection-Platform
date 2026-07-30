"""
Core Data Schema — UnifiedFinding & Supporting Models
======================================================
Defines all Pydantic Models for the modular LLM-augmented SAST & logic-bug analysis pipeline
including ScanManifest, CoverageReport, ProjectContext, 4-stage workflow states, and finding correlation.
"""

import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────────────────

class ScannerType(str, Enum):
    """Origin scanner type."""
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    LOGIC_BUG = "logic-bug"
    MANUAL = "manual"


class BranchType(str, Enum):
    """Pipeline analysis branch."""
    SAST_TRIAGE_BRANCH = "sast_triage_branch"
    LOGIC_BUG_BRANCH = "logic_bug_branch"


class Severity(str, Enum):
    """Technical severity level."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TriageVerdict(str, Enum):
    """Triage verdict output."""
    TRUE_POSITIVE = "TP"                  # Vulnerability confirmed
    FALSE_POSITIVE = "FP"                 # False positive noise
    NEEDS_REVIEW = "NEEDS_REVIEW"         # Requires manual AppSec review
    NEEDS_MORE_CONTEXT = "NEEDS_MORE_CONTEXT"  # Insufficient context to determine


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    SUPPRESSED = "SUPPRESSED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ScanState(str, Enum):
    """Relationship-aware correlation state across scans."""
    NEW = "NEW"
    EXISTING = "EXISTING"
    CHANGED = "CHANGED"
    FIXED = "FIXED"
    REOPENED = "REOPENED"


class ScanStage(str, Enum):
    """4-stage workflow stage."""
    SCAN = "scan"
    VALIDATE = "validate"
    PATCH = "patch"
    COMPARE = "compare"


class CIMode(str, Enum):
    """CI/CD Policy Gate Mode."""
    REPORT_ONLY = "REPORT_ONLY"
    SHADOW_GATING = "SHADOW_GATING"
    BLOCKING_GATE = "BLOCKING_GATE"


class ActionGroup(str, Enum):
    """Processing policy action group."""
    AUTO_SUPPRESS_CANDIDATE = "AUTO_SUPPRESS_CANDIDATE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    HIGH_CONFIDENCE_TP = "HIGH_CONFIDENCE_TP"


class SecretTaxonomy(str, Enum):
    """Gitleaks secret validity classification taxonomy."""
    VALID_SECRET = "VALID_SECRET"
    REVOKED_SECRET = "REVOKED_SECRET"
    TEST_CREDENTIAL = "TEST_CREDENTIAL"
    PLACEHOLDER = "PLACEHOLDER"
    HISTORICAL_SECRET = "HISTORICAL_SECRET"
    FALSE_MATCH = "FALSE_MATCH"
    UNKNOWN_VALIDITY = "UNKNOWN_VALIDITY"


class GuardCategory(str, Enum):
    """Categories of security guards in code."""
    AUTHENTICATION = "AUTHENTICATION"
    ROLE = "ROLE"
    OWNERSHIP = "OWNERSHIP"
    TENANT = "TENANT"
    STATE_TRANSITION = "STATE_TRANSITION"
    VALIDATION = "VALIDATION"
    TRANSACTION = "TRANSACTION"
    UNKNOWN = "UNKNOWN"


class ContextQuality(str, Enum):
    """Quality tier of context extraction."""
    HIGH = "HIGH"          # AST node + full function / slice + caller/callee context
    MEDIUM = "MEDIUM"      # AST function / statement node
    FALLBACK = "FALLBACK"  # Line window fallback (when AST parsing fails)


class PatchStatus(str, Enum):
    """Status of LLM-generated remediation patch candidate."""
    PATCH_CANDIDATE = "PATCH_CANDIDATE"
    GUIDANCE_ONLY = "GUIDANCE_ONLY"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    FAILED_VALIDATION = "FAILED_VALIDATION"


# ─── Codex Security Supporting Models ───────────────────────────────────────

class ScanManifest(BaseModel):
    """Immutable scan manifest recording environment, commits, and versions."""
    manifest_id: str
    repository: str
    commit_sha: str = "0000000000000000000000000000000000000000"
    scanner_versions: Dict[str, str] = Field(default_factory=lambda: {"semgrep": "1.0.0", "gitleaks": "8.0.0"})
    model_version: str = "qwen3:8b"
    prompt_version: str = "v2.0"
    policy_version: str = "v1.0"
    timestamp_utc: str = ""


class CoverageReport(BaseModel):
    """Coverage report capturing scan completeness and failures."""
    total_files: int = 0
    analyzed_files: int = 0
    unsupported_files: List[str] = Field(default_factory=list)
    ast_failures: List[str] = Field(default_factory=list)
    unresolved_symbols: List[str] = Field(default_factory=list)
    llm_failures: List[str] = Field(default_factory=list)
    skipped_analysis_regions: List[str] = Field(default_factory=list)
    is_complete_scan: bool = True
    suggested_exit_code: int = 0  # 0 = clean complete, 2 = incomplete scan


class ProjectContext(BaseModel):
    """Versioned project_context.yaml representation."""
    version: str = "1.0"
    system_exposure: str = "INTERNAL"  # INTERNAL | PARTNER | INTERNET_FACING
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    authorization_policies: List[Dict[str, Any]] = Field(default_factory=list)
    security_invariants: List[str] = Field(default_factory=list)


class EvidenceReference(BaseModel):
    """Structured evidence reference anchoring every verdict to explicit code elements."""
    file_path: str
    line_number: int
    symbol: Optional[str] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    guard: Optional[str] = None
    code_path: List[str] = Field(default_factory=list)


class DecisionMetadata(BaseModel):
    """Decision metadata for tracking LLM evaluation state and reproducibility."""
    decision_score: float = Field(default=0.0, ge=0.0, le=1.0)
    model_version: str = "qwen3:8b"
    prompt_version: str = "v2.0"
    context_hash: str = ""
    policy_version: str = "v1.0"


class FindingContext(BaseModel):
    """Context extracted by MultiTierContextExtractor."""
    context_quality: ContextQuality = ContextQuality.FALLBACK
    enclosing_function: Optional[str] = None
    enclosing_class: Optional[str] = None
    ast_node_type: Optional[str] = None
    annotations: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    line_window: Optional[str] = None
    surrounding_code: Optional[str] = None
    imports: List[str] = Field(default_factory=list)
    caller_callee_info: Optional[str] = None
    sliced_code: Optional[str] = None
    related_config: Optional[str] = None
    redacted: bool = True


class LightweightSecurityContextGraph(BaseModel):
    """Lightweight Security Context Graph representing Entrypoint -> Guard -> Sink traces."""
    bug_type: str
    entrypoint: str
    guards: List[str] = Field(default_factory=list)
    guard_categories: List[GuardCategory] = Field(default_factory=list)
    sensitive_sink: str
    has_auth_guard: bool = False
    trace_path: List[str] = Field(default_factory=list)
    limitations_disclaimer: str = (
        "Lightweight security context graph based on AST heuristics. "
        "Lacks full interprocedural dataflow. Absence of guard generates LOGIC_BUG_CANDIDATE."
    )


class RiskScoreDetails(BaseModel):
    """Risk score details calculated on a normalized 0-100 rubric scale."""
    overall_score: float = Field(..., ge=0.0, le=100.0)
    severity_score: float = Field(3.0, ge=1.0, le=5.0)
    reachability_score: float = Field(3.0, ge=1.0, le=5.0)
    exposure_score: float = Field(3.0, ge=1.0, le=5.0)
    data_sensitivity_score: float = Field(3.0, ge=1.0, le=5.0)
    exploitability_score: float = Field(3.0, ge=1.0, le=5.0)
    risk_level: Severity = Severity.MEDIUM


class RemediationPatch(BaseModel):
    """Remediation proposal generated by Remediation Engine for selected validated findings."""
    status: PatchStatus = PatchStatus.PATCH_CANDIDATE
    commit_sha: str = "HEAD"
    fix_summary: str
    code_diff: str
    recommended_test: Optional[str] = None
    validation_checks: Dict[str, bool] = Field(
        default_factory=lambda: {
            "syntax_valid": False,
            "apply_valid": False,
            "unit_test_passed": False,
            "security_regression_passed": False
        }
    )


# ─── Main Model ───────────────────────────────────────────────────────────────

class UnifiedFinding(BaseModel):
    """Central finding model of the platform."""
    finding_id: str
    scanner: ScannerType
    branch_type: BranchType = BranchType.SAST_TRIAGE_BRANCH
    rule_id: str
    repository: str
    commit_sha: Optional[str] = "HEAD"
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    severity: Severity = Severity.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # ── Correlation & Manifest ────────────────────────────────────────────────
    correlation_state: ScanState = ScanState.NEW
    scan_manifest: Optional[ScanManifest] = None
    guard_policy_evidence: Optional[Dict[str, Any]] = None

    # ── Secret Taxonomy & Context ─────────────────────────────────────────────
    secret_taxonomy: SecretTaxonomy = SecretTaxonomy.UNKNOWN_VALIDITY
    context: Optional[FindingContext] = None

    # ── Verdict & Evidence ───────────────────────────────────────────────────
    verdict: Optional[TriageVerdict] = None
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    evidence_ref: Optional[EvidenceReference] = None
    decision_metadata: Optional[DecisionMetadata] = None
    action_group: Optional[ActionGroup] = None

    # ── Graph, Risk & Remediation ─────────────────────────────────────────────
    security_context_graph: Optional[LightweightSecurityContextGraph] = None
    risk_score_details: Optional[RiskScoreDetails] = None
    remediation_patch: Optional[RemediationPatch] = None
    risk_score: Optional[float] = None
    remediation: Optional[Dict[str, Any]] = None

    # ── Lifecycle & Audit ─────────────────────────────────────────────────────
    fingerprint: Optional[str] = None
    status: FindingStatus = FindingStatus.NEW
    processing_error: Optional[str] = None

    def compute_fingerprint(self) -> str:
        """Compute stable SHA-256 fingerprint based on rule_id + file_path + normalized snippet."""
        clean_snippet = " ".join(self.snippet.strip().split())
        raw = f"{self.rule_id}:{self.file_path}:{clean_snippet}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint
