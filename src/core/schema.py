"""
Core Data Schema — UnifiedFinding & Supporting Models
======================================================
Defines all Pydantic Models for the modular LLM-augmented SAST & logic-bug analysis pipeline.
All findings from parsers, triage, logic-bug detectors, risk scoring, and remediation
converge onto this schema.
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


# ─── Sub-models ───────────────────────────────────────────────────────────────

class EvidenceReference(BaseModel):
    """
    Structured evidence reference anchoring every verdict to explicit code elements.
    Verdicts without verifiable evidence references must fallback to NEEDS_MORE_CONTEXT/NEEDS_REVIEW.
    """
    file_path: str
    line_number: int
    symbol: Optional[str] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    guard: Optional[str] = None
    code_path: List[str] = Field(default_factory=list)


class DecisionMetadata(BaseModel):
    """
    Decision metadata for tracking LLM evaluation state and reproducibility.
    Note: decision_score is uncalibrated raw score; not treated as true probability.
    """
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
    """
    Lightweight Security Context Graph representing Entrypoint -> Guard -> Sink traces.
    
    LIMITATIONS NOTICE:
    This graph is an AST-derived lightweight security context graph. It is NOT a full
    Control Flow Graph (CFG) or complete Code Property Graph (CPG), as it lacks full 
    interprocedural data flow analysis, alias resolution, and complete symbol table tracking.
    Missing guards indicate a LOGIC_BUG_CANDIDATE for review, not automated proof of vulnerability.
    """
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
    """
    Risk score details calculated on a normalized 0-100 rubric scale.
    Formula: Risk = ((0.25*Sev + 0.25*Reach + 0.20*Exp + 0.20*Sens + 0.10*Exploit) - 1.0) / 4.0 * 100
    """
    overall_score: float = Field(..., ge=0.0, le=100.0)  # Normalized 0-100
    severity_score: float = Field(3.0, ge=1.0, le=5.0)          # Impact (1-5)
    reachability_score: float = Field(3.0, ge=1.0, le=5.0)      # Reachability (1-5)
    exposure_score: float = Field(3.0, ge=1.0, le=5.0)          # Exposure (1-5)
    data_sensitivity_score: float = Field(3.0, ge=1.0, le=5.0)  # Data Sensitivity (1-5)
    exploitability_score: float = Field(3.0, ge=1.0, le=5.0)    # Exploitability (1-5)
    risk_level: Severity = Severity.MEDIUM


class RemediationPatch(BaseModel):
    """
    Remediation proposal generated by Remediation Engine.
    Patches are strictly PATCH_CANDIDATE items linked to commit_sha and must pass validation.
    Never auto-applied or auto-merged.
    """
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
    """
    Central finding model of the platform.
    Represents findings from SAST Triage Branch (Semgrep/Gitleaks) and Logic-Bug Branch.
    """
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


class GroundTruthBenchmarkItem(BaseModel):
    """Benchmark item for versioned benchmark evaluation."""
    finding_id: str
    ground_truth_verdict: TriageVerdict
    rule_family: str = "generic"
    repository: str = "benchmark_repo"
    reviewer_notes: Optional[str] = None
    confidence_level: Optional[str] = "HIGH"
