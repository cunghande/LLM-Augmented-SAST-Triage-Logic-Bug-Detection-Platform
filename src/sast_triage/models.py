"""Domain models and enums for SAST Triage Platform."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- Enums ---


class ScannerType(str, Enum):
    """Supported static security scanner tools."""

    SEMGREP = "SEMGREP"
    GITLEAKS = "GITLEAKS"


class FindingType(str, Enum):
    """Category of security finding."""

    SAST = "SAST"
    SECRET = "SECRET"


class Severity(str, Enum):
    """Normalized finding severity level."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class ContextStrategy(str, Enum):
    """Strategy used for source code context extraction."""

    PYTHON_FUNCTION = "PYTHON_FUNCTION"
    PYTHON_CLASS = "PYTHON_CLASS"
    LINE_WINDOW = "LINE_WINDOW"
    REDACTED_LINE_WINDOW = "REDACTED_LINE_WINDOW"
    UNAVAILABLE = "UNAVAILABLE"


class SourceKind(str, Enum):
    """Origin of extracted source code."""

    WORKTREE = "WORKTREE"


class PathCategory(str, Enum):
    """Classification of file path for policy decisions."""

    PRODUCTION = "PRODUCTION"
    TEST = "TEST"
    FIXTURE = "FIXTURE"
    EXAMPLE = "EXAMPLE"
    DOCUMENTATION = "DOCUMENTATION"
    UNKNOWN = "UNKNOWN"


class MissingContextReason(str, Enum):
    """Reasons why source context could not be extracted or is limited."""

    SOURCE_FILE_NOT_FOUND = "SOURCE_FILE_NOT_FOUND"
    SOURCE_PATH_OUTSIDE_REPOSITORY = "SOURCE_PATH_OUTSIDE_REPOSITORY"
    SOURCE_FILE_TOO_LARGE = "SOURCE_FILE_TOO_LARGE"
    SOURCE_FILE_UNSUPPORTED_ENCODING = "SOURCE_FILE_UNSUPPORTED_ENCODING"
    PYTHON_AST_PARSE_FAILED = "PYTHON_AST_PARSE_FAILED"
    ENCLOSING_SCOPE_EXCEEDED_LIMIT = "ENCLOSING_SCOPE_EXCEEDED_LIMIT"
    INVALID_FINDING_LINE_RANGE = "INVALID_FINDING_LINE_RANGE"
    ARTIFACT_REPOSITORY_MISMATCH = "ARTIFACT_REPOSITORY_MISMATCH"


class ModelVerdict(str, Enum):
    """Triage verdict proposed by LLM."""

    LIKELY_TP = "LIKELY_TP"
    LIKELY_FP = "LIKELY_FP"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class ModelConfidence(str, Enum):
    """Confidence level of LLM verdict."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class PolicyAction(str, Enum):
    """System-level triage decision action."""

    LIKELY_TP = "LIKELY_TP"
    FP_CANDIDATE = "FP_CANDIDATE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    TRIAGE_ERROR = "TRIAGE_ERROR"


class ProcessingStage(str, Enum):
    """Pipeline processing stages."""

    PARSE = "PARSE"
    CONTEXT = "CONTEXT"
    SANITIZE = "SANITIZE"
    TRIAGE = "TRIAGE"
    POLICY = "POLICY"
    REPORT = "REPORT"
    BINDING = "BINDING"


class ArtifactRepositoryMatch(str, Enum):
    """Verification status of artifact-to-repository binding."""

    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    MISMATCH = "MISMATCH"


# --- Helper Functions ---


def _is_absolute_path(path_str: str) -> bool:
    """Check if path string represents an absolute path."""
    if not path_str:
        return False
    path_obj = Path(path_str)
    return (
        path_obj.is_absolute()
        or path_str.startswith(("/", "\\"))
        or (len(path_str) > 1 and path_str[1] == ":")
    )


# --- Base Model ---


class BaseDomainModel(BaseModel):
    """Immutable base Pydantic model for public boundary models."""

    model_config = ConfigDict(frozen=True, extra="forbid")


# --- Domain Models ---


class NormalizedFinding(BaseDomainModel):
    """Normalized security finding produced by a scanner parser.

    The `metadata` dictionary contains allowlisted, sanitized, serialization-safe
    scanner metadata (e.g. CWE, OWASP, technology, secret_category, rule_description).
    Raw scanner records, raw secrets, unredacted snippets, and author/commit details
    are strictly prohibited in this model.
    """

    finding_instance_id: str
    scanner: ScannerType
    finding_type: FindingType
    rule_id: str
    rule_name: str | None = None
    file_path: str
    start_line: int
    end_line: int | None = None
    severity: Severity
    message: str
    snippet: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for NormalizedFinding."""
        if not self.finding_instance_id or not self.finding_instance_id.strip():
            raise ValueError("finding_instance_id must not be empty")

        if self.scanner == ScannerType.SEMGREP and self.finding_type != FindingType.SAST:
            raise ValueError("SEMGREP scanner findings must have SAST finding_type")
        if self.scanner == ScannerType.GITLEAKS and self.finding_type != FindingType.SECRET:
            raise ValueError("GITLEAKS scanner findings must have SECRET finding_type")

        if not self.file_path or not self.file_path.strip():
            raise ValueError("file_path must not be empty")
        if _is_absolute_path(self.file_path):
            raise ValueError("file_path must be a relative path, absolute paths are prohibited")

        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")

        if not self.message or not self.message.strip():
            raise ValueError("message must not be empty")

        if self.start_line <= 0:
            raise ValueError("start_line must be greater than 0")

        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")

        return self


class SanitizedContext(BaseDomainModel):
    """Sanitized source code context safe for LLM provider consumption."""

    finding_id: str
    sanitized_snippet: str | None = None
    context_strategy: ContextStrategy
    context_start_line: int | None = None
    context_end_line: int | None = None
    finding_start_line: int
    finding_end_line: int | None = None
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    limited_imports: list[str] | None = None
    limited_decorators: list[str] | None = None
    path_category: PathCategory
    source_kind: SourceKind
    context_available: bool
    missing_context_reasons: list[MissingContextReason] = Field(default_factory=list)
    redactions_applied: int = 0
    redaction_types: list[str] = Field(default_factory=list)
    truncated: bool = False

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for SanitizedContext."""
        if not self.finding_id or not self.finding_id.strip():
            raise ValueError("finding_id must not be empty")

        if self.finding_start_line <= 0:
            raise ValueError("finding_start_line must be greater than 0")

        if self.finding_end_line is not None and self.finding_end_line < self.finding_start_line:
            raise ValueError("finding_end_line must be >= finding_start_line")

        if self.redactions_applied < 0:
            raise ValueError("redactions_applied cannot be negative")

        for r_type in self.redaction_types:
            if not r_type or not r_type.strip():
                raise ValueError("redaction_types elements must be non-empty strings")

        if self.context_strategy == ContextStrategy.UNAVAILABLE:
            if self.context_available:
                raise ValueError("context_available must be False when context_strategy is UNAVAILABLE")
            if self.sanitized_snippet is not None:
                raise ValueError("sanitized_snippet must be None when context_strategy is UNAVAILABLE")
            if not self.missing_context_reasons:
                raise ValueError("missing_context_reasons must not be empty when context_strategy is UNAVAILABLE")
        else:
            if not self.context_available:
                raise ValueError("context_available must be True for active context strategy")
            if self.sanitized_snippet is None or not self.sanitized_snippet.strip():
                raise ValueError("sanitized_snippet must be a non-empty string for active context strategy")
            if self.context_start_line is None or self.context_end_line is None:
                raise ValueError("context_start_line and context_end_line are required for active context strategy")
            if self.context_start_line <= 0:
                raise ValueError("context_start_line must be greater than 0")
            if self.context_end_line < self.context_start_line:
                raise ValueError("context_end_line must be >= context_start_line")
            if self.context_start_line > self.finding_start_line:
                raise ValueError("context_start_line must be <= finding_start_line")
            if self.finding_end_line is not None and self.finding_end_line > self.context_end_line:
                raise ValueError("finding_end_line must be <= context_end_line")

        return self


class TriageInput(BaseDomainModel):
    """Input payload provided to TriageProvider."""

    finding: NormalizedFinding
    context: SanitizedContext
    prompt_version: str
    output_schema_version: str
    prompt_type: str

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for TriageInput."""
        if self.context.finding_id != self.finding.finding_instance_id:
            raise ValueError(
                f"context.finding_id ('{self.context.finding_id}') must match "
                f"finding.finding_instance_id ('{self.finding.finding_instance_id}')"
            )
        if not self.prompt_version or not self.prompt_version.strip():
            raise ValueError("prompt_version must not be empty")
        if not self.output_schema_version or not self.output_schema_version.strip():
            raise ValueError("output_schema_version must not be empty")
        if not self.prompt_type or not self.prompt_type.strip():
            raise ValueError("prompt_type must not be empty")
        return self


class TriageDecision(BaseDomainModel):
    """Triage decision produced by LLM provider."""

    model_verdict: ModelVerdict
    model_confidence: ModelConfidence
    summary: str
    evidence: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    model_version: str
    prompt_version: str

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for TriageDecision."""
        if not self.summary or not self.summary.strip():
            raise ValueError("summary must not be empty")
        if not self.model_version or not self.model_version.strip():
            raise ValueError("model_version must not be empty")
        if not self.prompt_version or not self.prompt_version.strip():
            raise ValueError("prompt_version must not be empty")
        return self


class PolicyDecision(BaseDomainModel):
    """System decision after applying conservative policy rules."""

    action: PolicyAction
    reasons: list[str]
    policy_version: str
    escalated: bool
    escalation_reason: str | None = None

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for PolicyDecision."""
        if not self.reasons:
            raise ValueError("reasons must not be empty")
        if not self.policy_version or not self.policy_version.strip():
            raise ValueError("policy_version must not be empty")
        if self.escalated and (self.escalation_reason is None or not self.escalation_reason.strip()):
            raise ValueError("escalation_reason is required when escalated is True")
        return self


class ProcessingError(BaseDomainModel):
    """Safe, serializable error record for pipeline reports."""

    finding_id: str | None = None
    scanner: ScannerType | None = None
    stage: ProcessingStage
    error_code: str
    safe_message: str
    retryable: bool = False

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for ProcessingError."""
        if not self.error_code or not self.error_code.strip():
            raise ValueError("error_code must not be empty")
        if not self.safe_message or not self.safe_message.strip():
            raise ValueError("safe_message must not be empty")
        return self


class TriageResult(BaseDomainModel):
    """Aggregated final result for a single finding."""

    finding: NormalizedFinding
    sanitized_context: SanitizedContext
    triage_decision: TriageDecision | None = None
    policy_decision: PolicyDecision
    processing_errors: list[ProcessingError] = Field(default_factory=list)
    processed_at: datetime
    processing_duration_ms: int | None = None

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for TriageResult."""
        if self.sanitized_context.finding_id != self.finding.finding_instance_id:
            raise ValueError(
                f"sanitized_context.finding_id ('{self.sanitized_context.finding_id}') must match "
                f"finding.finding_instance_id ('{self.finding.finding_instance_id}')"
            )
        if self.triage_decision is None:
            if self.policy_decision.action != PolicyAction.TRIAGE_ERROR:
                raise ValueError("policy_decision.action must be TRIAGE_ERROR when triage_decision is None")
            if not any(err.stage == ProcessingStage.TRIAGE for err in self.processing_errors):
                raise ValueError(
                    "processing_errors must contain at least one ProcessingError with stage=TRIAGE when triage_decision is None"
                )

        if self.policy_decision.action == PolicyAction.TRIAGE_ERROR and not self.processing_errors:
            raise ValueError(
                "processing_errors must not be empty when policy_decision.action is TRIAGE_ERROR"
            )

        if self.processing_duration_ms is not None and self.processing_duration_ms < 0:
            raise ValueError("processing_duration_ms cannot be negative")
        return self


class RunMetadata(BaseDomainModel):
    """Run-level metadata without absolute repository paths."""

    run_id: str
    repository_name: str
    repository_identifier: str
    commit_sha: str | None = None
    working_tree_state: str | None = None
    artifact_repository_match: ArtifactRepositoryMatch
    scanners_attempted: list[ScannerType]
    scanners_succeeded: list[ScannerType]
    scanner_versions: dict[str, str | None] = Field(default_factory=dict)
    scanner_config_ids: dict[str, str | None] = Field(default_factory=dict)
    input_artifact_hashes: dict[str, str | None] = Field(default_factory=dict)
    prompt_version: str | None = None
    model_version: str | None = None
    policy_version: str
    triage_provider: str
    tool_version: str
    cli_mode: str
    started_at: datetime
    completed_at: datetime
    total_findings_parsed: int = 0
    findings_triaged_ok: int = 0
    findings_with_errors: int = 0

    @model_validator(mode="after")
    def validate_invariants(self) -> Self:
        """Enforce domain invariants for RunMetadata."""
        if not self.run_id or not self.run_id.strip():
            raise ValueError("run_id must not be empty")

        if not self.repository_name or not self.repository_name.strip():
            raise ValueError("repository_name must not be empty")
        if _is_absolute_path(self.repository_name):
            raise ValueError("repository_name must not contain absolute path")

        if not self.repository_identifier or not self.repository_identifier.strip():
            raise ValueError("repository_identifier must not be empty")
        if _is_absolute_path(self.repository_identifier):
            raise ValueError("repository_identifier must not contain absolute path")

        for ctrl_char in ("\n", "\r", "\t", "\0"):
            if ctrl_char in self.repository_name:
                raise ValueError("repository_name must not contain newlines or control characters")
            if ctrl_char in self.repository_identifier:
                raise ValueError("repository_identifier must not contain newlines or control characters")

        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be earlier than started_at")
        if (
            self.total_findings_parsed < 0
            or self.findings_triaged_ok < 0
            or self.findings_with_errors < 0
        ):
            raise ValueError("Finding counts cannot be negative")
        if not set(self.scanners_succeeded).issubset(set(self.scanners_attempted)):
            raise ValueError("scanners_succeeded must be a subset of scanners_attempted")
        return self


class BatchResult(BaseDomainModel):
    """Top-level batch execution output model."""

    run_metadata: RunMetadata
    results: list[TriageResult]
    scanner_errors: list[ProcessingError] = Field(default_factory=list)


class ScannerParseResult(BaseDomainModel):
    """Immutable result of parsing a single scanner artifact.

    Uses tuples (not lists) so that the returned collections cannot be
    mutated after the parser hands them off.  Does not contain the raw
    artifact content or absolute artifact paths.
    """

    findings: tuple[NormalizedFinding, ...] = ()
    errors: tuple[ProcessingError, ...] = ()
