"""Internal typed evidence models for bounded context analysis.

These models are not public report/domain models.  Any code text stored here
must already be sanitized before the package is rendered for a provider.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceStatus(str, Enum):
    """Completeness state of context evidence."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ToolStatus(str, Enum):
    """Safe status returned by an evidence tool."""

    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """Allowlisted finding facts included in provider evidence."""

    rule_id: str
    category: str | None
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int | None


@dataclass(frozen=True, slots=True)
class RelevantCodeEvidence:
    """Sanitized code selected around the finding."""

    scope_type: str
    function_name: str | None
    class_name: str | None
    start_line: int | None
    end_line: int | None
    code: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    """Safe structural description of a potential data source."""

    expression: str
    source_type: str
    user_controlled: bool
    file_path: str
    line: int | None
    confidence: str


@dataclass(frozen=True, slots=True)
class SinkEvidence:
    """Safe structural description of a security-sensitive sink."""

    expression: str
    sink_type: str
    dangerous_argument: str | None
    dangerous_conditions: tuple[str, ...]
    file_path: str
    line: int | None


@dataclass(frozen=True, slots=True)
class TaintStep:
    """One safe source-to-sink step."""

    order: int
    kind: str
    expression: str
    function_id: str | None
    file_path: str
    line: int | None


@dataclass(frozen=True, slots=True)
class TaintPathEvidence:
    """Bounded local or interprocedural taint result."""

    path_type: str
    steps: tuple[TaintStep, ...]
    source_reaches_sink: bool | None
    complete: bool


@dataclass(frozen=True, slots=True)
class SecurityControlEvidence:
    """Guard, validation, sanitizer, or safe API relevant to the taint path."""

    symbol: str
    control_type: str
    on_taint_path: bool
    protects_target: bool | None
    effective: bool | None
    confidence: str


@dataclass(frozen=True, slots=True)
class ContextCompleteness:
    """Explicit context-sufficiency facts consumed by the gate."""

    status: EvidenceStatus
    source_resolved: bool
    sink_resolved: bool
    taint_path_complete: bool
    call_chain_complete: bool
    reachability_resolved: bool
    unresolved_symbols: tuple[str, ...] = ()
    missing_information: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    """Internal evidence assembled from AST and bounded dataflow analysis."""

    finding_id: str
    finding: FindingEvidence
    relevant_code: RelevantCodeEvidence
    source: SourceEvidence | None
    sink: SinkEvidence | None
    taint_path: TaintPathEvidence
    security_controls: tuple[SecurityControlEvidence, ...]
    context_completeness: ContextCompleteness
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Uniform safe JSON-compatible tool result."""

    status: ToolStatus
    complete: bool
    evidence: dict[str, Any]
    limitations: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def to_json_dict(self) -> dict[str, Any]:
        """Return the required JSON result shape."""
        return {
            "status": self.status.value,
            "complete": self.complete,
            "evidence": self.evidence,
            "limitations": list(self.limitations),
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class EvidenceExpansionResult:
    """Agent expansion result without raw tool transcripts."""

    evidence: EvidencePackage
    tool_calls: int
    tool_names: tuple[str, ...]
