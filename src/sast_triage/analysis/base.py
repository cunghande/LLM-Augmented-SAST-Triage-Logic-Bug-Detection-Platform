"""Typed internal contract for the Joern repository analysis backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from sast_triage.models import NormalizedFinding

if TYPE_CHECKING:
    from sast_triage.logic.index import LogicFindingIndex


@dataclass(frozen=True, slots=True)
class AnalysisIdentity:
    """Safe metadata describing one repository analysis session."""

    backend: str
    version: str
    config_id: str
    build_status: str
    build_seconds: float


@dataclass(frozen=True, slots=True)
class GraphStep:
    """One source-free CPG path step."""

    kind: str
    symbol: str
    file_path: str
    line: int | None


@dataclass(frozen=True, slots=True)
class GraphControl:
    """A bounded security-control candidate returned by an analysis backend."""

    symbol: str
    control_type: str
    on_path: bool
    effective: bool | None


@dataclass(frozen=True, slots=True)
class GraphEvidence:
    """Safe graph projection; it never contains source code or literal values."""

    source_type: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    source_user_controlled: bool | None = None
    sink_type: str | None = None
    sink_symbol: str | None = None
    sink_file: str | None = None
    sink_line: int | None = None
    paths: tuple[tuple[GraphStep, ...], ...] = ()
    callers: tuple[GraphStep, ...] = ()
    controls: tuple[GraphControl, ...] = ()
    source_reaches_sink: bool | None = None
    path_complete: bool = False
    reachability_resolved: bool = False
    limitations: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def merge(self, other: GraphEvidence) -> GraphEvidence:
        """Merge new graph facts without discarding earlier safe evidence."""
        return GraphEvidence(
            source_type=other.source_type or self.source_type,
            source_file=other.source_file or self.source_file,
            source_line=(other.source_line if other.source_line is not None else self.source_line),
            source_user_controlled=(
                other.source_user_controlled
                if other.source_user_controlled is not None
                else self.source_user_controlled
            ),
            sink_type=other.sink_type or self.sink_type,
            sink_symbol=other.sink_symbol or self.sink_symbol,
            sink_file=other.sink_file or self.sink_file,
            sink_line=other.sink_line if other.sink_line is not None else self.sink_line,
            paths=tuple(dict.fromkeys((*self.paths, *other.paths))),
            callers=tuple(dict.fromkeys((*self.callers, *other.callers))),
            controls=tuple(dict.fromkeys((*self.controls, *other.controls))),
            source_reaches_sink=(
                other.source_reaches_sink
                if other.source_reaches_sink is not None
                else self.source_reaches_sink
            ),
            path_complete=self.path_complete or other.path_complete,
            reachability_resolved=self.reachability_resolved or other.reachability_resolved,
            limitations=tuple(dict.fromkeys((*self.limitations, *other.limitations))),
            provenance=tuple(dict.fromkeys((*self.provenance, *other.provenance))),
        )

    def fingerprint(self) -> tuple[object, ...]:
        """Return a stable, source-free progress fingerprint for loop detection."""
        return (
            self.source_type,
            self.source_file,
            self.source_line,
            self.sink_type,
            self.sink_symbol,
            self.sink_file,
            self.sink_line,
            self.paths,
            self.callers,
            self.controls,
            self.source_reaches_sink,
            self.path_complete,
            self.reachability_resolved,
            self.provenance,
        )


class AnalysisBackend(Protocol):
    """Internal interface implemented by the run's Joern backend."""

    identity: AnalysisIdentity
    logic_index: LogicFindingIndex | None

    def discover_findings(
        self,
        existing: tuple[NormalizedFinding, ...],
    ) -> tuple[NormalizedFinding, ...]:
        """Return additional bounded cross-file findings."""

    def discover_logic_findings(
        self,
        detector: str,
        existing: tuple[NormalizedFinding, ...],
    ) -> tuple[NormalizedFinding, ...]:
        """Return findings from an explicitly selected logic detector."""

    def initial_evidence(self, finding: NormalizedFinding) -> GraphEvidence:
        """Return source-free initial CPG evidence for one finding."""

    def run_tool(
        self,
        tool_name: str,
        finding: NormalizedFinding,
        evidence: GraphEvidence,
        *,
        max_depth: int,
        max_paths: int,
        max_nodes: int,
    ) -> GraphEvidence:
        """Execute one allowlisted evidence query."""
