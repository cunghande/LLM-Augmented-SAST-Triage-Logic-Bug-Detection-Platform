"""Điều phối mở rộng bằng chứng có giới hạn và xác định."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from sast_triage.analysis.base import AnalysisBackend, GraphEvidence
from sast_triage.analysis.rule_semantics import sink_only_evidence_is_sufficient
from sast_triage.models import NormalizedFinding


@dataclass(frozen=True, slots=True)
class GraphEvidenceExpansionResult:
    """Bounded graph expansion result without raw query transcripts."""

    evidence: GraphEvidence
    tool_calls: int
    tool_names: tuple[str, ...]


class GraphEvidenceExpansionAgent:
    """Iteratively fill explicit Joern evidence gaps using three fixed tools."""

    def __init__(
        self,
        backend: AnalysisBackend,
        finding: NormalizedFinding,
        initial: GraphEvidence,
        *,
        max_iterations: int = 5,
        max_tool_calls: int = 5,
        max_depth: int = 5,
        max_paths: int = 10,
        max_nodes: int = 500,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not 1 <= max_iterations <= 5:
            raise ValueError("max_iterations must be between 1 and 5")
        if not 1 <= max_tool_calls <= 5:
            raise ValueError("max_tool_calls must be between 1 and 5")
        if not 1 <= max_depth <= 5:
            raise ValueError("max_depth must be between 1 and 5")
        if max_paths < 1 or max_nodes < 1 or timeout_seconds <= 0:
            raise ValueError("graph query budgets must be positive")
        self._backend = backend
        self._finding = finding
        self._initial = initial
        self._max_iterations = max_iterations
        self._max_tool_calls = max_tool_calls
        self._max_depth = max_depth
        self._max_paths = max_paths
        self._max_nodes = max_nodes
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _is_intrinsic(finding: NormalizedFinding) -> bool:
        return sink_only_evidence_is_sufficient(finding)

    def _sufficient(self, evidence: GraphEvidence) -> bool:
        if evidence.sink_symbol is None:
            return False
        if self._is_intrinsic(self._finding):
            return True
        return (
            evidence.source_type is not None
            and evidence.source_reaches_sink is True
            and evidence.path_complete
            and evidence.reachability_resolved
            and "JOERN_CONTROL_FLOW" in evidence.provenance
        )

    def _next_tool(self, evidence: GraphEvidence) -> str | None:
        if (
            evidence.source_type is None
            or evidence.source_reaches_sink is not True
            or not evidence.path_complete
        ):
            return "trace_dataflow"
        if not evidence.reachability_resolved:
            return "find_reachability"
        if "JOERN_CONTROL_FLOW" not in evidence.provenance:
            return "inspect_security_control"
        return None

    def expand(self) -> GraphEvidenceExpansionResult:
        """Run at most five one-tool iterations and stop on no progress."""
        evidence = self._initial
        tool_names: list[str] = []
        visited: set[tuple[str, tuple[object, ...]]] = set()
        started = time.monotonic()

        for _ in range(self._max_iterations):
            if self._sufficient(evidence) or len(tool_names) >= self._max_tool_calls:
                break
            if time.monotonic() - started >= self._timeout_seconds:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_FINDING_TIMEOUT"))
                    ),
                )
                break
            tool_name = self._next_tool(evidence)
            if tool_name is None:
                break
            signature = (tool_name, evidence.fingerprint())
            if signature in visited:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_QUERY_REPEATED"))
                    ),
                )
                break
            visited.add(signature)
            previous = evidence.fingerprint()
            result = self._backend.run_tool(
                tool_name,
                self._finding,
                evidence,
                max_depth=self._max_depth,
                max_paths=self._max_paths,
                max_nodes=self._max_nodes,
            )
            tool_names.append(tool_name)
            evidence = evidence.merge(result)
            if evidence.fingerprint() == previous:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_NO_PROGRESS"))
                    ),
                )
                break

        if not self._sufficient(evidence) and len(tool_names) >= self._max_tool_calls:
            evidence = replace(
                evidence,
                limitations=tuple(
                    dict.fromkeys((*evidence.limitations, "MAX_TOOL_CALLS_REACHED"))
                ),
            )
        return GraphEvidenceExpansionResult(
            evidence=evidence,
            tool_calls=len(tool_names),
            tool_names=tuple(tool_names),
        )
