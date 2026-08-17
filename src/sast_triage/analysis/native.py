"""Adapter for the existing bounded Python repository index."""

from __future__ import annotations

import time
from pathlib import Path

from sast_triage import __version__ as TOOL_VERSION
from sast_triage.analysis.base import AnalysisIdentity, GraphEvidence
from sast_triage.context.repository_index import (
    MODULE2_CONFIG_ID,
    RepositoryEvidenceIndex,
    build_repository_index,
)
from sast_triage.models import NormalizedFinding


class NativeAnalysisBackend:
    """Expose the existing native index through the shared backend contract."""

    def __init__(
        self,
        repository: Path,
        repository_identifier: str,
        *,
        module2_enabled: bool,
    ) -> None:
        started = time.perf_counter()
        self.repository_index: RepositoryEvidenceIndex | None = (
            build_repository_index(repository, repository_identifier)
            if module2_enabled
            else None
        )
        self.identity = AnalysisIdentity(
            backend="native",
            version=TOOL_VERSION,
            config_id=(MODULE2_CONFIG_ID if module2_enabled else "native-local-evidence-v1"),
            build_status="complete",
            build_seconds=round(time.perf_counter() - started, 6),
        )

    def discover_findings(
        self,
        existing: tuple[NormalizedFinding, ...],
    ) -> tuple[NormalizedFinding, ...]:
        """Use the native index when Module 2 is enabled."""
        if self.repository_index is None:
            return ()
        return self.repository_index.discover_findings(existing)

    def initial_evidence(self, finding: NormalizedFinding) -> GraphEvidence | None:
        """Signal that the existing local AST engine owns native evidence."""
        return None

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
        """Native expansion remains implemented by EvidenceToolbox."""
        return evidence
