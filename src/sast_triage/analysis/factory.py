"""Create exactly one repository analysis backend for a run."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sast_triage.analysis.base import AnalysisBackend
from sast_triage.analysis.joern import JoernAnalysisBackend


@contextmanager
def analysis_backend_session(
    repository: Path,
    repository_identifier: str,
    *,
    module2_enabled: bool,
    logic_detector: str = "off",
) -> Iterator[AnalysisBackend]:
    """Yield the repository's single Joern analysis backend."""
    with JoernAnalysisBackend(
        repository,
        repository_identifier,
        module2_enabled=module2_enabled,
        logic_detector=logic_detector,
    ) as joern:
        yield joern
