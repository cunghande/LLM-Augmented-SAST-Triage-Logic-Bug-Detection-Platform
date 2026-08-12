"""Create exactly one repository analysis backend for a run."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sast_triage.analysis.base import AnalysisBackend
from sast_triage.analysis.joern import JoernAnalysisBackend
from sast_triage.analysis.native import NativeAnalysisBackend


@contextmanager
def analysis_backend_session(
    backend: str,
    repository: Path,
    repository_identifier: str,
    *,
    module2_enabled: bool,
) -> Iterator[AnalysisBackend]:
    """Yield one backend without mixing evidence engines in a run."""
    if backend == "native":
        yield NativeAnalysisBackend(
            repository,
            repository_identifier,
            module2_enabled=module2_enabled,
        )
        return
    if backend == "joern":
        with JoernAnalysisBackend(
            repository,
            repository_identifier,
            module2_enabled=module2_enabled,
        ) as joern:
            yield joern
        return
    raise ValueError("Unsupported analysis backend.")
