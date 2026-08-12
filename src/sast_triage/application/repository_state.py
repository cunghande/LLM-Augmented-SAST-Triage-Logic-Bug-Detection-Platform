"""Read minimal, report-safe repository state for reproducibility."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40,64}")


def read_repository_state(repository: Path) -> tuple[str | None, str | None]:
    """Return HEAD SHA and clean/dirty state without reading Git history."""
    if shutil.which("git") is None:
        return None, None
    root = repository.resolve()
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            check=False,
            shell=False,
            timeout=5.0,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None, None
    raw_head = head.stdout.decode("ascii", errors="ignore").strip()
    if head.returncode != 0 or _COMMIT_PATTERN.fullmatch(raw_head) is None:
        return None, None

    try:
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            check=False,
            shell=False,
            timeout=5.0,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return raw_head.lower(), "unknown"
    working_tree_state = (
        "clean" if status.returncode == 0 and not status.stdout.strip() else "dirty"
    )
    return raw_head.lower(), working_tree_state
