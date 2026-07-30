"""
External Storage & Security Controls Module
============================================
Manages scan artifact storage outside scanned Git worktrees with restrictive file
permissions (0700 dir / 0600 file) and retention policies.
"""

import os
import json
import shutil
import datetime
from pathlib import Path
from typing import Union, Dict, Any, List, Optional
from src.core.schema import UnifiedFinding, ScanManifest, CoverageReport


DEFAULT_ARTIFACT_ROOT = Path.home() / ".sast_platform" / "artifacts"


class ExternalStorageManager:
    """Manages secure artifact storage outside git worktrees with strict file permissions."""

    def __init__(self, storage_root: Optional[Union[str, Path]] = None):
        self.storage_root = Path(storage_root) if storage_root else DEFAULT_ARTIFACT_ROOT
        self._ensure_secure_directory(self.storage_root)

    def _ensure_secure_directory(self, path: Path):
        """Create directory if not existing and set restrictive permissions (0700)."""
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except Exception:
            pass

    def _ensure_secure_file(self, path: Path):
        """Set restrictive file permissions (0600)."""
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    def get_run_dir(self, repo_name: str, run_id: str) -> Path:
        """Create run directory under secure storage root."""
        run_dir = self.storage_root / repo_name / run_id
        self._ensure_secure_directory(run_dir)
        return run_dir

    def save_scan_manifest(self, manifest: ScanManifest, run_dir: Path) -> Path:
        """Save ScanManifest JSON with secure permissions."""
        file_path = run_dir / "scan_manifest.json"
        content = json.dumps(manifest.model_dump(), indent=2, ensure_ascii=False)
        file_path.write_text(content, encoding="utf-8")
        self._ensure_secure_file(file_path)
        return file_path

    def save_coverage_report(self, coverage: CoverageReport, run_dir: Path) -> Path:
        """Save CoverageReport JSON with secure permissions."""
        file_path = run_dir / "coverage_report.json"
        content = json.dumps(coverage.model_dump(), indent=2, ensure_ascii=False)
        file_path.write_text(content, encoding="utf-8")
        self._ensure_secure_file(file_path)
        return file_path

    def save_findings_json(self, findings: List[UnifiedFinding], filename: str, run_dir: Path) -> Path:
        """Save findings JSON with secure permissions."""
        file_path = run_dir / filename
        data = [f.model_dump() for f in findings]
        content = json.dumps(data, indent=2, ensure_ascii=False)
        file_path.write_text(content, encoding="utf-8")
        self._ensure_secure_file(file_path)
        return file_path

    def enforce_retention_policy(self, repo_name: str, max_runs: int = 10):
        """Clean up older artifact runs exceeding max_runs retention limit."""
        repo_dir = self.storage_root / repo_name
        if not repo_dir.exists():
            return

        run_dirs = sorted([d for d in repo_dir.iterdir() if d.is_dir()], key=lambda d: d.stat().st_mtime)
        if len(run_dirs) > max_runs:
            for old_dir in run_dirs[:-max_runs]:
                shutil.rmtree(old_dir, ignore_errors=True)
