"""
Context Policy Module — GuardRequirementPolicy Loader
======================================================
Loads project_context.yaml and provides declarative GuardRequirementPolicy evidence
for logic bug candidate detection and triage evaluation.
"""

import yaml
from pathlib import Path
from typing import Optional, Dict, Any
from src.core.schema import ProjectContext, GuardCategory


class GuardRequirementPolicy:
    """Provides project context invariants and guard policy requirements."""

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "config" / "project_context.yaml"
        self.config_path = config_path
        self.project_context = self._load_context()

    def _load_context(self) -> ProjectContext:
        """Load and parse project_context.yaml file."""
        if not self.config_path.exists():
            return ProjectContext()

        try:
            content = self.config_path.read_text(encoding="utf-8")
            data = yaml.safe_load(content) or {}
            return ProjectContext(**data)
        except Exception as e:
            print(f"[!] Warning: Failed to load project_context.yaml ({e})")
            return ProjectContext()

    def get_guard_evidence_for_route(self, route_path: str, sink_operation: str) -> Dict[str, Any]:
        """Match route against authorization policies and security invariants."""
        matching_policies = []
        for pol in self.project_context.authorization_policies:
            app_routes = pol.get("applicable_routes", [])
            for pattern in app_routes:
                pattern_clean = pattern.replace("*", "")
                if pattern_clean in route_path:
                    matching_policies.append(pol)

        return {
            "system_exposure": self.project_context.system_exposure,
            "matching_policies": matching_policies,
            "security_invariants": self.project_context.security_invariants,
            "policy_count": len(matching_policies)
        }
