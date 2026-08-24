"""Bounded, source-free index for the focused Python business-logic detector."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path

from sast_triage.logic.analyzer import analyze_python_module
from sast_triage.logic.models import LogicCandidate
from sast_triage.models import FindingType, NormalizedFinding, ScannerType

LOGIC_DETECTOR_CONFIG_ID = "python-idor-business-logic-v3"
_PROJECT_MARKERS = ("pyproject.toml", "setup.cfg", "setup.py")
_SKIPPED_PARTS = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}
)
_HIGH_RISK_PATH_TOKENS = (
    "admin",
    "api",
    "auth",
    "billing",
    "checkout",
    "finance",
    "loan",
    "order",
    "payment",
    "permission",
    "profile",
    "route",
    "transfer",
    "user",
    "view",
    "wallet",
    "workflow",
)


@dataclass(frozen=True, slots=True)
class LogicFindingIndex:
    """Immutable logic candidates without raw source or literal values."""

    candidates: tuple[LogicCandidate, ...]
    skipped_files: int = 0

    def candidate_for(self, finding: NormalizedFinding) -> LogicCandidate | None:
        """Return the unique candidate backing a projected logic finding."""
        logic_class = finding.metadata.get("logic_class")
        matches = [
            candidate
            for candidate in self.candidates
            if candidate.file_path == finding.file_path
            and candidate.line == finding.start_line
            and candidate.bug_class.value == logic_class
        ]
        return matches[0] if len(matches) == 1 else None

    def discover_findings(
        self,
        existing: tuple[NormalizedFinding, ...] = (),
    ) -> tuple[NormalizedFinding, ...]:
        """Project focused logic candidates into normalized findings."""
        occupied = {
            (finding.rule_id, finding.file_path, finding.start_line)
            for finding in existing
        }
        findings: list[NormalizedFinding] = []
        for candidate in self.candidates:
            rule_id = f"module2.logic.{candidate.bug_class.value.replace('_', '-')}"
            identity = (rule_id, candidate.file_path, candidate.line)
            if identity in occupied:
                continue
            digest = hashlib.sha256(
                (
                    f"MODULE2:LOGIC:{candidate.bug_class.value}:"
                    f"{candidate.file_path}:{candidate.line}:{candidate.function}"
                ).encode()
            ).hexdigest()
            findings.append(
                NormalizedFinding(
                    finding_instance_id=digest,
                    scanner=ScannerType.MODULE2,
                    finding_type=FindingType.SAST,
                    rule_id=rule_id,
                    rule_name=(
                        "Bounded AST candidate for "
                        + candidate.bug_class.value.replace("_", " ")
                    ),
                    file_path=candidate.file_path,
                    start_line=candidate.line,
                    end_line=candidate.end_line,
                    severity=candidate.severity,
                    message=(
                        "A bounded source-to-guard-to-sink trace matched a "
                        f"{candidate.bug_class.value.replace('_', ' ')} pattern."
                    ),
                    metadata={
                        "analysis_scope": "bounded_python_ast",
                        "analysis_complete": candidate.analysis_complete,
                        "component": candidate.component,
                        "logic_class": candidate.bug_class.value,
                        "entrypoint": candidate.function,
                        "entrypoint_exposed": candidate.entrypoint,
                        "source_kind": candidate.source_kind,
                        "sink_kind": candidate.sink_kind,
                        "guards": list(candidate.guards),
                        "trace": list(candidate.trace),
                        "cwe": candidate.cwe,
                        "risk_score": candidate.risk_score,
                        "risk_level": candidate.risk_level,
                        "risk_factors": dict(candidate.risk_factors),
                        "remediation": candidate.remediation,
                        "validation_checklist": list(candidate.validation_checklist),
                    },
                )
            )
            occupied.add(identity)
        return tuple(findings)


def _analysis_priority(path: Path, root: Path) -> tuple[int, int, str]:
    """Prioritize security-sensitive application files when the budget binds."""
    relative = path.relative_to(root).as_posix().lower()
    parts = set(Path(relative).parts)
    is_test_or_example = bool(
        parts.intersection({"test", "tests", "example", "examples"})
    )
    token_hits = sum(token in relative for token in _HIGH_RISK_PATH_TOKENS)
    return (1 if is_test_or_example else 0, -token_hits, relative)


def _component_roots(root: Path) -> tuple[str, ...]:
    roots = {"."}
    for marker in _PROJECT_MARKERS:
        for path in root.rglob(marker):
            if _SKIPPED_PARTS.isdisjoint(path.relative_to(root).parts):
                roots.add(path.parent.relative_to(root).as_posix() or ".")
    return tuple(sorted(roots, key=lambda value: (value.count("/"), value)))


def _component_for(file_path: str, roots: tuple[str, ...]) -> str:
    return max(
        (
            root
            for root in roots
            if root == "." or file_path == root or file_path.startswith(f"{root}/")
        ),
        key=len,
    )


def build_logic_index(
    repository_root: Path,
    *,
    max_python_files: int = 20_000,
    max_file_size_bytes: int = 1_048_576,
) -> LogicFindingIndex:
    """Analyze bounded Python files without retaining source text or AST nodes."""
    root = repository_root.resolve()
    component_roots = _component_roots(root)
    paths = [
        path
        for path in root.rglob("*.py")
        if _SKIPPED_PARTS.isdisjoint(path.relative_to(root).parts)
        and not path.is_symlink()
    ]
    paths.sort(key=lambda path: _analysis_priority(path, root))

    candidates: list[LogicCandidate] = []
    skipped = 0
    for number, path in enumerate(paths):
        if number >= max_python_files:
            skipped += 1
            continue
        relative = path.relative_to(root).as_posix()
        try:
            resolved = path.resolve(strict=True)
            if (
                not resolved.is_relative_to(root)
                or resolved.stat().st_size > max_file_size_bytes
            ):
                skipped += 1
                continue
            tree = ast.parse(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            skipped += 1
            continue
        candidates.extend(
            analyze_python_module(
                tree,
                file_path=relative,
                component=_component_for(relative, component_roots),
            )
        )

    return LogicFindingIndex(
        candidates=tuple(candidates),
        skipped_files=skipped,
    )
