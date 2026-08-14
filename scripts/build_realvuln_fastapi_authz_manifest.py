"""Build a source-free FastAPI authorization manifest from RealVuln v2 GT."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REALVULN = ROOT / "benchmarks" / "ExternalTargets" / "Real-Vuln-Benchmark"
REPOS = REALVULN / "repos"
GROUND_TRUTH = REALVULN / "ground-truth"
OUTPUT = ROOT / "benchmarks" / "LogicAuthz" / "realvuln-fastapi-natural-v1.json"
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
POSITIVE_CLASSES = {"broken_access_control", "missing_authentication"}
NEGATIVE_CLASSES = {
    "broken_access_control_false_positive",
    "missing_authentication_false_positive",
    "idor_false_positive",
}


def _decorator_leaf(node: ast.expr) -> str | None:
    """Return the final identifier in a decorator call."""
    if not isinstance(node, ast.Call):
        return None
    target = node.func
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _route_lines(source_path: Path) -> dict[str, int]:
    """Map directly decorated FastAPI handler names to decorator lines."""
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return {}
    routes: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if _decorator_leaf(decorator) in ROUTE_METHODS:
                routes[node.name] = decorator.lineno
                break
    return routes


def _theme(repo_id: str) -> str:
    """Return a business-theme key used to prevent split leakage."""
    for value in ("fintech-lending", "marketplace-commerce", "logistics-dispatch", "property-management", "support-desk"):
        if value in repo_id:
            return value
    return "human-fastapi"


def _split(theme: str) -> str:
    """Keep every provider variant of one business theme in one split."""
    if theme in {"fintech-lending", "marketplace-commerce"}:
        return "held_out"
    if theme in {"logistics-dispatch", "property-management"}:
        return "calibration"
    return "development"


def main() -> int:
    """Create the pre-split natural-case manifest without copying source text."""
    benchmark = json.loads((REALVULN / "benchmark-manifest.json").read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = []
    excluded_non_routes = 0
    for repo_id, repo_metadata in sorted(benchmark["repos"].items()):
        if repo_metadata.get("framework") != "fastapi":
            continue
        repository_root = REPOS / repo_id
        gt_path = GROUND_TRUTH / repo_id / "ground-truth.json"
        if not repository_root.is_dir() or not gt_path.is_file():
            continue
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        route_cache: dict[str, dict[str, int]] = {}
        for finding in gt.get("findings", []):
            vulnerability_class = finding.get("vulnerability_class")
            is_vulnerable = finding.get("is_vulnerable") is True
            if (is_vulnerable and vulnerability_class not in POSITIVE_CLASSES) or (
                not is_vulnerable and vulnerability_class not in NEGATIVE_CLASSES
            ):
                continue
            relative_file = str(finding.get("file", "")).replace("\\", "/")
            function_name = str(finding.get("location", {}).get("function", ""))
            if relative_file not in route_cache:
                route_cache[relative_file] = _route_lines(repository_root / relative_file)
            route_line = route_cache[relative_file].get(function_name)
            if route_line is None:
                excluded_non_routes += 1
                continue
            theme = _theme(repo_id)
            cases.append(
                {
                    "case_id": f"{repo_id}:{finding['id']}",
                    "repository_identifier": repo_id,
                    "repository_root": str(repository_root.relative_to(ROOT)).replace("\\", "/"),
                    "file_path": relative_file,
                    "route_line": route_line,
                    "expected_state": "MISSING_AUTHZ" if is_vulnerable else "PROTECTED",
                    "split": _split(theme),
                    "case_type": vulnerability_class,
                    "theme": theme,
                    "negative_control_type": None if is_vulnerable else "realvuln_false_positive",
                    "reviewer_ids": [],
                    "adjudication_status": "UNREVIEWED",
                }
            )
    payload = {
        "version": "realvuln-v2-fastapi-authz-natural-v1",
        "dataset_kind": "realvuln_official_unreviewed",
        "held_out_frozen": True,
        "ground_truth_sha256": benchmark["ground_truth_content_hash"],
        "selection": {
            "positive_classes": sorted(POSITIVE_CLASSES),
            "negative_classes": sorted(NEGATIVE_CLASSES),
            "direct_fastapi_routes_only": True,
            "excluded_non_route_findings": excluded_non_routes,
            "note": "Specialized authz labels have not received an independent two-reviewer audit.",
        },
        "cases": cases,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(cases)} cases; excluded {excluded_non_routes} non-route findings: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
