"""Build a source-free benchmark manifest from official vendor advisories."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Revision:
    """One pinned vulnerable or fixed repository revision."""

    identifier: str
    root: str
    commit: str
    expected_state: str


@dataclass(frozen=True, slots=True)
class AdvisoryRoute:
    """One endpoint named by an official vendor advisory."""

    advisory_id: str
    advisory_url: str
    cwe: str
    case_type: str
    file_path: str
    method: str
    local_path: str
    public_path: str


LANGFLOW_VULNERABLE = Revision(
    "official-langflow-v1.7.3",
    "benchmarks/ExternalTargets/OfficialAuthz/langflow-v1.7.3",
    "cd2b1b3d0867719b7d8482840746d1b105b1cd0d",
    "MISSING_AUTHZ",
)
LANGFLOW_FIXED = Revision(
    "official-langflow-fixed",
    "benchmarks/ExternalTargets/OfficialAuthz/langflow-fixed",
    "976ec789d2886a86de109c044d089d68e96c9a35",
    "PROTECTED",
)
OPEN_WEBUI_VULNERABLE = Revision(
    "official-open-webui-v0.8.11",
    "benchmarks/ExternalTargets/OfficialAuthz/open-webui-v0.8.11",
    "4d058a125b17eb57212af5eab98d683548d546e3",
    "MISSING_AUTHZ",
)
OPEN_WEBUI_FIXED = Revision(
    "official-open-webui-fixed",
    "benchmarks/ExternalTargets/OfficialAuthz/open-webui-fixed",
    "01f4282f1ffe0d6212f58d3afbeae21fffd0c4be",
    "PROTECTED",
)


LANGFLOW_ROUTES = (
    AdvisoryRoute(
        "GHSA-7grx-3xcx-2xv5",
        "https://github.com/langflow-ai/langflow/security/advisories/GHSA-7grx-3xcx-2xv5",
        "CWE-862",
        "missing_function_authz",
        "src/backend/base/langflow/api/v1/files.py",
        "GET",
        "/images/{flow_id}/{file_name}",
        "/api/v1/files/images/{flow_id}/{file_name}",
    ),
    *(
        AdvisoryRoute(
            "GHSA-9c59-2mvc-vfr8",
            "https://github.com/langflow-ai/langflow/security/advisories/GHSA-9c59-2mvc-vfr8",
            "CWE-639",
            "idor_bola",
            "src/backend/base/langflow/api/v1/monitor.py",
            method,
            local_path,
            f"/api/v1/monitor{local_path}",
        )
        for method, local_path in (
            ("GET", "/builds"),
            ("DELETE", "/builds"),
            ("DELETE", "/messages"),
            ("PUT", "/messages/{message_id}"),
            ("PATCH", "/messages/session/{old_session_id}"),
            ("DELETE", "/messages/session/{session_id}"),
            ("GET", "/transactions"),
        )
    ),
    AdvisoryRoute(
        "GHSA-qrpv-q767-xqq2",
        "https://github.com/langflow-ai/langflow/security/advisories/GHSA-qrpv-q767-xqq2",
        "CWE-639",
        "idor_bola",
        "src/backend/base/langflow/api/v1/openai_responses.py",
        "POST",
        "/responses",
        "/api/v1/responses",
    ),
)

OPEN_WEBUI_ROUTES = tuple(
    AdvisoryRoute(
        "GHSA-4g37-7p2c-38r9",
        "https://github.com/open-webui/open-webui/security/advisories/GHSA-4g37-7p2c-38r9",
        "CWE-639",
        "idor_bola",
        "backend/open_webui/routers/retrieval.py",
        "POST",
        local_path,
        f"/api/v1/retrieval{local_path}",
    )
    for local_path in (
        "/query/doc",
        "/query/collection",
        "/process/text",
        "/process/file",
        "/process/files/batch",
        "/process/web",
        "/process/youtube",
    )
)


def _head(root: Path) -> str:
    """Read the checked-out commit without including repository content."""
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _route_line(root: Path, route: AdvisoryRoute) -> int:
    """Resolve the exact decorator line for an advisory endpoint."""
    tree = ast.parse((root / route.file_path).read_text(encoding="utf-8"))
    matches: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.upper()
            path = decorator.args[0].value if decorator.args and isinstance(decorator.args[0], ast.Constant) else None
            if method == route.method and path == route.local_path:
                matches.append(decorator.lineno)
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one {route.method} {route.local_path} route in {route.file_path}; found {len(matches)}."
        )
    return matches[0]


def _cases(revision: Revision, routes: tuple[AdvisoryRoute, ...]) -> list[dict[str, Any]]:
    """Create source-free cases for one pinned repository revision."""
    root = Path(revision.root)
    actual = _head(root)
    if actual != revision.commit:
        raise RuntimeError(f"Revision mismatch for {revision.identifier}: expected {revision.commit}, got {actual}.")
    phase = "vulnerable" if revision.expected_state == "MISSING_AUTHZ" else "fixed"
    return [
        {
            "case_id": f"{revision.identifier}:{route.advisory_id}:{route.method}:{route.public_path}",
            "repository_identifier": revision.identifier,
            "repository_root": revision.root,
            "file_path": route.file_path,
            "route_line": _route_line(root, route),
            "expected_state": revision.expected_state,
            "split": "held_out",
            "case_type": route.case_type,
            "theme": f"{revision.identifier.split('-')[1]}-{route.advisory_id.lower()}",
            "negative_control_type": "official_patched_revision" if phase == "fixed" else None,
            "reviewer_ids": [],
            "adjudication_status": "UNREVIEWED",
            "ground_truth_source": "official_vendor_github_security_advisory",
            "advisory_id": route.advisory_id,
            "advisory_url": route.advisory_url,
            "commit_sha": revision.commit,
            "cwe": route.cwe,
            "http_method": route.method,
            "route_path": route.public_path,
            "revision_role": phase,
        }
        for route in routes
    ]


def main() -> int:
    """Validate pinned revisions and write the deterministic manifest."""
    cases = [
        *_cases(LANGFLOW_VULNERABLE, LANGFLOW_ROUTES),
        *_cases(LANGFLOW_FIXED, LANGFLOW_ROUTES),
        *_cases(OPEN_WEBUI_VULNERABLE, OPEN_WEBUI_ROUTES),
        *_cases(OPEN_WEBUI_FIXED, OPEN_WEBUI_ROUTES),
    ]
    canonical = json.dumps(cases, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest = {
        "version": "official-fastapi-authz-advisories-v1",
        "dataset_kind": "official_vendor_advisory_natural",
        "held_out_frozen": True,
        "ground_truth_sha256": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "selection": {
            "sources": ["langflow-ai/langflow", "open-webui/open-webui"],
            "positive_source": "official affected revision",
            "negative_source": "official patched or later verified revision",
            "quality_gate_note": "Supplementary external qualification; case families remain separated by case_type.",
        },
        "cases": cases,
    }
    output = Path("benchmarks/LogicAuthz/official-fastapi-authz-advisories-v1.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(cases)} official cases to {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
