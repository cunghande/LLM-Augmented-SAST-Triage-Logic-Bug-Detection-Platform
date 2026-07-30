"""
Lightweight Security Context Graph Module
=========================================
Extracts lightweight security context traces (Entrypoint -> Guard -> Sink) from AST.

LIMITATIONS DISCLAIMER:
This module extracts an AST-derived lightweight security context graph.
It is NOT a full Control Flow Graph (CFG) or full Code Property Graph (CPG), as it lacks
complete interprocedural data flow analysis, full symbol resolution, and alias tracking.
Absence of a guard generates a LOGIC_BUG_CANDIDATE for review, not proof of vulnerability.
"""

import ast
import re
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field
from src.core.schema import GuardCategory, LightweightSecurityContextGraph


class CodeNode(BaseModel):
    node_type: str  # ENTRYPOINT, GUARD, SINK
    name: str
    file_path: str
    line_number: int
    code_snippet: str


class TracePath(BaseModel):
    entrypoint: CodeNode
    guards: List[CodeNode] = Field(default_factory=list)
    guard_categories: List[GuardCategory] = Field(default_factory=list)
    sensitive_sink: CodeNode
    has_auth_guard: bool = False
    potential_vulnerability: Optional[str] = None


GUARD_PATTERNS = [
    (r"verifyToken|authenticate|jwt|authMiddleware|isLoggedIn|login_required", GuardCategory.AUTHENTICATION),
    (r"requireAdmin|admin_required|hasRole|is_admin|checkRole", GuardCategory.ROLE),
    (r"checkOwnership|isOwner|matchUserId|user_id\s*==|owner_id", GuardCategory.OWNERSHIP),
    (r"tenant_id|checkTenant|multi_tenant", GuardCategory.TENANT),
    (r"verifyState|canTransition|checkStatus", GuardCategory.STATE_TRANSITION),
    (r"validate|sanitize|checkInput|assert", GuardCategory.VALIDATION),
    (r"transaction|with_transaction|atomic", GuardCategory.TRANSACTION),
]

SINK_PATTERNS = [
    r"(?:Order|User|Coupon|Product|Cart)\.(?:findById|findOne|update|delete|destroy|create)",
    r"db\.query|connection\.query|cursor\.execute|session\.execute",
    r"fs\.readFile|fs\.writeFile|upload\.single|multer",
    r"open\(|pickle\.load|torch\.load"
]

ROUTE_PATTERNS_JS = [
    r"router\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)]+)\)",
    r"app\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)]+)\)"
]

ROUTE_PATTERNS_PY = [
    r"@app\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
    r"@router\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]"
]


def classify_guard(text: str) -> Optional[GuardCategory]:
    """Classify code snippet into explicit GuardCategory."""
    for pattern, category in GUARD_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return category
    return None


def is_guard(text: str) -> bool:
    """Check if text contains any security guard."""
    return classify_guard(text) is not None


def is_sink(text: str) -> bool:
    """Check if code text calls a sensitive sink."""
    for p in SINK_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def parse_js_routes(file_path: Path) -> List[TracePath]:
    """Parse JS/TS route definitions into lightweight security context traces."""
    traces: List[TracePath] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            for pattern in ROUTE_PATTERNS_JS:
                match = re.search(pattern, line)
                if match:
                    method = match.group(1).upper()
                    path_str = match.group(2)
                    args_str = match.group(3) if len(match.groups()) >= 3 else ""

                    entry_node = CodeNode(
                        node_type="ENTRYPOINT",
                        name=f"{method} {path_str}",
                        file_path=str(file_path),
                        line_number=idx + 1,
                        code_snippet=line.strip()
                    )

                    cat = classify_guard(args_str) or classify_guard(line)
                    guards_list = []
                    guard_cats = []
                    has_guard = cat is not None
                    if has_guard and cat:
                        guards_list.append(CodeNode(
                            node_type="GUARD",
                            name=cat.value,
                            file_path=str(file_path),
                            line_number=idx + 1,
                            code_snippet=args_str.strip()
                        ))
                        guard_cats.append(cat)

                    search_end = min(len(lines), idx + 35)
                    for sink_idx in range(idx + 1, search_end):
                        s_line = lines[sink_idx]
                        if is_sink(s_line):
                            sink_node = CodeNode(
                                node_type="SINK",
                                name="SensitiveDataOperation",
                                file_path=str(file_path),
                                line_number=sink_idx + 1,
                                code_snippet=s_line.strip()
                            )

                            vun_type = None
                            if ":id" in path_str and not has_guard:
                                vun_type = "LOGIC_BUG_CANDIDATE: IDOR / Missing Ownership Guard"
                            elif "update" in s_line.lower() or "create" in s_line.lower():
                                vun_type = "LOGIC_BUG_CANDIDATE: Mass Assignment"

                            traces.append(TracePath(
                                entrypoint=entry_node,
                                guards=guards_list,
                                guard_categories=guard_cats,
                                sensitive_sink=sink_node,
                                has_auth_guard=has_guard,
                                potential_vulnerability=vun_type
                            ))
    except Exception:
        pass
    return traces


def parse_py_routes(file_path: Path) -> List[TracePath]:
    """Parse Python FastAPI route definitions into lightweight security context traces."""
    traces: List[TracePath] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content)
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                is_route = False
                route_name = node.name
                guard_cats = []
                guards_list = []

                for dec in node.decorator_list:
                    dec_str = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if "app." in dec_str or "router." in dec_str:
                        is_route = True
                        route_name = f"API {node.name} ({dec_str})"
                    cat = classify_guard(dec_str)
                    if cat:
                        guard_cats.append(cat)
                        guards_list.append(CodeNode(
                            node_type="GUARD",
                            name=cat.value,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            code_snippet=dec_str
                        ))

                if is_route:
                    entry_node = CodeNode(
                        node_type="ENTRYPOINT",
                        name=route_name,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    )

                    has_guard = len(guard_cats) > 0

                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            call_str = ast.unparse(child) if hasattr(ast, "unparse") else ""
                            if is_sink(call_str):
                                sink_line = getattr(child, "lineno", node.lineno)
                                sink_node = CodeNode(
                                    node_type="SINK",
                                    name="SensitiveOperation",
                                    file_path=str(file_path),
                                    line_number=sink_line,
                                    code_snippet=call_str
                                )
                                traces.append(TracePath(
                                    entrypoint=entry_node,
                                    guards=guards_list,
                                    guard_categories=guard_cats,
                                    sensitive_sink=sink_node,
                                    has_auth_guard=has_guard,
                                    potential_vulnerability="LOGIC_BUG_CANDIDATE: Missing Guard" if not has_guard else None
                                ))
    except Exception:
        pass
    return traces


def extract_code_graph(repo_dir: Path) -> List[TracePath]:
    """Extract lightweight security context traces across repository."""
    traces: List[TracePath] = []
    js_files = list(repo_dir.glob("**/*.js")) + list(repo_dir.glob("**/*.ts"))
    for jf in js_files:
        if "node_modules" not in str(jf):
            traces.extend(parse_js_routes(jf))

    py_files = list(repo_dir.glob("**/*.py"))
    for pf in py_files:
        if "venv" not in str(pf) and ".venv" not in str(pf):
            traces.extend(parse_py_routes(pf))

    return traces
