"""Bounded, source-free Python repository index for cross-file evidence.

Raw source is read and parsed only while :func:`build_repository_index` is
executing.  The returned index contains identifiers, relative paths and line
numbers, never source text or literal values.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path

from sast_triage.context.framework_registry import (
    FRAMEWORK_REGISTRY_VERSION,
    endpoint_source_type,
    source_type_for_call,
)
from sast_triage.models import FindingType, NormalizedFinding, ScannerType, Severity

MODULE2_CONFIG_ID = f"python-cross-file-evidence-v2-{FRAMEWORK_REGISTRY_VERSION}"
FASTAPI_AUTHZ_CONFIG_ID = "module2-fastapi-missing-function-authz-v2"
_PROJECT_MARKERS = ("pyproject.toml", "setup.cfg", "setup.py")
_SKIPPED_PARTS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"})
_SOURCE_SUFFIXES = (
    "input",
    "request.args.get",
    "request.form.get",
    "request.get_json",
    "request.cookies.get",
    "request.headers.get",
    "request.values.get",
    "request.files.get",
    "os.environ.get",
)
_SINK_SUFFIXES: dict[str, str] = {
    "eval": "code_execution",
    "exec": "code_execution",
    "os.system": "command_execution",
    "subprocess.run": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.Popen": "command_execution",
    "execute": "sql_query",
    "executemany": "sql_query",
    "render_template_string": "html_rendering",
    "mark_safe": "html_rendering",
    "Markup": "html_rendering",
    "xpath": "xpath_query",
    "fromstring": "xml_parsing",
    "parse": "xml_parsing",
    "open": "file_access",
}
_CONTROL_SUFFIXES: dict[str, str] = {
    "escape": "output_encoding",
    "clean": "sanitizer_candidate",
    "quote": "escaping_candidate",
    "validate": "validation_candidate",
    "check": "validation_candidate",
    "verify": "validation_candidate",
}


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _matches(name: str | None, suffixes: tuple[str, ...]) -> str | None:
    if name is None:
        return None
    return next((item for item in suffixes if name == item or name.endswith(f".{item}")), None)


def _source_type(node: ast.AST, parameters: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Classify an argument without retaining its literal or source spelling."""
    if isinstance(node, ast.Name) and node.id in parameters:
        return None, node.id
    if isinstance(node, ast.Subscript):
        name = _qualified_name(node.value)
        if name in {"request.args", "request.form", "request.headers", "request.cookies", "sys.argv"}:
            return "request_or_command_input", None
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            name = _qualified_name(item.func)
            framework_source = source_type_for_call(name)
            if framework_source:
                return framework_source, None
            if _matches(name, _SOURCE_SUFFIXES):
                return "user_controlled_call", None
    return None, None


def _walk_function(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.AST, ...]:
    """Walk one function body without attributing nested scopes to its caller."""
    collected: list[ast.AST] = []
    stack = list(reversed(function.body))
    while stack:
        node = stack.pop()
        collected.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return tuple(collected)


_FASTAPI_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route"})
_FASTAPI_DEPENDENCY_CALLS = frozenset({"depends", "security"})
_AUTHN_TOKENS = frozenset({
    "authenticate", "authentication", "authn", "current_user", "current_active_user",
    "get_current_user", "get_current_active_user", "verified_user", "get_verified_user",
    "jwt", "oauth", "session", "token",
})
_AUTHZ_TOKENS = frozenset({
    "authorize", "authorization", "authz", "admin", "role", "permission", "permissions",
    "scope", "scopes", "ownership", "owner", "tenant", "policy", "access", "allowed",
    "user_id", "owner_id", "tenant_id", "is_allowed", "can_", "require_admin", "require_role", "require_permission",
    "check_access", "check_permission", "enforce",
})
_SENSITIVE_ROUTE_TOKENS = frozenset({
    "admin", "internal", "private", "user", "users", "profile", "profiles", "resource",
    "resources", "order", "orders", "account", "accounts", "payment", "payments", "invoice",
    "invoices", "credential", "credentials", "secret", "secrets", "settings", "permission",
    "permissions", "role", "roles",
})
_PUBLIC_ROUTE_TOKENS = frozenset({"health", "healthz", "ready", "readiness", "live", "liveness", "login", "signup", "register", "docs", "openapi", "redoc", "ping", "status", "metrics", "public"})
_SENSITIVE_OPERATION_TOKENS = frozenset({
    "delete", "remove", "update", "modify", "create", "insert", "save", "transfer", "refund",
    "approve", "promote", "grant", "revoke", "reset", "password", "credential", "account",
    "payment", "invoice", "admin", "internal", "private", "secret",
})
_SENSITIVE_DATA_TOKENS = frozenset({
    "address", "balance", "casework", "contact", "credential", "credit", "email",
    "financial", "health", "medical", "owner", "payment", "payroll", "permission",
    "phone", "private", "role", "salary", "scope", "secret", "ssn", "tax", "tenant",
    "token",
})


def _safe_route_path(value: str | None) -> str:
    """Return a bounded route label without arbitrary repository-controlled text."""
    if not value:
        return "<dynamic-route>"
    allowed = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}:-/.[]")
    cleaned = "".join(character if character in allowed else "?" for character in value.strip())
    if not cleaned:
        return "<dynamic-route>"
    safe_segments: list[str] = []
    known = _SENSITIVE_ROUTE_TOKENS | _PUBLIC_ROUTE_TOKENS
    for segment in cleaned.split("/"):
        if not segment:
            continue
        if segment.startswith("{") and segment.endswith("}"):
            parameter = segment[1:-1].lower()
            safe_segments.append(
                "{" + parameter[:32] + "}"
                if parameter.replace("_", "").isalnum()
                else "{param}"
            )
            continue
        segment_tokens = set(segment.lower().replace("-", "_").split("_"))
        if segment.lower() in known or segment_tokens & known:
            safe_segments.append(segment[:64])
        else:
            safe_segments.append("<segment>")
    return "/" + "/".join(safe_segments) if safe_segments else "<dynamic-route>"


def _constant_string(node: ast.AST | None) -> str | None:
    """Read one short literal string while keeping it local to analysis."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _name_leaf(name: str | None) -> str:
    """Return a normalized identifier leaf for analyst-maintained token checks."""
    return (name or "").rsplit(".", 1)[-1].lower()


def _dependency_name(node: ast.AST) -> str | None:
    """Extract a dependency callable name without retaining arguments or literals."""
    if not isinstance(node, ast.Call) or _name_leaf(_qualified_name(node.func)) not in _FASTAPI_DEPENDENCY_CALLS:
        return None
    if node.args:
        return _qualified_name(node.args[0])
    return None


def _dependency_names(node: ast.AST | None) -> tuple[str, ...]:
    """Extract dependency callables from a Depends/Security expression or list."""
    if node is None:
        return ()
    values: list[str] = []
    candidates = (node, *ast.walk(node))
    for candidate in candidates:
        if (
            isinstance(candidate, ast.Call)
            and _name_leaf(_qualified_name(candidate.func)) in _FASTAPI_DEPENDENCY_CALLS
            and (not candidate.args or _qualified_name(candidate.args[0]) is None)
        ):
            values.append("<dynamic-dependency>")
            continue
        name = _dependency_name(candidate)
        if name:
            values.append(name)
    return tuple(dict.fromkeys(values))


def _dependency_from_default(node: ast.AST | None) -> tuple[str, ...]:
    """Return dependencies declared in a function parameter default."""
    return _dependency_names(node)


def _classify_control(name: str | None) -> tuple[str | None, str | None]:
    """Classify one maintained authentication/authorization identifier."""
    lowered = (name or "").lower()
    leaf = _name_leaf(name)
    if not lowered:
        return None, None
    authz_specific_tokens = _AUTHZ_TOKENS - {"access"}
    if any(token in lowered or token in leaf for token in authz_specific_tokens):
        return "authorization", name
    if "access" in lowered and "token" not in lowered:
        return "authorization", name
    if any(token in lowered or token in leaf for token in _AUTHN_TOKENS):
        return "authentication", name
    return None, None


def _iter_call_names(node: ast.AST) -> tuple[str, ...]:
    """Project call and attribute names from a function AST without literals."""
    names: list[str] = []
    for item in _walk_function(node) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ast.walk(node):
        if isinstance(item, ast.Call):
            name = _qualified_name(item.func)
            if name:
                names.append(name)
        elif isinstance(item, ast.Attribute) and item.attr.lower() in {"role", "roles", "permission", "permissions", "scope", "scopes", "tenant_id", "owner_id", "user_id", "is_admin"}:
            name = _qualified_name(item)
            if name:
                names.append(name)
    return tuple(dict.fromkeys(names))


def _iter_control_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Project only calls and attributes used in enforcement expressions."""
    names: list[str] = []
    for item in _walk_function(node):
        if isinstance(item, ast.Call):
            name = _qualified_name(item.func)
            if name:
                names.append(name)
        if not isinstance(item, (ast.If, ast.Assert, ast.Compare)):
            continue
        expression = item.test if isinstance(item, (ast.If, ast.Assert)) else item
        for candidate in ast.walk(expression):
            if not isinstance(candidate, ast.Attribute):
                continue
            if candidate.attr.lower() not in {
                "role", "roles", "permission", "permissions", "scope", "scopes",
                "tenant_id", "owner_id", "user_id", "is_admin",
            }:
                continue
            name = _qualified_name(candidate)
            if name:
                names.append(name)
    return tuple(dict.fromkeys(names))


def _extract_routes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[tuple[tuple[str, ...], str | None, int, tuple[str, ...]], ...]:
    """Extract every FastAPI route decorator attached to one handler."""
    routes: list[tuple[tuple[str, ...], str | None, int, tuple[str, ...]]] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        decorator_name = _qualified_name(decorator.func)
        method_name = _name_leaf(decorator_name)
        if method_name not in _FASTAPI_ROUTE_METHODS:
            continue
        path = _constant_string(decorator.args[0]) if decorator.args else None
        if method_name == "api_route":
            methods: list[str] = []
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                    for item in keyword.value.elts:
                        literal = _constant_string(item)
                        if literal:
                            methods.append(literal.upper()[:16])
            methods = methods or ["GET"]
        else:
            methods = [method_name.upper()]
        dependencies: list[str] = []
        for keyword in decorator.keywords:
            if keyword.arg == "dependencies":
                dependencies.extend(_dependency_names(keyword.value))
        for argument in (*node.args.defaults, *node.args.kw_defaults):
            dependencies.extend(_dependency_from_default(argument))
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            dependencies.extend(_dependency_names(argument.annotation))
        routes.append(
            (tuple(dict.fromkeys(methods)), path, decorator.lineno, tuple(dict.fromkeys(dependencies)))
        )
    return tuple(routes)


def _literal_tokens(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Return bounded identifier-like tokens from local string literals."""
    tokens: set[str] = set()
    for item in _walk_function(node):
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            continue
        normalized = "".join(character.lower() if character.isalnum() else " " for character in item.value)
        tokens.update(part for part in normalized.split() if 2 <= len(part) <= 32)
    return frozenset(tokens)


def _route_sensitivity(
    raw_route_path: str | None,
    methods: tuple[str, ...],
    handler: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    """Return deterministic reasons why a route needs authorization analysis."""
    lowered_path = (raw_route_path or "").lower()
    path_tokens = {part for part in lowered_path.replace("{", "/").replace("}", "/").replace("-", "_").split("/") if part}
    handler_tokens = set(handler.lower().replace(".", "_").split("_"))
    reasons: list[str] = []
    if any(method in {"POST", "PUT", "PATCH", "DELETE"} for method in methods):
        reasons.append("mutating_method")
    if "{" in lowered_path and "}" in lowered_path:
        reasons.append("resource_identifier")
    if path_tokens & _SENSITIVE_ROUTE_TOKENS or handler_tokens & _SENSITIVE_ROUTE_TOKENS:
        reasons.append("sensitive_route")
    operation_names = {_name_leaf(name) for name in _iter_call_names(node)}
    if operation_names & _SENSITIVE_OPERATION_TOKENS:
        reasons.append("sensitive_operation")
    if _literal_tokens(node) & _SENSITIVE_DATA_TOKENS:
        reasons.append("sensitive_response_or_branch")
    if path_tokens & _PUBLIC_ROUTE_TOKENS:
        return ()
    if not reasons and all(method == "GET" for method in methods):
        return ()
    return tuple(dict.fromkeys(reasons))


def _build_fastapi_authorization_endpoints(
    parsed_files: list[_ParsedFile],
    functions: tuple[FunctionSymbol, ...],
    function_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    *,
    repository_identifier: str,
    skipped_files: int,
) -> tuple[FastAPIAuthorizationEndpoint, ...]:
    """Build bounded FastAPI route authorization facts from already parsed files."""
    function_by_simple: dict[str, tuple[str, ...]] = {}
    for function in functions:
        function_by_simple.setdefault(function.simple_name, ())
        function_by_simple[function.simple_name] = (*function_by_simple[function.simple_name], function.qualified_name)

    controls_by_function: dict[str, tuple[tuple[str, str], ...]] = {}
    for _ in range(max(1, len(functions))):
        changed = False
        for function in functions:
            controls: list[tuple[str, str]] = []
            for name in _iter_control_names(function_nodes[function.qualified_name]):
                control_type, symbol = _classify_control(name)
                if control_type and symbol:
                    controls.append((control_type, symbol))
                for candidate in function_by_simple.get(_name_leaf(name), ()):
                    controls.extend(controls_by_function.get(candidate, ()))
            projected = tuple(dict.fromkeys(controls))
            if controls_by_function.get(function.qualified_name) != projected:
                controls_by_function[function.qualified_name] = projected
                changed = True
        if not changed:
            break

    route_objects: dict[tuple[str, str], tuple[str, ...]] = {}
    include_dependencies: dict[tuple[str, str], tuple[str, ...]] = {}
    global_route_dependencies: dict[str, tuple[str, ...]] = {}
    global_include_dependencies: dict[str, tuple[str, ...]] = {}
    route_prefixes: dict[tuple[str, str], str | None] = {}
    include_prefixes: dict[tuple[str, str], str | None] = {}
    global_route_prefixes: dict[str, str | None] = {}
    global_include_prefixes: dict[str, str | None] = {}
    dynamic_auth_boundary: dict[str, bool] = {}
    for parsed in parsed_files:
        for statement in parsed.tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if isinstance(value, ast.Call):
                    constructor = _name_leaf(_qualified_name(value.func))
                    if constructor in {"fastapi", "apirouter"}:
                        dependencies: list[str] = []
                        for keyword in value.keywords:
                            if keyword.arg == "dependencies":
                                dependencies.extend(_dependency_names(keyword.value))
                        targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
                        for target in targets:
                            if isinstance(target, ast.Name):
                                projected = tuple(dict.fromkeys(dependencies))
                                route_objects[(parsed.path, target.id)] = projected
                                previous = global_route_dependencies.get(target.id)
                                if previous is None:
                                    global_route_dependencies[target.id] = projected
                                elif previous != projected:
                                    global_route_dependencies[target.id] = ("<dynamic-router-dependencies>",)
                                prefix = next(
                                    (_constant_string(keyword.value) for keyword in value.keywords if keyword.arg == "prefix"),
                                    "",
                                )
                                route_prefixes[(parsed.path, target.id)] = prefix
                                previous_prefix = global_route_prefixes.get(target.id)
                                if target.id not in global_route_prefixes:
                                    global_route_prefixes[target.id] = prefix
                                elif previous_prefix != prefix:
                                    global_route_prefixes[target.id] = None
            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _qualified_name(node.func)
                if call_name and _name_leaf(call_name) in {"add_middleware", "middleware"}:
                    dynamic_auth_boundary[parsed.path] = True
                if not call_name or _name_leaf(call_name) != "include_router" or not node.args:
                    continue
                router_name = _qualified_name(node.args[0])
                if router_name:
                    dependencies: list[str] = []
                    for keyword in node.keywords:
                        if keyword.arg == "dependencies":
                            dependencies.extend(_dependency_names(keyword.value))
                    key = (parsed.path, router_name.rsplit(".", 1)[-1])
                    projected = tuple(dict.fromkeys(dependencies))
                    include_dependencies[key] = projected
                    simple_router_name = router_name.rsplit(".", 1)[-1]
                    include_prefix = next(
                        (_constant_string(keyword.value) for keyword in node.keywords if keyword.arg == "prefix"),
                        "",
                    )
                    include_prefixes[key] = include_prefix
                    previous = global_include_dependencies.get(simple_router_name)
                    if previous is None:
                        global_include_dependencies[simple_router_name] = projected
                    elif previous != projected:
                        global_include_dependencies[simple_router_name] = ("<dynamic-router-dependencies>",)
                    previous_prefix = global_include_prefixes.get(simple_router_name)
                    if simple_router_name not in global_include_prefixes:
                        global_include_prefixes[simple_router_name] = include_prefix
                    elif previous_prefix != include_prefix:
                        global_include_prefixes[simple_router_name] = None

    endpoints: list[FastAPIAuthorizationEndpoint] = []
    for function in functions:
        node = function_nodes[function.qualified_name]
        routes = _extract_routes(node)
        if not routes:
            continue
        for methods, local_route_path, route_line, direct_dependencies in routes:
            decorator_base = None
            for decorator in node.decorator_list:
                if getattr(decorator, "lineno", -1) != route_line or not isinstance(decorator, ast.Call):
                    continue
                raw = _qualified_name(decorator.func)
                decorator_base = raw.rsplit(".", 1)[0] if raw and "." in raw else None
                break
            dependencies = list(direct_dependencies)
            prefix_parts: list[str] = []
            if decorator_base:
                object_name = decorator_base.rsplit(".", 1)[-1]
                dependencies.extend(
                    route_objects.get((function.file_path, object_name), global_route_dependencies.get(object_name, ()))
                )
                dependencies.extend(
                    include_dependencies.get((function.file_path, object_name), global_include_dependencies.get(object_name, ()))
                )
                router_prefix = route_prefixes.get(
                    (function.file_path, object_name), global_route_prefixes.get(object_name, "")
                )
                include_prefix = include_prefixes.get(
                    (function.file_path, object_name), global_include_prefixes.get(object_name, "")
                )
                if include_prefix:
                    prefix_parts.append(include_prefix)
                if router_prefix:
                    prefix_parts.append(router_prefix)
            raw_route_path = "".join(prefix_parts) + (local_route_path or "") if local_route_path is not None else None
            route_path = _safe_route_path(raw_route_path)
            dependencies = list(dict.fromkeys(dependencies))
            authentication: list[str] = []
            authorization: list[str] = []
            unknown_dependency = False
            for dependency in dependencies:
                control_type, symbol = _classify_control(dependency)
                if control_type == "authentication" and symbol:
                    authentication.append(symbol)
                elif control_type == "authorization" and symbol:
                    authorization.append(symbol)
                else:
                    candidates = function_by_simple.get(_name_leaf(dependency), ())
                    if not candidates:
                        unknown_dependency = True
                    for candidate in candidates:
                        for nested_type, nested_symbol in controls_by_function.get(candidate, ()):
                            if nested_type == "authentication":
                                authentication.append(nested_symbol)
                            elif nested_type == "authorization":
                                authorization.append(nested_symbol)
            for control_type, symbol in controls_by_function.get(function.qualified_name, ()):
                if control_type == "authentication":
                    authentication.append(symbol)
                else:
                    authorization.append(symbol)
            sensitivity = _route_sensitivity(raw_route_path, methods, function.qualified_name, node)
            if not sensitivity and authorization:
                sensitivity = ("authorization_control_present",)
            if not sensitivity:
                continue
            dynamic = unknown_dependency or dynamic_auth_boundary.get(function.file_path, False)
            completeness = "PARTIAL" if skipped_files or raw_route_path is None else "COMPLETE"
            if authorization:
                state = "PROTECTED"
            elif dynamic:
                state = "UNKNOWN"
                completeness = "PARTIAL"
            else:
                state = "MISSING_AUTHZ_CANDIDATE"
            endpoints.append(
                FastAPIAuthorizationEndpoint(
                    repository_identifier=repository_identifier,
                    file_path=function.file_path,
                    handler=function.qualified_name,
                    handler_line=function.line,
                    route_line=route_line,
                    methods=methods,
                    route_path=route_path,
                    dependencies=tuple(dependencies),
                    authentication_controls=tuple(dict.fromkeys(authentication)),
                    authorization_controls=tuple(dict.fromkeys(authorization)),
                    sensitivity_reasons=sensitivity,
                    analysis_state=state,
                    completeness=completeness,
                    provenance=("fastapi_route_index", "fastapi_dependency_index"),
                )
            )
    return tuple(endpoints)


def _argument_origin(
    node: ast.AST,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    line: int,
    parameters: tuple[str, ...],
    seen: frozenset[str] = frozenset(),
) -> tuple[str | None, str | None]:
    """Resolve a bounded same-function assignment before recording a call edge."""
    direct = _source_type(node, parameters)
    if direct != (None, None) or not isinstance(node, ast.Name) or node.id in seen:
        return direct
    assignments: list[tuple[int, ast.AST]] = []
    for child in _walk_function(function):
        if not isinstance(child, ast.Assign) or child.lineno >= line:
            continue
        if any(isinstance(target, ast.Name) and target.id == node.id for target in child.targets):
            assignments.append((child.lineno, child.value))
    if not assignments:
        return direct
    _, value = max(assignments, key=lambda item: item[0])
    return _argument_origin(value, function, getattr(value, "lineno", line), parameters, seen | {node.id})


@dataclass(frozen=True, slots=True)
class RepositoryComponent:
    """A safe monorepo component identified by its relative project root."""

    identifier: str
    root: str


@dataclass(frozen=True, slots=True)
class FunctionSymbol:
    """A Python function signature without source or literal values."""

    qualified_name: str
    simple_name: str
    module: str
    file_path: str
    component: str
    line: int
    end_line: int
    parameters: tuple[str, ...]
    entrypoint_source_type: str | None = None


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """A source-free interprocedural summary prepared for Sprint 2/3 queries."""

    function: str
    file_path: str
    component: str
    parameter_to_sinks: tuple[tuple[str, str], ...]
    returned_parameters: tuple[str, ...]
    security_controls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CallSite:
    """A source-free call edge in the repository call graph."""

    caller: str
    callee: str
    file_path: str
    component: str
    line: int
    argument_sources: tuple[str | None, ...]
    argument_parameters: tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class SinkCandidate:
    """A parameterized sensitive sink that can be traced across files."""

    function: str
    file_path: str
    component: str
    line: int
    sink_type: str
    parameter: str


@dataclass(frozen=True, slots=True)
class CrossFileTrace:
    """A bounded cross-file source-to-sink trace."""

    source_file: str
    source_line: int
    source_type: str
    sink_file: str
    sink_line: int
    sink_type: str
    function_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FastAPIAuthorizationEndpoint:
    """Source-free authorization facts for one FastAPI route handler.

    The analyzer deliberately stores names, locations, and bounded
    classifications only.  It never exposes source text or literal values.
    """

    repository_identifier: str
    file_path: str
    handler: str
    handler_line: int
    route_line: int
    methods: tuple[str, ...]
    route_path: str
    dependencies: tuple[str, ...]
    authentication_controls: tuple[str, ...]
    authorization_controls: tuple[str, ...]
    sensitivity_reasons: tuple[str, ...]
    analysis_state: str
    completeness: str
    provenance: tuple[str, ...]

    @property
    def is_candidate(self) -> bool:
        """Return whether the endpoint is a complete missing-authorization candidate."""
        return self.analysis_state == "MISSING_AUTHZ_CANDIDATE"


@dataclass(frozen=True, slots=True)
class RepositoryEvidenceIndex:
    """Immutable structured index shared by sequential Module 1/Module 2 work."""

    repository_identifier: str
    components: tuple[RepositoryComponent, ...]
    functions: tuple[FunctionSymbol, ...]
    summaries: tuple[FunctionSummary, ...]
    calls: tuple[CallSite, ...]
    sinks: tuple[SinkCandidate, ...]
    skipped_files: int = 0
    fastapi_endpoints: tuple[FastAPIAuthorizationEndpoint, ...] = ()

    def component_for(self, file_path: str) -> str:
        """Return the longest owning monorepo component for a relative path."""
        matches = [
            item.identifier
            for item in self.components
            if item.root == "." or file_path == item.root or file_path.startswith(f"{item.root}/")
        ]
        return max(matches, key=len, default=".")

    def function_at(self, file_path: str, line: int) -> FunctionSymbol | None:
        """Return the narrowest function containing a finding line."""
        matches = [item for item in self.functions if item.file_path == file_path and item.line <= line <= item.end_line]
        return min(matches, key=lambda item: item.end_line - item.line) if matches else None

    def summary_for(self, function_name: str) -> FunctionSummary | None:
        """Return the safe summary used by bounded future interprocedural queries."""
        return next((item for item in self.summaries if item.function == function_name), None)

    def trace_for_finding(self, finding: NormalizedFinding, max_depth: int = 5) -> CrossFileTrace | None:
        """Trace an unresolved sink parameter to a source in another file."""
        function = self.function_at(finding.file_path, finding.start_line)
        if function is None:
            return None
        candidates = sorted(
            (item for item in self.sinks if item.function == function.qualified_name),
            key=lambda item: abs(item.line - finding.start_line),
        )
        for sink in candidates:
            trace = self._trace(function.qualified_name, sink.parameter, sink, max_depth, ())
            if trace is not None and trace.source_file != sink.file_path:
                return trace
        return None

    def _trace(
        self,
        function_name: str,
        parameter: str,
        sink: SinkCandidate,
        depth: int,
        visited: tuple[str, ...],
    ) -> CrossFileTrace | None:
        if depth <= 0 or function_name in visited:
            return None
        function = next((item for item in self.functions if item.qualified_name == function_name), None)
        if function is None or parameter not in function.parameters:
            return None
        index = function.parameters.index(parameter)
        for call in self.calls:
            if call.callee != function_name or len(call.argument_sources) <= index:
                continue
            source_type = call.argument_sources[index]
            if source_type:
                return CrossFileTrace(
                    source_file=call.file_path,
                    source_line=call.line,
                    source_type=source_type,
                    sink_file=sink.file_path,
                    sink_line=sink.line,
                    sink_type=sink.sink_type,
                    function_path=(*visited, call.caller, function_name),
                )
            caller_parameter = call.argument_parameters[index]
            if caller_parameter:
                found = self._trace(
                    call.caller,
                    caller_parameter,
                    sink,
                    depth - 1,
                    (*visited, function_name),
                )
                if found is not None:
                    return found
        if function.entrypoint_source_type and parameter in function.parameters:
            return CrossFileTrace(
                source_file=function.file_path,
                source_line=function.line,
                source_type=function.entrypoint_source_type,
                sink_file=sink.file_path,
                sink_line=sink.line,
                sink_type=sink.sink_type,
                function_path=(*visited, function_name),
            )
        return None

    def discover_findings(
        self,
        existing: tuple[NormalizedFinding, ...] = (),
        max_depth: int = 5,
    ) -> tuple[NormalizedFinding, ...]:
        """Discover cross-file candidates not already reported at the sink location."""
        occupied = {(item.file_path, item.start_line) for item in existing}
        findings: list[NormalizedFinding] = []
        for sink in self.sinks:
            if (sink.file_path, sink.line) in occupied:
                continue
            trace = self._trace(sink.function, sink.parameter, sink, max_depth, ())
            if trace is None or trace.source_file == trace.sink_file:
                continue
            digest = hashlib.sha256(
                f"MODULE2:{sink.sink_type}:{sink.file_path}:{sink.line}".encode()
            ).hexdigest()
            findings.append(
                NormalizedFinding(
                    finding_instance_id=digest,
                    scanner=ScannerType.MODULE2,
                    finding_type=FindingType.SAST,
                    rule_id=f"module2.python.cross-file.{sink.sink_type}",
                    rule_name="Bounded cross-file source-to-sink path",
                    file_path=sink.file_path,
                    start_line=sink.line,
                    end_line=sink.line,
                    severity=Severity.HIGH,
                    message="A bounded cross-file source-to-sink path requires security triage.",
                    metadata={
                        "analysis_scope": "cross_file",
                        "component": sink.component,
                        "sink_type": sink.sink_type,
                    },
                )
            )
            occupied.add((sink.file_path, sink.line))
        return tuple(findings)

    def analyze_fastapi_authorization(self) -> tuple[FastAPIAuthorizationEndpoint, ...]:
        """Return all bounded FastAPI authorization facts, including protected/unknown routes."""
        return self.fastapi_endpoints

    def discover_fastapi_authorization_findings(
        self,
        existing: tuple[NormalizedFinding, ...] = (),
    ) -> tuple[NormalizedFinding, ...]:
        """Discover complete missing function-level authorization candidates."""
        occupied = {(item.file_path, item.start_line) for item in existing}
        findings: list[NormalizedFinding] = []
        for endpoint in self.fastapi_endpoints:
            location = (endpoint.file_path, endpoint.route_line)
            if not endpoint.is_candidate or endpoint.completeness != "COMPLETE" or location in occupied:
                continue
            digest = hashlib.sha256(
                f"FASTAPI_AUTHZ:{endpoint.file_path}:{endpoint.route_line}:{','.join(endpoint.methods)}:{endpoint.route_path}".encode()
            ).hexdigest()
            severity = Severity.HIGH if any(
                reason in endpoint.sensitivity_reasons
                for reason in ("mutating_method", "sensitive_route", "sensitive_operation")
            ) else Severity.MEDIUM
            findings.append(
                NormalizedFinding(
                    finding_instance_id=digest,
                    scanner=ScannerType.MODULE2,
                    finding_type=FindingType.SAST,
                    rule_id="module2.fastapi.missing-function-authz",
                    rule_name="FastAPI missing function-level authorization",
                    file_path=endpoint.file_path,
                    start_line=endpoint.route_line,
                    end_line=endpoint.handler_line,
                    severity=severity,
                    message="A sensitive FastAPI endpoint has no verifiable function-level authorization control.",
                    metadata={
                        "analysis_scope": "fastapi_authorization",
                        "detector_version": "sprint2-v2",
                        "framework": "fastapi",
                        "cwe": "CWE-862",
                        "endpoint": {
                            "handler": endpoint.handler,
                            "methods": list(endpoint.methods),
                            "route_path": endpoint.route_path,
                            "route_line": endpoint.route_line,
                        },
                        "sensitivity_reasons": list(endpoint.sensitivity_reasons),
                        "authentication_controls": list(endpoint.authentication_controls),
                        "authorization_controls": list(endpoint.authorization_controls),
                        "dependencies": list(endpoint.dependencies),
                        "context_completeness": endpoint.completeness,
                        "provenance": list(endpoint.provenance),
                    },
                )
            )
            occupied.add(location)
        return tuple(findings)


@dataclass(frozen=True, slots=True)
class _ParsedFile:
    path: str
    component: str
    module: str
    tree: ast.Module
    aliases: dict[str, str]


def _module_name(path: str, component_root: str) -> str:
    relative = Path(path) if component_root == "." else Path(path).relative_to(component_root)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _aliases(tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return result


def _resolve_callee(raw: str, parsed: _ParsedFile, functions: tuple[FunctionSymbol, ...]) -> str:
    first, *rest = raw.split(".")
    if first in parsed.aliases:
        candidate = ".".join((parsed.aliases[first], *rest))
        exact = [item.qualified_name for item in functions if item.qualified_name == candidate]
        if len(exact) == 1:
            return exact[0]
    local = f"{parsed.module}.{raw}" if parsed.module else raw
    if any(item.qualified_name == local for item in functions):
        return local
    simple = [
        item.qualified_name
        for item in functions
        if item.simple_name == raw.split(".")[-1] and item.component == parsed.component
    ]
    return simple[0] if len(simple) == 1 else raw


def build_repository_index(
    repository_root: Path,
    repository_identifier: str,
    *,
    max_python_files: int = 20_000,
    max_file_size_bytes: int = 1_048_576,
    include_file_paths: frozenset[str] | None = None,
) -> RepositoryEvidenceIndex:
    """Build a bounded monorepo-aware index without retaining raw source text.

    ``include_file_paths`` is intended for pinned endpoint-level benchmark
    manifests. Production analysis leaves it unset and indexes the repository.
    """
    root = repository_root.resolve()
    marker_roots = {"."}
    if include_file_paths is None:
        for marker in _PROJECT_MARKERS:
            for path in root.rglob(marker):
                if not _SKIPPED_PARTS.isdisjoint(path.relative_to(root).parts):
                    continue
                marker_roots.add(path.parent.relative_to(root).as_posix() or ".")
    components = tuple(
        RepositoryComponent(identifier=item, root=item)
        for item in sorted(marker_roots, key=lambda value: (value.count("/"), value))
    )

    parsed_files: list[_ParsedFile] = []
    skipped = 0
    candidate_paths = (
        sorted(root / Path(value) for value in include_file_paths)
        if include_file_paths is not None
        else sorted(root.rglob("*.py"))
    )
    for number, path in enumerate(candidate_paths):
        if number >= max_python_files:
            skipped += 1
            continue
        relative = path.relative_to(root).as_posix()
        if not _SKIPPED_PARTS.isdisjoint(Path(relative).parts) or path.is_symlink():
            continue
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root) or resolved.stat().st_size > max_file_size_bytes:
                skipped += 1
                continue
            text = resolved.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, UnicodeDecodeError, SyntaxError):
            skipped += 1
            continue
        owner = max(
            (
                item.identifier
                for item in components
                if item.root == "." or relative.startswith(f"{item.root}/")
            ),
            key=len,
        )
        parsed_files.append(
            _ParsedFile(relative, owner, _module_name(relative, owner), tree, _aliases(tree))
        )

    functions: list[FunctionSymbol] = []
    function_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for parsed in parsed_files:
        for node in ast.walk(parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            qualified = f"{parsed.module}.{node.name}" if parsed.module else node.name
            parameters = tuple(
                item.arg
                for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            )
            symbol = FunctionSymbol(
                qualified_name=qualified,
                simple_name=node.name,
                module=parsed.module,
                file_path=parsed.path,
                component=parsed.component,
                line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                parameters=parameters,
                entrypoint_source_type=endpoint_source_type(node),
            )
            functions.append(symbol)
            function_nodes[qualified] = node
    frozen_functions = tuple(functions)

    calls: list[CallSite] = []
    sinks: list[SinkCandidate] = []
    summaries: list[FunctionSummary] = []
    parsed_by_path = {item.path: item for item in parsed_files}
    for function in frozen_functions:
        node = function_nodes[function.qualified_name]
        parsed = parsed_by_path[function.file_path]
        parameter_to_sinks: list[tuple[str, str]] = []
        returned_parameters: list[str] = []
        controls: list[str] = []
        for child in _walk_function(node):
            if (
                isinstance(child, ast.Return)
                and isinstance(child.value, ast.Name)
                and child.value.id in function.parameters
            ):
                returned_parameters.append(child.value.id)
            if not isinstance(child, ast.Call):
                continue
            raw_callee = _qualified_name(child.func)
            if raw_callee is None:
                continue
            sources: list[str | None] = []
            parameters: list[str | None] = []
            for argument in child.args:
                source, parameter = _argument_origin(
                    argument,
                    node,
                    child.lineno,
                    function.parameters,
                )
                sources.append(source)
                parameters.append(parameter)
            calls.append(
                CallSite(
                    caller=function.qualified_name,
                    callee=_resolve_callee(raw_callee, parsed, frozen_functions),
                    file_path=function.file_path,
                    component=function.component,
                    line=child.lineno,
                    argument_sources=tuple(sources),
                    argument_parameters=tuple(parameters),
                )
            )
            sink_match = next(
                (
                    sink_type
                    for suffix, sink_type in _SINK_SUFFIXES.items()
                    if raw_callee == suffix or raw_callee.endswith(f".{suffix}")
                ),
                None,
            )
            if sink_match and child.args:
                _, parameter = _source_type(child.args[0], function.parameters)
                if parameter:
                    parameter_to_sinks.append((parameter, sink_match))
                    sinks.append(
                        SinkCandidate(
                            function=function.qualified_name,
                            file_path=function.file_path,
                            component=function.component,
                            line=child.lineno,
                            sink_type=sink_match,
                            parameter=parameter,
                        )
                    )
            control = next(
                (
                    control_type
                    for suffix, control_type in _CONTROL_SUFFIXES.items()
                    if raw_callee == suffix or raw_callee.endswith(f".{suffix}")
                ),
                None,
            )
            if control:
                controls.append(control)
        summaries.append(
            FunctionSummary(
                function=function.qualified_name,
                file_path=function.file_path,
                component=function.component,
                parameter_to_sinks=tuple(dict.fromkeys(parameter_to_sinks)),
                returned_parameters=tuple(dict.fromkeys(returned_parameters)),
                security_controls=tuple(dict.fromkeys(controls)),
            )
        )
    fastapi_endpoints = _build_fastapi_authorization_endpoints(
        parsed_files,
        frozen_functions,
        function_nodes,
        repository_identifier=repository_identifier,
        skipped_files=skipped,
    )
    return RepositoryEvidenceIndex(
        repository_identifier=repository_identifier,
        components=components,
        functions=frozen_functions,
        summaries=tuple(summaries),
        calls=tuple(calls),
        sinks=tuple(sinks),
        skipped_files=skipped,
        fastapi_endpoints=fastapi_endpoints,
    )
