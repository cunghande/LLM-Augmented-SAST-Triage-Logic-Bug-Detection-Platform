"""Conservative AST patterns for focused IDOR and business-rule bugs.

The analyzer receives an already parsed AST and returns identifiers, relative
paths, line numbers and classifications only. It never retains source text or
literal values.
"""

from __future__ import annotations

import ast

from sast_triage.logic.models import LogicBugClass, LogicCandidate
from sast_triage.models import Severity

_REQUEST_ROOTS = {"request", "req"}
_ROUTE_DECORATOR_SUFFIXES = (
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_view",
)
_ACTOR_NAMES = {
    "current_user",
    "request.user",
    "req.user",
    "user",
    "actor",
    "principal",
}
_NON_INPUT_PARAMETERS = {
    "self",
    "cls",
    "request",
    "req",
    "current_user",
    "user",
    "db",
    "info",
    "session",
}
_ID_TOKENS = ("id", "uuid", "slug", "key", "reference", "token")
_LOOKUP_CALLS = (
    "execute",
    "get",
    "get_or_404",
    "get_object_or_404",
    "filter",
    "filter_by",
    "find",
    "find_one",
    "first",
    "one",
)
_MUTATION_CALLS = (
    "add",
    "bulk_create",
    "commit",
    "create",
    "delete",
    "insert",
    "save",
    "update",
)
_AUTHZ_CALL_TOKENS = (
    "allow",
    "assert_allowed",
    "authorize",
    "can_access",
    "can_edit",
    "can_manage",
    "can_view",
    "check_access",
    "check_owner",
    "check_permission",
    "enforce_scope",
    "has_permission",
    "is_owner",
    "ownership",
    "owning",
    "permission",
    "require_role",
    "tenant_scope",
)
_DOMAIN_VALUE_TOKENS = (
    "amount",
    "balance",
    "credit",
    "discount",
    "delta",
    "inventory",
    "limit",
    "price",
    "quantity",
    "quota",
    "stock",
    "total",
)
_PAGINATION_TOKENS = ("limit", "offset", "page", "page_size", "per_page")
_COLLECTION_FUNCTION_TOKENS = (
    "admin",
    "gallery",
    "images",
    "list",
    "records",
    "users",
)
_CLIENT_PRICE_TOKENS = ("discount", "price", "subtotal", "total", "unit_price")

_CLASS_FACTS: dict[LogicBugClass, tuple[str, Severity, str]] = {
    LogicBugClass.MISSING_AUTHZ_IDOR: (
        "CWE-639",
        Severity.HIGH,
        "Bind the requested object to the authenticated subject or tenant before reading or mutating it.",
    ),
    LogicBugClass.BUSINESS_RULE_BYPASS: (
        "CWE-840",
        Severity.HIGH,
        "Recompute trusted values on the server and enforce domain and resource bounds before the operation.",
    ),
}


def _qualified_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_endpoint(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    decorators = [
        _qualified_name(item.func) if isinstance(item, ast.Call) else _qualified_name(item)
        for item in function.decorator_list
    ]
    if any(
        name is not None
        and any(
            name == suffix or name.endswith(f".{suffix}")
            for suffix in _ROUTE_DECORATOR_SUFFIXES
        )
        for name in decorators
    ):
        return True
    parameters = (*function.args.posonlyargs, *function.args.args)
    if function.name == "mutate" or function.name.startswith("resolve_"):
        return True
    if (
        parameters
        and parameters[0].arg in {"self", "cls"}
        and function.name.lower() in {"get", "post", "put", "patch", "delete"}
    ):
        return True
    return bool(parameters and parameters[0].arg in _REQUEST_ROOTS)


def _walk_function(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.AST, ...]:
    """Walk a function without attributing nested scopes to the outer function."""
    nodes: list[ast.AST] = []
    stack = list(reversed(function.body))
    while stack:
        node = stack.pop()
        nodes.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(nodes)


def _node_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    names: set[str] = set()
    for child in ast.walk(node):
        qualified = _qualified_name(child)
        if qualified:
            names.add(qualified.lower())
    return names


def _last_name(name: str | None) -> str:
    return (name or "").rsplit(".", 1)[-1].lower()


def _matches_last(name: str | None, suffixes: tuple[str, ...]) -> bool:
    last = _last_name(name)
    return any(last == suffix or last.endswith(f"_{suffix}") for suffix in suffixes)


def _is_lookup_call(name: str | None) -> bool:
    last = _last_name(name)
    return _matches_last(name, _LOOKUP_CALLS) or last.startswith(
        ("fetch_", "find_", "get_", "load_", "read_")
    )


def _is_authz_call(name: str | None) -> bool:
    lowered = (name or "").lower()
    last = _last_name(lowered)
    if any(token in lowered for token in _AUTHZ_CALL_TOKENS):
        return True
    semantic_prefix = last.startswith(("assert_", "authorize_", "can_", "ensure_", "require_"))
    semantic_target = any(
        token in last
        for token in (
            "access",
            "allowed",
            "download",
            "manage",
            "owner",
            "permission",
            "scope",
            "tenant",
            "view",
            "visible",
        )
    )
    verified_authz_lookup = (
        lowered.startswith(("authz.", "authorization.", "permissions."))
        and last.startswith(("fetch_", "get_", "load_", "read_"))
        and any(
            token in last
            for token in ("for_access", "for_manage", "for_update", "for_view")
        )
    )
    scoped_helper = last.endswith(("_access", "_allowed", "_permission"))
    return (
        semantic_prefix and semantic_target
        or "visible_to" in last
        or verified_authz_lookup
        or scoped_helper
    )


def _is_identifier_name(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(("id", "ref")):
        return True
    return any(
        lowered == token
        or lowered.endswith(f"_{token}")
        or lowered.startswith(f"{token}_")
        for token in _ID_TOKENS
    )


def _request_source_kind(node: ast.AST | None) -> str | None:
    for name in _node_names(node):
        if name in _REQUEST_ROOTS or name.startswith(("request.", "req.")):
            if any(token in name for token in ("json", "body", "post", "form", "data")):
                return "http_request_body"
            return "http_request_parameter"
    return None


def _assignment_sources(
    nodes: tuple[ast.AST, ...],
    route_parameters: set[str],
) -> dict[str, str]:
    sources = {name: "http_route_parameter" for name in route_parameters}
    for node in sorted(nodes, key=lambda item: getattr(item, "lineno", 0)):
        value: ast.AST | None = None
        targets: tuple[ast.AST, ...] = ()
        if isinstance(node, ast.Assign):
            value = node.value
            targets = tuple(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = (node.target,)
        if value is None:
            continue
        source_kind = _request_source_kind(value)
        referenced = _node_names(value)
        if source_kind is None:
            source_kind = next(
                (
                    kind
                    for variable, kind in sources.items()
                    if variable.lower() in referenced
                ),
                None,
            )
        if source_kind is None:
            continue
        for target in targets:
            if isinstance(target, (ast.Name, ast.Attribute)):
                name = _qualified_name(target)
                if name:
                    sources[name] = source_kind
    for node in sorted(nodes, key=lambda item: getattr(item, "lineno", 0)):
        if not isinstance(node, (ast.For, ast.AsyncFor)):
            continue
        source_kind = _source_for(node.iter, sources)
        if source_kind:
            for child in ast.walk(node.target):
                if isinstance(child, ast.Name):
                    sources[child.id] = source_kind
    for node in sorted(nodes, key=lambda item: getattr(item, "lineno", 0)):
        if not isinstance(node, ast.Call):
            continue
        callee = (_qualified_name(node.func) or "").lower()
        if not any(token in callee for token in ("clean", "normalize", "parse", "validate")):
            continue
        source_kind = next(
            (
                kind
                for argument in node.args
                if (kind := _source_for(argument, sources)) is not None
            ),
            None,
        )
        if source_kind is None:
            continue
        for argument in node.args:
            if isinstance(argument, ast.Name) and argument.id not in sources:
                sources[argument.id] = source_kind
    return sources


def _source_for(node: ast.AST | None, sources: dict[str, str]) -> str | None:
    direct = _request_source_kind(node)
    if direct:
        return direct
    names = _node_names(node)
    return next(
        (kind for variable, kind in sources.items() if variable.lower() in names),
        None,
    )


def _guard_names(nodes: tuple[ast.AST, ...]) -> tuple[str, ...]:
    guards: set[str] = set()
    for node in nodes:
        if isinstance(node, (ast.If, ast.Assert)):
            test = node.test
        elif isinstance(node, ast.Call):
            name = (_qualified_name(node.func) or "").lower()
            if _is_authz_call(name):
                guards.add(name)
            continue
        else:
            continue
        for name in _node_names(test):
            if (
                any(token in name for token in _AUTHZ_CALL_TOKENS)
                or any(actor in name for actor in _ACTOR_NAMES)
                or any(token in name for token in ("owner", "tenant", "role", "scope"))
            ):
                guards.add(name)
    return tuple(sorted(guards))


def _has_object_authz_guard(nodes: tuple[ast.AST, ...]) -> bool:
    for node in nodes:
        if isinstance(node, ast.Call):
            name = (_qualified_name(node.func) or "").lower()
            if _is_authz_call(name):
                return True
        if not isinstance(node, (ast.If, ast.Assert)):
            continue
        names = _node_names(node.test)
        has_actor = any(
            actor == name or name.endswith(f".{actor}")
            for actor in _ACTOR_NAMES
            for name in names
        )
        has_scope = any(
            any(
                token in name
                for token in (
                    "admin",
                    "assistant",
                    "employee",
                    "instructor",
                    "manager",
                    "owner",
                    "patient",
                    "provider",
                    "receiver_id",
                    "role",
                    "scope",
                    "sender_id",
                    "student_id",
                    "tenant",
                    "user_id",
                )
            )
            for name in names
        )
        has_authz_boolean = any(
            _last_name(name).startswith("can_")
            or any(
                token in _last_name(name)
                for token in ("allowed", "authorized", "permission")
            )
            for name in names
        )
        denies_access = isinstance(node, ast.Assert) or any(
            isinstance(child, (ast.Raise, ast.Return))
            for statement in node.body
            for child in ast.walk(statement)
        )
        if denies_access and (has_actor and has_scope or has_authz_boolean):
            return True
    return False


def _lookup_is_subject_scoped(node: ast.Call) -> bool:
    names = {
        name
        for argument in (*node.args, *(item.value for item in node.keywords))
        for name in _node_names(argument)
    }
    has_actor = any(
        name == actor or name.endswith(f".{actor}")
        for actor in _ACTOR_NAMES
        for name in names
    )
    has_scope = any(
        any(
            token in name
            for token in (
                "owner_id",
                "tenant_id",
                "user_id",
                "borrower_id",
                "customer_id",
                "sender_id",
                "receiver_id",
                "region_id",
            )
        )
        for name in names
    )
    return has_actor and has_scope


def _has_numeric_bound_guard(nodes: tuple[ast.AST, ...], variable: str) -> bool:
    for node in nodes:
        if not isinstance(node, (ast.If, ast.Assert)):
            continue
        test = node.test
        if variable.lower() not in _node_names(test):
            continue
        if any(isinstance(child, ast.Constant) and isinstance(child.value, (int, float)) for child in ast.walk(test)):
            return True
        call_names = {
            (_qualified_name(child.func) or "").lower()
            for child in ast.walk(test)
            if isinstance(child, ast.Call)
        }
        if any("valid" in name or "bound" in name or "limit" in name for name in call_names):
            return True
    return False


def _source_assignments(
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
) -> dict[str, set[str]]:
    """Build a bounded source-alias graph once for one function."""
    assignments: dict[str, set[str]] = {}
    for node in nodes:
        value: ast.AST | None = None
        targets: tuple[ast.AST, ...] = ()
        if isinstance(node, ast.Assign):
            value = node.value
            targets = tuple(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = (node.target,)
        if value is None:
            continue
        dependencies = {
            name
            for name in _node_names(value)
            if name in sources
        }
        for target in targets:
            name = _qualified_name(target)
            if name in sources:
                assignments[name] = dependencies - {name}
    return assignments


def _source_roots(
    variable: str,
    assignments: dict[str, set[str]],
) -> set[str]:
    """Resolve bounded assignment aliases back to caller-controlled roots."""

    resolved: set[str] = set()
    pending = [variable]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        dependencies = assignments.get(current, set())
        if dependencies:
            pending.extend(dependencies)
        else:
            resolved.add(current)
    return resolved or {variable}


def _source_lineage(
    variable: str,
    assignments: dict[str, set[str]],
) -> set[str]:
    """Return bounded source aliases, including intermediate business fields."""
    lineage: set[str] = set()
    pending = [variable]
    while pending:
        current = pending.pop()
        if current in lineage:
            continue
        lineage.add(current)
        pending.extend(assignments.get(current, set()))
    return lineage


def _pagination_bound_status(
    nodes: tuple[ast.AST, ...],
    variable: str,
) -> tuple[bool, bool]:
    """Return whether a pagination value has lower and upper server-side bounds."""
    lower = False
    upper = False
    lowered_variable = variable.lower()
    for node in nodes:
        if isinstance(node, (ast.If, ast.Assert)):
            expression = node.test
            if lowered_variable not in _node_names(expression):
                continue
            constants = [
                child.value
                for child in ast.walk(expression)
                if isinstance(child, ast.Constant)
                and isinstance(child.value, int)
                and not isinstance(child.value, bool)
            ]
            lower = lower or any(value <= 1 for value in constants)
            upper = upper or any(value > 1 for value in constants)
            call_names = {
                (_qualified_name(child.func) or "").lower()
                for child in ast.walk(expression)
                if isinstance(child, ast.Call)
            }
            if any("validate" in name or "pagination" in name for name in call_names):
                lower = True
                upper = True
        if not isinstance(node, ast.Call):
            continue
        names = _node_names(node)
        if lowered_variable not in names:
            continue
        call_name = _last_name(_qualified_name(node.func))
        constants = [
            child.value
            for child in ast.walk(node)
            if isinstance(child, ast.Constant)
            and isinstance(child.value, int)
            and not isinstance(child.value, bool)
        ]
        if call_name == "max" and constants:
            lower = True
        if call_name == "min" and constants:
            upper = True
        if "validate" in call_name or "pagination" in call_name:
            lower = True
            upper = True
    return lower, upper


def _risk(
    bug_class: LogicBugClass,
    *,
    entrypoint: bool,
) -> tuple[float, str, tuple[tuple[str, float], ...]]:
    severity = 4.0
    reachability = 5.0 if entrypoint else 3.5
    exposure = 4.5 if entrypoint else 3.0
    sensitivity = {
        LogicBugClass.MISSING_AUTHZ_IDOR: 4.5,
        LogicBugClass.BUSINESS_RULE_BYPASS: 4.0,
    }[bug_class]
    exploitability = 4.0
    score = round(
        0.25 * severity
        + 0.25 * reachability
        + 0.20 * exposure
        + 0.20 * sensitivity
        + 0.10 * exploitability,
        2,
    )
    level = "CRITICAL" if score >= 4.2 else "HIGH" if score >= 3.4 else "MEDIUM"
    return (
        score,
        level,
        (
            ("severity", severity),
            ("reachability", reachability),
            ("exposure", exposure),
            ("data_sensitivity", sensitivity),
            ("exploitability", exploitability),
        ),
    )


def _candidate(
    bug_class: LogicBugClass,
    *,
    file_path: str,
    component: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    entrypoint: bool,
    line: int,
    end_line: int,
    source_kind: str,
    sink_kind: str,
    guards: tuple[str, ...],
    source_symbol: str | None = None,
    source_line: int | None = None,
    sink_symbol: str | None = None,
    sink_line: int | None = None,
    sink_argument: str | None = None,
) -> LogicCandidate:
    cwe, severity, remediation = _CLASS_FACTS[bug_class]
    score, level, factors = _risk(bug_class, entrypoint=entrypoint)
    return LogicCandidate(
        bug_class=bug_class,
        file_path=file_path,
        component=component,
        line=line,
        end_line=max(line, end_line),
        function=function.name,
        entrypoint=entrypoint,
        source_kind=source_kind,
        sink_kind=sink_kind,
        guards=guards,
        trace=(
            f"entrypoint:{function.name}@{function.lineno}",
            f"source:{source_kind}",
            f"sink:{sink_kind}@{line}",
        ),
        cwe=cwe,
        severity=severity,
        risk_score=score,
        risk_level=level,
        risk_factors=factors,
        remediation=remediation,
        validation_checklist=(
            "Add a negative authorization or boundary test for the exact sink.",
            "Add a positive test for the intended authorized or bounded flow.",
            "Review the complete source-to-guard-to-sink trace.",
        ),
        function_start_line=function.lineno,
        function_end_line=function.end_lineno or function.lineno,
        source_symbol=source_symbol,
        source_line=source_line or function.lineno,
        sink_symbol=sink_symbol,
        sink_line=sink_line or line,
        sink_argument=sink_argument,
    )


def _idor_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    if _has_object_authz_guard(nodes):
        return []
    guards = _guard_names(nodes)
    results: list[LogicCandidate] = []
    for node in nodes:
        if not isinstance(node, ast.Call) or not _is_lookup_call(_qualified_name(node.func)):
            continue
        if _lookup_is_subject_scoped(node):
            continue
        arguments = (*node.args, *(item.value for item in node.keywords))
        source_argument = next(
            (item for item in arguments if _source_for(item, sources)),
            None,
        )
        source_kind = _source_for(source_argument, sources)
        names = {name.rsplit(".", 1)[-1] for item in arguments for name in _node_names(item)}
        route_identifier = source_kind == "http_route_parameter"
        if source_kind is None or not (
            route_identifier or any(_is_identifier_name(name) for name in names)
        ):
            continue
        source_symbols = sorted(
            name
            for name in names
            if name in sources and sources[name] == source_kind
        )
        source_symbol = source_symbols[0] if source_symbols else None
        sink_symbol = _qualified_name(node.func)
        results.append(
            _candidate(
                LogicBugClass.MISSING_AUTHZ_IDOR,
                function=function,
                line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                source_kind=source_kind,
                sink_kind="object_lookup_without_subject_scope",
                guards=guards,
                source_symbol=source_symbol,
                source_line=(
                    source_argument.lineno
                    if source_argument is not None
                    and hasattr(source_argument, "lineno")
                    else function.lineno
                ),
                sink_symbol=sink_symbol,
                sink_line=node.lineno,
                sink_argument=source_symbol,
                **common,
            )
        )
    return results


def _missing_authorization_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    """Detect narrowly named privileged endpoints without an authorization gate."""
    del sources
    if not bool(common.get("entrypoint")):
        return []
    if _has_object_authz_guard(nodes):
        return []
    name = function.name.lower()
    privileged_tokens = (
        "audit",
        "delete_all",
        "difficulty",
        "secret",
        "reset",
        "start_over",
        "all_users",
    )
    if not any(token in name for token in privileged_tokens):
        return []
    calls = [node for node in nodes if isinstance(node, ast.Call)]
    preferred_tokens = {
        "audit": ("query", "order_by", "all"),
        "delete_all": ("delete",),
        "difficulty": ("set_mode",),
        "secret": ("secret", "token", "key"),
        "reset": ("reset", "initialize"),
        "start_over": ("initialize", "reset"),
        "all_users": ("all", "query"),
    }
    active_tokens = next(
        (tokens for token, tokens in preferred_tokens.items() if token in name),
        (),
    )
    sink = next(
        (
            node
            for node in calls
            if any(token in _qualified_name(node.func).lower() for token in active_tokens)
        ),
        calls[0] if calls else None,
    )
    return [
        _candidate(
            LogicBugClass.MISSING_AUTHZ_IDOR,
            function=function,
            line=function.lineno,
            end_line=function.end_lineno or function.lineno,
            source_kind="http_or_graphql_endpoint",
            sink_kind="privileged_endpoint_without_authorization",
            guards=_guard_names(nodes),
            source_symbol=function.name,
            source_line=function.lineno,
            sink_symbol=_qualified_name(sink.func) if sink is not None else function.name,
            sink_line=sink.lineno if sink is not None else function.lineno,
            sink_argument="authorization_boundary",
            **common,
        )
    ]


def _actor_binding_override_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    """Detect blanket request-map updates that can overwrite an actor binding."""
    del sources
    if _has_object_authz_guard(nodes):
        return []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = _qualified_name(node.func)
        if _last_name(name) != "update" or not node.args:
            continue
        if _request_source_kind(node.args[0]) is None:
            continue
        receiver = _qualified_name(node.func.value) if isinstance(node.func, ast.Attribute) else None
        if receiver is None:
            continue
        return [
            _candidate(
                LogicBugClass.MISSING_AUTHZ_IDOR,
                function=function,
                line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                source_kind="http_request_body",
                sink_kind="request_mapping_overwrites_actor_binding",
                guards=_guard_names(nodes),
                source_symbol="request_body",
                source_line=node.args[0].lineno,
                sink_symbol=name,
                sink_line=node.lineno,
                sink_argument=receiver,
                **common,
            )
        ]
    return []


def _business_rule_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    guards = _guard_names(nodes)
    assignments = _source_assignments(nodes, sources)
    results: list[LogicCandidate] = []
    for variable, source_kind in sources.items():
        last = variable.rsplit(".", 1)[-1].lower()
        if any(
            token == last or last.endswith(f"_{token}")
            for token in _PAGINATION_TOKENS
        ):
            continue
        if not any(token in last for token in _DOMAIN_VALUE_TOKENS):
            continue
        roots = _source_roots(variable, assignments)
        lineage = _source_lineage(variable, assignments)
        client_controls_price = any(
            any(
                token in name.rsplit(".", 1)[-1].lower()
                for token in _CLIENT_PRICE_TOKENS
            )
            for name in lineage
            if name != variable or name in roots
        )
        domain_lineage = {
            name
            for name in lineage
            if any(
                token in name.rsplit(".", 1)[-1].lower()
                for token in _DOMAIN_VALUE_TOKENS
            )
        }
        domain_values = domain_lineage - {variable} or domain_lineage
        roots_are_bounded = all(
            _has_numeric_bound_guard(nodes, value) for value in domain_values
        )
        if not client_controls_price and roots_are_bounded:
            continue
        call_sinks = [
            node
            for node in nodes
            if isinstance(node, ast.Call)
            and _matches_last(_qualified_name(node.func), _MUTATION_CALLS)
            and variable.lower() in _node_names(node)
        ]
        assignment_sinks = [
            node
            for node in nodes
            if isinstance(node, ast.AugAssign)
            and variable.lower() in _node_names(node.value)
        ]
        return_sinks = [
            node
            for node in nodes
            if isinstance(node, ast.Return)
            and variable.lower() in _node_names(node.value)
        ]
        sinks = [*call_sinks, *assignment_sinks, *return_sinks]
        if not sinks:
            continue
        sink = min(sinks, key=lambda item: item.lineno)
        results.append(
            _candidate(
                LogicBugClass.BUSINESS_RULE_BYPASS,
                function=function,
                line=sink.lineno,
                end_line=sink.end_lineno or sink.lineno,
                source_kind=source_kind,
                sink_kind=(
                    "client_controlled_price_or_total"
                    if client_controls_price
                    else "unvalidated_domain_value_operation"
                ),
                guards=guards,
                source_symbol=variable,
                source_line=min(
                    (
                        node.lineno
                        for node in nodes
                        if isinstance(node, (ast.Assign, ast.AnnAssign))
                        and variable.lower() in _node_names(node)
                    ),
                    default=function.lineno,
                ),
                sink_symbol=(
                    _qualified_name(sink.func)
                    if isinstance(sink, ast.Call)
                    else "return"
                    if isinstance(sink, ast.Return)
                    else "augmented_assignment"
                ),
                sink_line=sink.lineno,
                sink_argument=variable,
                **common,
            )
        )
    return results


def _pagination_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    guards = _guard_names(nodes)
    assignments = _source_assignments(nodes, sources)
    results: list[LogicCandidate] = []
    for variable, source_kind in sources.items():
        last = variable.rsplit(".", 1)[-1].lower()
        if not any(
            token == last or last.endswith(f"_{token}")
            for token in _PAGINATION_TOKENS
        ):
            continue
        uses = [
            node
            for node in nodes
            if isinstance(node, ast.Call)
            and _last_name(_qualified_name(node.func))
            in {"limit", "offset", "paginate", "slice"}
            and variable.lower() in _node_names(node)
        ]
        if not uses:
            continue
        roots = _source_roots(variable, assignments)
        bounds = [_pagination_bound_status(nodes, root) for root in roots]
        requires_upper = any(
            token in last for token in ("limit", "page_size", "per_page")
        )
        bounded = all(
            lower and (upper or not requires_upper) for lower, upper in bounds
        )
        if bounded:
            continue
        sink = min(uses, key=lambda item: item.lineno)
        results.append(
            _candidate(
                LogicBugClass.BUSINESS_RULE_BYPASS,
                function=function,
                line=sink.lineno,
                end_line=sink.end_lineno or sink.lineno,
                source_kind=source_kind,
                sink_kind="unbounded_pagination_parameter",
                guards=guards,
                source_symbol=variable,
                source_line=function.lineno,
                sink_symbol=_qualified_name(sink.func),
                sink_line=sink.lineno,
                sink_argument=variable,
                **common,
            )
        )

    calls = [node for node in nodes if isinstance(node, ast.Call)]
    has_collection_shape = any(
        token in function.name.lower() for token in _COLLECTION_FUNCTION_TOKENS
    )
    has_bound = any(
        _last_name(_qualified_name(node.func)) in {"limit", "paginate", "slice"}
        for node in calls
    )
    unbounded_query = next(
        (
            node
            for node in calls
            if _last_name(_qualified_name(node.func)) in {"all", "fetchall"}
        ),
        None,
    )
    if has_collection_shape and not has_bound and unbounded_query is not None:
        results.append(
            _candidate(
                LogicBugClass.BUSINESS_RULE_BYPASS,
                function=function,
                line=unbounded_query.lineno,
                end_line=unbounded_query.end_lineno or unbounded_query.lineno,
                source_kind="http_endpoint",
                sink_kind="unbounded_collection_query",
                guards=guards,
                source_symbol=function.name,
                source_line=function.lineno,
                sink_symbol=_qualified_name(unbounded_query.func),
                sink_line=unbounded_query.lineno,
                sink_argument="collection",
                **common,
            )
        )
    return results


def analyze_python_module(
    tree: ast.Module,
    *,
    file_path: str,
    component: str,
) -> tuple[LogicCandidate, ...]:
    """Return bounded candidates for focused IDOR and business-rule bugs."""
    results: list[LogicCandidate] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes = _walk_function(function)
        entrypoint = _is_endpoint(function)
        parameters = {
            item.arg
            for item in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
            if item.arg.lower() not in _NON_INPUT_PARAMETERS
        }
        sources = _assignment_sources(nodes, parameters if entrypoint else set())
        if not entrypoint and not any(_request_source_kind(node) for node in nodes):
            continue
        common = {
            "file_path": file_path,
            "component": component,
            "entrypoint": entrypoint,
        }
        results.extend(_idor_candidates(function, nodes, sources, **common))
        results.extend(
            _missing_authorization_candidates(function, nodes, sources, **common)
        )
        results.extend(
            _actor_binding_override_candidates(function, nodes, sources, **common)
        )
        results.extend(_business_rule_candidates(function, nodes, sources, **common))
        results.extend(_pagination_candidates(function, nodes, sources, **common))

    unique: dict[tuple[object, ...], LogicCandidate] = {}
    for candidate in results:
        key = (
            candidate.bug_class,
            candidate.file_path,
            candidate.line,
            candidate.function,
            candidate.sink_kind,
        )
        unique.setdefault(key, candidate)
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (item.file_path, item.line, item.bug_class.value),
        )
    )
