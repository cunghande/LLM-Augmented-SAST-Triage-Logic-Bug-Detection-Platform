"""Conservative AST patterns for the five Sprint 2 logic-bug classes.

The analyzer receives an already parsed AST and returns identifiers, relative
paths, line numbers and classifications only. It never retains source text or
literal values.
"""

from __future__ import annotations

import ast

from sast_triage.context.framework_registry import endpoint_source_type
from sast_triage.logic.models import LogicBugClass, LogicCandidate
from sast_triage.models import Severity

_REQUEST_ROOTS = {"request", "req"}
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
    "session",
}
_ID_TOKENS = ("id", "uuid", "slug", "key", "reference", "token")
_LOOKUP_CALLS = (
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
    "permission",
    "require_role",
    "tenant_scope",
)
_DOMAIN_VALUE_TOKENS = (
    "amount",
    "balance",
    "credit",
    "discount",
    "inventory",
    "limit",
    "price",
    "quantity",
    "quota",
    "stock",
    "total",
)
_WORKFLOW_ACTIONS = (
    "approve",
    "cancel",
    "change_password",
    "checkout",
    "close",
    "complete",
    "decide",
    "delete",
    "publish",
    "reset_password",
    "update_password",
)

_CLASS_FACTS: dict[LogicBugClass, tuple[str, Severity, str]] = {
    LogicBugClass.MISSING_AUTHZ_IDOR: (
        "CWE-639",
        Severity.HIGH,
        "Bind the requested object to the authenticated subject or tenant before reading or mutating it.",
    ),
    LogicBugClass.MASS_ASSIGNMENT: (
        "CWE-915",
        Severity.HIGH,
        "Replace blanket binding with an explicit allowlist of writable fields and reject privileged fields.",
    ),
    LogicBugClass.RACE_CONDITION_TOCTOU: (
        "CWE-367",
        Severity.HIGH,
        "Move the check and state change into one atomic transaction with an appropriate row or process lock.",
    ),
    LogicBugClass.BUSINESS_RULE_BYPASS: (
        "CWE-840",
        Severity.HIGH,
        "Enforce server-side domain bounds and invariants immediately before the state-changing operation.",
    ),
    LogicBugClass.INSECURE_WORKFLOW: (
        "CWE-841",
        Severity.HIGH,
        "Validate the current workflow state and required proof before allowing the sensitive transition.",
    ),
}


def _qualified_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


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
            "visible",
        )
    )
    return semantic_prefix and semantic_target or "visible_to" in last


def _is_identifier_name(name: str) -> bool:
    lowered = name.lower()
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
            actor == name or name.endswith(f".{actor}") or actor in name
            for actor in _ACTOR_NAMES
            for name in names
        )
        has_scope = any(
            any(token in name for token in ("owner", "tenant", "user_id", "sender_id", "receiver_id", "role", "scope"))
            for name in names
        )
        if has_actor and has_scope:
            return True
    return False


def _lookup_is_subject_scoped(node: ast.Call) -> bool:
    names = {
        name
        for argument in (*node.args, *(item.value for item in node.keywords))
        for name in _node_names(argument)
    }
    has_actor = any(
        name == actor or name.endswith(f".{actor}") or actor in name
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


def _has_atomic_control(nodes: tuple[ast.AST, ...]) -> bool:
    def is_atomic_name(name: str) -> bool:
        lowered = name.lower()
        last = _last_name(lowered)
        return (
            last in {
                "acquire",
                "atomic",
                "begin_nested",
                "compare_and_swap",
                "lock",
                "select_for_update",
                "synchronized",
            }
            or lowered.endswith("transaction.atomic")
        )

    for node in nodes:
        target: ast.AST | None = None
        if isinstance(node, ast.Call):
            target = node.func
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            names = set()
            for item in node.items:
                names.update(_node_names(item.context_expr))
            if any(is_atomic_name(name) for name in names):
                return True
        if target is not None:
            name = (_qualified_name(target) or "").lower()
            if is_atomic_name(name):
                return True
    return False


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


def _has_state_guard(nodes: tuple[ast.AST, ...], transition_line: int) -> bool:
    for node in nodes:
        if getattr(node, "lineno", transition_line) >= transition_line:
            continue
        if not isinstance(node, (ast.If, ast.Assert)):
            continue
        if any(
            name.endswith((".status", ".state")) or name in {"status", "state"}
            for name in _node_names(node.test)
        ):
            return True
    return False


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
        LogicBugClass.MASS_ASSIGNMENT: 4.5,
        LogicBugClass.RACE_CONDITION_TOCTOU: 4.0,
        LogicBugClass.BUSINESS_RULE_BYPASS: 4.0,
        LogicBugClass.INSECURE_WORKFLOW: 4.5,
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
            "Add a negative authorization or invariant test.",
            "Add a positive test for the intended workflow.",
            "Review the complete source-to-guard-to-sink trace.",
        ),
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
        source_kind = next((_source_for(item, sources) for item in arguments if _source_for(item, sources)), None)
        names = {name.rsplit(".", 1)[-1] for item in arguments for name in _node_names(item)}
        if source_kind is None or not any(_is_identifier_name(name) for name in names):
            continue
        results.append(
            _candidate(
                LogicBugClass.MISSING_AUTHZ_IDOR,
                function=function,
                line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                source_kind=source_kind,
                sink_kind="object_lookup_without_subject_scope",
                guards=guards,
                **common,
            )
        )
    return results


def _mass_assignment_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    guards = _guard_names(nodes)
    results: list[LogicCandidate] = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = (_qualified_name(node.func) or "").lower()
        source_kind: str | None = None
        sink_kind: str | None = None
        if _matches_last(name, _MUTATION_CALLS):
            expansions = [item.value for item in node.keywords if item.arg is None]
            source_kind = next((_source_for(item, sources) for item in expansions if _source_for(item, sources)), None)
            if source_kind:
                sink_kind = "unfiltered_keyword_expansion"
            if not source_kind and node.args and _last_name(name) == "update":
                source_kind = _source_for(node.args[0], sources)
                if source_kind:
                    sink_kind = "unfiltered_mapping_update"
        expansions = [item.value for item in node.keywords if item.arg is None]
        if not source_kind and expansions:
            source_kind = next(
                (
                    kind
                    for item in expansions
                    if (kind := _source_for(item, sources)) is not None
                ),
                None,
            )
            if source_kind:
                sink_kind = "unfiltered_model_construction"
        if name.endswith(".__dict__.update") and node.args:
            source_kind = _source_for(node.args[0], sources)
            if source_kind:
                sink_kind = "model_dictionary_update"
        if _last_name(name) == "setattr" and len(node.args) >= 3:
            source_kind = _source_for(node.args[1], sources) or _source_for(node.args[2], sources)
            if source_kind:
                sink_kind = "dynamic_attribute_assignment"
        if source_kind and sink_kind:
            results.append(
                _candidate(
                    LogicBugClass.MASS_ASSIGNMENT,
                    function=function,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    source_kind=source_kind,
                    sink_kind=sink_kind,
                    guards=guards,
                    **common,
                )
            )
    return results


def _race_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    **common: object,
) -> list[LogicCandidate]:
    if _has_atomic_control(nodes):
        return []
    mutations: list[tuple[int, set[str], ast.AST]] = []
    for node in nodes:
        if isinstance(node, ast.AugAssign):
            mutations.append((node.lineno, _node_names(node.target), node))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            mutations.append((node.lineno, _node_names(target), node))
    results: list[LogicCandidate] = []
    for node in nodes:
        if not isinstance(node, ast.If):
            continue
        checked = {
            name
            for name in _node_names(node.test)
            if any(token in name for token in _DOMAIN_VALUE_TOKENS)
        }
        if not checked:
            continue
        later = next(
            (
                mutation
                for line, names, mutation in sorted(mutations, key=lambda item: item[0])
                if line > node.lineno and any(name in checked for name in names)
            ),
            None,
        )
        if later is None:
            continue
        results.append(
            _candidate(
                LogicBugClass.RACE_CONDITION_TOCTOU,
                function=function,
                line=node.lineno,
                end_line=getattr(later, "end_lineno", later.lineno) or later.lineno,
                source_kind="shared_mutable_state",
                sink_kind="non_atomic_check_then_mutate",
                guards=_guard_names(nodes),
                **common,
            )
        )
    return results


def _business_rule_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    state_change_lines = [
        node.lineno
        for node in nodes
        if (
            isinstance(node, ast.Call)
            and _matches_last(_qualified_name(node.func), _MUTATION_CALLS)
        )
        or isinstance(node, ast.AugAssign)
    ]
    if not state_change_lines:
        return []
    guards = _guard_names(nodes)
    results: list[LogicCandidate] = []
    for variable, source_kind in sources.items():
        last = variable.rsplit(".", 1)[-1].lower()
        if not any(token in last for token in _DOMAIN_VALUE_TOKENS):
            continue
        if _has_numeric_bound_guard(nodes, variable):
            continue
        uses = [
            node
            for node in nodes
            if getattr(node, "lineno", 0) in state_change_lines
            and variable.lower() in _node_names(node)
        ]
        if not uses:
            uses = [
                node
                for node in nodes
                if isinstance(node, ast.AugAssign)
                and variable.lower() in _node_names(node.value)
            ]
        if not uses:
            continue
        sink = min(uses, key=lambda item: item.lineno)
        results.append(
            _candidate(
                LogicBugClass.BUSINESS_RULE_BYPASS,
                function=function,
                line=sink.lineno,
                end_line=sink.end_lineno or sink.lineno,
                source_kind=source_kind,
                sink_kind="unvalidated_domain_value_mutation",
                guards=guards,
                **common,
            )
        )
    return results


def _workflow_candidates(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    nodes: tuple[ast.AST, ...],
    sources: dict[str, str],
    **common: object,
) -> list[LogicCandidate]:
    lowered_name = function.name.lower()
    guards = _guard_names(nodes)
    results: list[LogicCandidate] = []
    if "password" in lowered_name and any(action in lowered_name for action in ("change", "update", "reset")):
        calls = [node for node in nodes if isinstance(node, ast.Call)]
        password_calls = [
            node
            for node in calls
            if any(
                token in (_qualified_name(node.func) or "").lower()
                for token in (
                    "set_password",
                    "get_password_hash",
                    "hash_password",
                    "generate_password_hash",
                )
            )
        ]
        password_assignments = [
            node
            for node in nodes
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                "password" in name
                for name in _node_names(
                    node.targets[0] if isinstance(node, ast.Assign) else node.target
                )
            )
        ]
        changes_password = bool(password_calls or password_assignments)
        if "reset" in lowered_name:
            verifies_existing = any(
                "token" in _node_names(argument)
                and any(
                    token in (_qualified_name(node.func) or "").lower()
                    for token in ("check", "decode", "find", "get", "lookup", "validate", "verify")
                )
                for node in calls
                for argument in node.args
            ) or any(
                isinstance(node, (ast.If, ast.Assert))
                and "token" in _node_names(node.test)
                for node in nodes
            )
        else:
            verifies_existing = any(
                any(
                    token in (_qualified_name(node.func) or "").lower()
                    for token in (
                        "check_password",
                        "verify_password",
                        "verify_current",
                        "old_password",
                    )
                )
                for node in calls
            ) or any(
                "old_password" in name or "current_password" in name
                for node in nodes
                for name in _node_names(node)
            )
        if changes_password and not verifies_existing:
            sink = (password_calls or password_assignments)[0]
            results.append(
                _candidate(
                    LogicBugClass.INSECURE_WORKFLOW,
                    function=function,
                    line=sink.lineno,
                    end_line=sink.end_lineno or sink.lineno,
                    source_kind=next(iter(sources.values()), "http_request_body"),
                    sink_kind="password_change_without_existing_secret_verification",
                    guards=guards,
                    **common,
                )
            )
    if any(action in lowered_name for action in (*_WORKFLOW_ACTIONS, "upload")):
        for node in nodes:
            target: ast.AST | None = None
            value: ast.AST | None = None
            if isinstance(node, ast.Assign):
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            if target is None or value is None:
                continue
            target_names = _node_names(target)
            if not any(name.endswith((".status", ".state")) for name in target_names):
                continue
            if _has_state_guard(nodes, node.lineno):
                continue
            results.append(
                _candidate(
                    LogicBugClass.INSECURE_WORKFLOW,
                    function=function,
                    line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    source_kind=_source_for(value, sources) or "workflow_action",
                    sink_kind="state_transition_without_prior_state_guard",
                    guards=guards,
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
    """Return bounded candidates for all five required logic-bug classes."""
    results: list[LogicCandidate] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes = _walk_function(function)
        entrypoint = endpoint_source_type(function) is not None
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
        results.extend(_mass_assignment_candidates(function, nodes, sources, **common))
        results.extend(_race_candidates(function, nodes, **common))
        results.extend(_business_rule_candidates(function, nodes, sources, **common))
        results.extend(_workflow_candidates(function, nodes, sources, **common))

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
