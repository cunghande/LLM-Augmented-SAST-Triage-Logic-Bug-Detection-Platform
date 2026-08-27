"""Bounded path-sensitive verification over already-sanitized Python context."""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass
from enum import Enum

from sast_triage.models import NormalizedFinding

_MISSING = object()
_MAX_STATES = 32
_FUNCTION_LINE = re.compile(r"^(?P<indent>[ \t]*)(?:async[ \t]+)?def[ \t]+")
_SECURITY_MARKERS = (
    "auth",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "signature",
    "token",
)


class _Origin(str, Enum):
    SAFE = "safe"
    TAINTED = "tainted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _Value:
    origin: _Origin
    constant: object = _MISSING
    items: tuple[_Value, ...] | None = None


SAFE_UNKNOWN = _Value(_Origin.SAFE)
TAINTED = _Value(_Origin.TAINTED)
UNKNOWN = _Value(_Origin.UNKNOWN)


@dataclass(slots=True)
class _State:
    values: dict[str, _Value]

    def clone(self) -> _State:
        return _State(dict(self.values))


@dataclass(frozen=True, slots=True)
class LocalVerification:
    """Source-free result of bounded local value resolution."""

    negative_taint_proven: bool
    unresolved_guard_observed: bool
    target_paths: int
    provenance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IntrinsicUsageVerification:
    """Source-free proof that an intrinsic primitive protects a security asset."""

    security_sensitive_usage_proven: bool
    usage_kind: str | None
    provenance: tuple[str, ...]


def _constant(value: object) -> _Value:
    return _Value(_Origin.SAFE, constant=value)


def _origin(values: list[_Value]) -> _Origin:
    if any(value.origin == _Origin.TAINTED for value in values):
        return _Origin.TAINTED
    if any(value.origin == _Origin.UNKNOWN for value in values):
        return _Origin.UNKNOWN
    return _Origin.SAFE


def _attribute_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _assigned_names(node: ast.AST) -> set[str]:
    return {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
    }


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    }


def _contains_security_marker(node: ast.AST) -> bool:
    values: list[str] = []
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            values.append(item.value.casefold())
        elif isinstance(item, ast.Name):
            values.append(item.id.casefold())
        elif isinstance(item, ast.Attribute):
            values.append(item.attr.casefold())
    return any(marker in value for marker in _SECURITY_MARKERS for value in values)


def _is_hash_target(call: ast.Call, finding: NormalizedFinding, start: int) -> bool:
    absolute_line = start + call.lineno - 1
    end_line = finding.end_line or finding.start_line
    name = _attribute_name(call.func).casefold()
    return (
        finding.start_line <= absolute_line <= end_line
        and name.rsplit(".", 1)[-1] in {"md5", "new", "sha1"}
    )


def _parse_enclosing_fragment(
    code: str,
    finding: NormalizedFinding,
    context_start_line: int,
) -> tuple[ast.Module, int] | None:
    """Parse a sanitized snippet, falling back to its enclosing function slice."""
    try:
        return ast.parse(textwrap.dedent(code)), context_start_line
    except (SyntaxError, ValueError, TypeError):
        pass
    lines = code.splitlines()
    target_index = finding.start_line - context_start_line
    if target_index < 0 or target_index >= len(lines):
        return None
    target_indent = len(lines[target_index]) - len(lines[target_index].lstrip())
    for index in range(target_index, -1, -1):
        match = _FUNCTION_LINE.match(lines[index])
        if match is None or len(match.group("indent")) >= target_indent:
            continue
        fragment = "\n".join(lines[index:])
        try:
            return ast.parse(textwrap.dedent(fragment)), context_start_line + index
        except (SyntaxError, ValueError, TypeError):
            continue
    return None


def _depends_on_taint(node: ast.AST, state: _State) -> bool:
    return any(
        isinstance(item, ast.Name)
        and state.values.get(item.id, UNKNOWN).origin == _Origin.TAINTED
        for item in ast.walk(node)
    ) or any(
        isinstance(item, ast.Attribute)
        and _attribute_name(item).startswith("request.")
        for item in ast.walk(node)
    )


def _eval_constant_binary(operator: ast.operator, left: object, right: object) -> object:
    try:
        if isinstance(operator, ast.Add):
            return left + right  # type: ignore[operator]
        if isinstance(operator, ast.Sub):
            return left - right  # type: ignore[operator]
        if isinstance(operator, ast.Mult):
            return left * right  # type: ignore[operator]
        if isinstance(operator, ast.FloorDiv):
            return left // right  # type: ignore[operator]
        if isinstance(operator, ast.Mod):
            return left % right  # type: ignore[operator]
    except (ArithmeticError, TypeError, ValueError):
        return _MISSING
    return _MISSING


def _evaluate(node: ast.AST, state: _State) -> _Value:
    if isinstance(node, ast.Constant):
        return _constant(node.value)
    if isinstance(node, ast.Name):
        if node.id == "request":
            return TAINTED
        return state.values.get(node.id, UNKNOWN)
    if isinstance(node, ast.Attribute):
        name = _attribute_name(node)
        if name in state.values:
            return state.values[name]
        if name == "request" or name.startswith("request."):
            return TAINTED
        base = _evaluate(node.value, state)
        return _Value(base.origin)
    if isinstance(node, (ast.List, ast.Tuple)):
        items = tuple(_evaluate(item, state) for item in node.elts)
        return _Value(_origin(list(items)), items=items)
    if isinstance(node, ast.JoinedStr):
        values = [
            _evaluate(item.value, state)
            for item in node.values
            if isinstance(item, ast.FormattedValue)
        ]
        return _Value(_origin(values) if values else _Origin.SAFE)
    if isinstance(node, ast.BinOp):
        left = _evaluate(node.left, state)
        right = _evaluate(node.right, state)
        origin = _origin([left, right])
        if (
            origin == _Origin.SAFE
            and left.constant is not _MISSING
            and right.constant is not _MISSING
        ):
            result = _eval_constant_binary(node.op, left.constant, right.constant)
            if result is not _MISSING:
                return _constant(result)
        return _Value(origin)
    if isinstance(node, ast.UnaryOp):
        value = _evaluate(node.operand, state)
        if value.constant is not _MISSING:
            try:
                if isinstance(node.op, ast.Not):
                    return _constant(not value.constant)
                if isinstance(node.op, ast.USub):
                    return _constant(-value.constant)  # type: ignore[operator]
            except (TypeError, ValueError):
                pass
        return _Value(value.origin)
    if isinstance(node, ast.Subscript):
        container = _evaluate(node.value, state)
        index = _evaluate(node.slice, state)
        if index.constant is not _MISSING:
            try:
                if container.items is not None and isinstance(index.constant, int):
                    return container.items[index.constant]
                if container.constant is not _MISSING:
                    return _constant(container.constant[index.constant])  # type: ignore[index]
            except (IndexError, KeyError, TypeError):
                return UNKNOWN
        return _Value(_origin([container, index]))
    if isinstance(node, ast.IfExp):
        condition = _evaluate_condition(node.test, state)
        if condition is True:
            return _evaluate(node.body, state)
        if condition is False:
            return _evaluate(node.orelse, state)
        left = _evaluate(node.body, state)
        right = _evaluate(node.orelse, state)
        if left == right:
            return left
        return _Value(_origin([left, right]))
    if isinstance(node, ast.Compare):
        result = _evaluate_condition(node, state)
        return _constant(result) if result is not None else UNKNOWN
    if isinstance(node, ast.Call):
        name = _attribute_name(node.func)
        receiver = (
            _evaluate(node.func.value, state)
            if isinstance(node.func, ast.Attribute)
            else None
        )
        suffix = name.rsplit(".", 1)[-1].casefold()
        if (
            name == "request"
            or name.startswith("request.")
            and not (
                suffix == "split"
                and receiver is not None
                and receiver.constant is not _MISSING
            )
        ):
            return TAINTED
        arguments = [_evaluate(argument, state) for argument in node.args]
        if (
            suffix == "split"
            and receiver is not None
            and receiver.constant is not _MISSING
            and all(argument.constant is not _MISSING for argument in arguments)
        ):
            try:
                raw_items = receiver.constant.split(  # type: ignore[union-attr]
                    *(argument.constant for argument in arguments)
                )
                items = tuple(_constant(item) for item in raw_items)
                return _Value(_Origin.SAFE, items=items)
            except (AttributeError, TypeError, ValueError):
                return UNKNOWN
        if suffix in {
            "b64decode",
            "b64encode",
            "unquote",
            "unquote_plus",
            "urlsafe_b64decode",
        } and arguments:
            return _Value(_origin(arguments))
        if suffix in {"decode", "encode"} and receiver is not None:
            return _Value(_origin([receiver, *arguments]))
        values = ([receiver] if receiver is not None else []) + arguments
        if name in {"len", "bool", "int", "str", "bytes"} and arguments:
            return _Value(arguments[0].origin)
        return _Value(_origin(values) if values else _Origin.UNKNOWN)
    return UNKNOWN


def _evaluate_condition(node: ast.AST, state: _State) -> bool | None:
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        left = _evaluate(node.left, state)
        right = _evaluate(node.comparators[0], state)
        if left.constant is _MISSING or right.constant is _MISSING:
            return None
        operator = node.ops[0]
        try:
            if isinstance(operator, ast.Eq):
                return left.constant == right.constant
            if isinstance(operator, ast.NotEq):
                return left.constant != right.constant
            if isinstance(operator, ast.Gt):
                return left.constant > right.constant  # type: ignore[operator]
            if isinstance(operator, ast.GtE):
                return left.constant >= right.constant  # type: ignore[operator]
            if isinstance(operator, ast.Lt):
                return left.constant < right.constant  # type: ignore[operator]
            if isinstance(operator, ast.LtE):
                return left.constant <= right.constant  # type: ignore[operator]
            if isinstance(operator, ast.In):
                return left.constant in right.constant  # type: ignore[operator]
            if isinstance(operator, ast.NotIn):
                return left.constant not in right.constant  # type: ignore[operator]
        except (TypeError, ValueError):
            return None
    value = _evaluate(node, state)
    if value.constant is not _MISSING:
        return bool(value.constant)
    return None


def _assign(target: ast.AST, value: _Value, state: _State) -> None:
    if isinstance(target, ast.Name):
        state.values[target.id] = value


def _call_name(node: ast.Call) -> str:
    return _attribute_name(node.func).rsplit(".", 1)[-1]


def _sink_names(finding: NormalizedFinding) -> frozenset[str]:
    rule = finding.rule_id.casefold()
    if any(token in rule for token in ("deserial", "pickle", "yaml")):
        return frozenset({"load", "loads"})
    if any(token in rule for token in ("subprocess", "command", "shell")):
        return frozenset({"call", "popen", "run", "system"})
    if any(token in rule for token in ("path-traversal", "path_traversal", "pathtraver")):
        return frozenset({"open"})
    if "redirect" in rule:
        return frozenset({"redirect"})
    if any(token in rule for token in ("sql", "query")):
        return frozenset({"execute", "executemany"})
    return frozenset()


class _Interpreter:
    def __init__(self, finding: NormalizedFinding, context_start_line: int) -> None:
        self.finding = finding
        self.context_start_line = context_start_line
        self.sink_names = _sink_names(finding)
        self.target_values: list[_Value] = []
        self.unresolved_guard_observed = False

    def _is_target(self, node: ast.Call) -> bool:
        absolute_line = self.context_start_line + node.lineno - 1
        end_line = self.finding.end_line or self.finding.start_line
        return (
            self.finding.start_line <= absolute_line <= end_line
            and _call_name(node).casefold() in self.sink_names
        )

    def _record_target(self, node: ast.Call, state: _State) -> None:
        for candidate in ast.walk(node):
            if (
                isinstance(candidate, ast.Call)
                and self._is_target(candidate)
                and candidate.args
            ):
                self.target_values.append(_evaluate(candidate.args[0], state))

    def execute(self, statements: list[ast.stmt], states: list[_State]) -> list[_State]:
        current = states
        for statement in statements:
            next_states: list[_State] = []
            for state in current[:_MAX_STATES]:
                next_states.extend(self._execute_statement(statement, state))
            current = next_states[:_MAX_STATES]
            if not current:
                break
        return current

    def _execute_statement(self, statement: ast.stmt, state: _State) -> list[_State]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [state]
        if isinstance(statement, ast.If):
            condition = _evaluate_condition(statement.test, state)
            if condition is True:
                return self.execute(statement.body, [state])
            if condition is False:
                return self.execute(statement.orelse, [state])
            if _depends_on_taint(statement.test, state) and any(
                isinstance(item, (ast.Return, ast.Raise)) for item in statement.body
            ):
                self.unresolved_guard_observed = True
            body_states = self.execute(statement.body, [state.clone()])
            else_states = self.execute(statement.orelse, [state.clone()])
            return (body_states + else_states)[:_MAX_STATES]
        if isinstance(statement, ast.Match):
            return self._execute_match(statement, state)
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            assigned_names = {
                item.id
                for item in ast.walk(statement)
                if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
            }
            for name in assigned_names:
                state.values[name] = UNKNOWN
            return [state]
        if isinstance(statement, ast.Try):
            body_states = self.execute(statement.body, [state])
            return self.execute(statement.orelse, body_states) if statement.orelse else body_states
        for candidate in ast.walk(statement):
            if isinstance(candidate, ast.Call) and self._is_target(candidate):
                self._record_target(candidate, state)
                break
        if isinstance(statement, ast.Assign):
            value = _evaluate(statement.value, state)
            for target in statement.targets:
                _assign(target, value, state)
            return [state]
        if isinstance(statement, ast.AnnAssign) and statement.value is not None:
            _assign(statement.target, _evaluate(statement.value, state), state)
            return [state]
        if isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
            left = state.values.get(statement.target.id, UNKNOWN)
            right = _evaluate(statement.value, state)
            state.values[statement.target.id] = _Value(_origin([left, right]))
            return [state]
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            self._apply_mutation(statement.value, state)
            return [state]
        if isinstance(statement, (ast.Return, ast.Raise)):
            return []
        return [state]

    def _apply_mutation(self, call: ast.Call, state: _State) -> None:
        if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
            return
        name = call.func.value.id
        current = state.values.get(name)
        if current is None or current.items is None:
            return
        items = list(current.items)
        if call.func.attr == "append" and call.args:
            items.append(_evaluate(call.args[0], state))
        elif call.func.attr == "pop":
            index_value = _evaluate(call.args[0], state) if call.args else _constant(-1)
            if not isinstance(index_value.constant, int):
                state.values[name] = UNKNOWN
                return
            try:
                items.pop(index_value.constant)
            except IndexError:
                state.values[name] = UNKNOWN
                return
        else:
            return
        state.values[name] = _Value(_origin(items), items=tuple(items))

    def _execute_match(self, statement: ast.Match, state: _State) -> list[_State]:
        subject = _evaluate(statement.subject, state)
        if subject.constant is _MISSING:
            states: list[_State] = []
            for case in statement.cases:
                states.extend(self.execute(case.body, [state.clone()]))
            return states[:_MAX_STATES]
        for case in statement.cases:
            if _pattern_matches(case.pattern, subject.constant):
                return self.execute(case.body, [state])
        return [state]


def _pattern_matches(pattern: ast.pattern, value: object) -> bool:
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        return pattern.value.value == value
    if isinstance(pattern, ast.MatchOr):
        return any(_pattern_matches(item, value) for item in pattern.patterns)
    return isinstance(pattern, ast.MatchAs) and pattern.name is None


def _route_bound_state(function: ast.FunctionDef | ast.AsyncFunctionDef) -> _State:
    """Bind request.path only when a framework route is fully static."""
    values: dict[str, _Value] = {}
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not decorator.args:
            continue
        if _attribute_name(decorator.func).rsplit(".", 1)[-1] != "route":
            continue
        route = decorator.args[0]
        if (
            isinstance(route, ast.Constant)
            and isinstance(route.value, str)
            and "<" not in route.value
            and ">" not in route.value
        ):
            values["request.path"] = _constant(route.value)
            break
    return _State(values)


def verify_sanitized_python_flow(
    finding: NormalizedFinding,
    sanitized_code: str,
    *,
    context_start_line: int,
) -> LocalVerification:
    """Prove only bounded negative flows; unknown constructs fail closed."""
    if not _sink_names(finding):
        return LocalVerification(False, False, 0, ())
    try:
        tree = ast.parse(textwrap.dedent(sanitized_code))
    except (SyntaxError, ValueError, TypeError):
        return LocalVerification(False, False, 0, ("BOUNDED_LOCAL_PARSE_FAILED",))
    interpreter = _Interpreter(finding, context_start_line)
    target_line = finding.start_line - context_start_line + 1
    enclosing_functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= target_line <= (node.end_lineno or node.lineno)
    ]
    initial_state = _State({})
    if enclosing_functions:
        target_function = min(
            enclosing_functions,
            key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
        )
        target_scope = target_function.body
        initial_state = _route_bound_state(target_function)
    else:
        target_scope = tree.body
    interpreter.execute(target_scope, [initial_state])
    target_values = interpreter.target_values
    negative = bool(target_values) and all(
        value.origin == _Origin.SAFE for value in target_values
    )
    return LocalVerification(
        negative_taint_proven=negative,
        unresolved_guard_observed=interpreter.unresolved_guard_observed,
        target_paths=len(target_values),
        provenance=("BOUNDED_LOCAL_PATH_SENSITIVE",),
    )


def verify_intrinsic_security_usage(
    finding: NormalizedFinding,
    sanitized_code: str,
    *,
    context_start_line: int,
) -> IntrinsicUsageVerification:
    """Prove a bounded flow from a weak hash result to sensitive storage."""
    rule = finding.rule_id.casefold()
    if not any(token in rule for token in ("hash", "md5", "sha1")):
        return IntrinsicUsageVerification(False, None, ())
    parsed = _parse_enclosing_fragment(
        sanitized_code,
        finding,
        context_start_line,
    )
    if parsed is None:
        return IntrinsicUsageVerification(
            False,
            None,
            ("BOUNDED_INTRINSIC_PARSE_FAILED",),
        )
    tree, parsed_start_line = parsed
    target_line = finding.start_line - parsed_start_line + 1
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= target_line <= (node.end_lineno or node.lineno)
    ]
    scope: ast.AST = (
        min(
            functions,
            key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
        )
        if functions
        else tree
    )
    target_calls = [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call)
        and _is_hash_target(node, finding, parsed_start_line)
    ]
    if not target_calls:
        return IntrinsicUsageVerification(False, None, ())

    tracked: set[str] = set()
    sensitive_handles: set[str] = set()
    ordered = sorted(
        (
            node
            for node in ast.walk(scope)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Call))
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for node in ordered:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = _assigned_names(node)
            if any(target in ast.walk(value) for target in target_calls) or (
                tracked and _loaded_names(value).intersection(tracked)
            ):
                tracked.update(targets)
            if (
                isinstance(value, ast.Call)
                and _attribute_name(value.func).rsplit(".", 1)[-1] == "open"
                and _contains_security_marker(value)
            ):
                sensitive_handles.update(targets)
            if targets and tracked.intersection(_loaded_names(value)) and any(
                any(marker in target.casefold() for marker in _SECURITY_MARKERS)
                for target in targets
            ):
                return IntrinsicUsageVerification(
                    True,
                    "security_sensitive_assignment",
                    ("BOUNDED_INTRINSIC_SECURITY_USAGE",),
                )
            continue

        call_name = _attribute_name(node.func)
        receiver_name = (
            node.func.value.id
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            else None
        )
        if (
            call_name.rsplit(".", 1)[-1] == "write"
            and receiver_name in sensitive_handles
            and tracked.intersection(_loaded_names(node))
        ):
            return IntrinsicUsageVerification(
                True,
                "security_sensitive_storage",
                ("BOUNDED_INTRINSIC_SECURITY_USAGE",),
            )
        if (
            _contains_security_marker(node.func)
            and tracked.intersection(_loaded_names(node))
        ):
            return IntrinsicUsageVerification(
                True,
                "security_sensitive_call",
                ("BOUNDED_INTRINSIC_SECURITY_USAGE",),
            )
    return IntrinsicUsageVerification(
        False,
        None,
        ("BOUNDED_INTRINSIC_SECURITY_USAGE_UNRESOLVED",),
    )
