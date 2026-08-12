"""Phân tích Python AST có giới hạn để xây dựng bằng chứng an toàn cho provider.

Engine không bao giờ thực thi mã đích. Mã nguồn thô chỉ được giữ trong object
nội bộ này; mọi biểu thức đi ra ngoài đều là cấu trúc và không chứa literal
value.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace

from sast_triage.context.ast_utils import (
    _CUSTOM_CONTROL_MARKERS,
    _KNOWN_SANITIZER_SUFFIXES,
    _KNOWN_TRANSPARENT_CALL_SUFFIXES,
    _SINK_CALL_SUFFIXES,
    _SOURCE_CALL_SUFFIXES,
    _UNRESOLVED_CONSTANT,
    _assigned_names,
    _matches_suffix,
    _qualified_name,
    _safe_expression,
)
from sast_triage.context.evidence_models import (
    ContextCompleteness,
    EvidencePackage,
    EvidenceStatus,
    FindingEvidence,
    RelevantCodeEvidence,
    SecurityControlEvidence,
    SinkEvidence,
    SourceEvidence,
    TaintPathEvidence,
    TaintStep,
)
from sast_triage.context.reader import SourceReadResult
from sast_triage.models import NormalizedFinding, SanitizedContext


@dataclass(frozen=True, slots=True)
class _Origin:
    source: SourceEvidence | None
    steps: tuple[TaintStep, ...]
    controls: tuple[SecurityControlEvidence, ...]
    unresolved_symbols: tuple[str, ...]
    source_reaches_sink: bool | None
    parameter_name: str | None = None


class CoreAnalysisEngine:
    """Tạo bằng chứng cấu trúc có giới hạn từ một file mã nguồn Python."""

    def __init__(
        self,
        finding: NormalizedFinding,
        source: SourceReadResult,
        sanitized_context: SanitizedContext,
    ) -> None:
        """Khởi tạo analyzer nội bộ cho một finding và file mã nguồn."""
        self.finding = finding
        self.source = source
        self.sanitized_context = sanitized_context
        self._tree = ast.parse(source.text)
        self._parent_map = self._build_parent_map(self._tree)
        self._functions = self._index_functions(self._tree)
        self._target_function = self._find_enclosing_function(finding.start_line)

    @staticmethod
    def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
        return {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

    def _function_id(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        names = [node.name]
        parent = self._parent_map.get(node)
        while parent is not None:
            if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(parent.name)
            parent = self._parent_map.get(parent)
        return f"{self.finding.file_path}::" + ".".join(reversed(names))

    def _index_functions(
        self,
        tree: ast.AST,
    ) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
        indexed: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                indexed[self._function_id(node)] = node
        return indexed

    def _find_enclosing_function(
        self,
        line: int,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        candidates = [
            node
            for node in self._functions.values()
            if node.lineno <= line <= (node.end_lineno or node.lineno)
        ]
        return min(candidates, key=lambda node: (node.end_lineno or node.lineno) - node.lineno) if candidates else None

    def target_function_id(self) -> str | None:
        """Trả về định danh hàm đích ổn định khi có thể."""
        return self._function_id(self._target_function) if self._target_function else None

    def _analysis_scope(self) -> ast.AST:
        return self._target_function or self._tree

    def _find_sink(self) -> tuple[ast.Call | None, str, ast.AST | None, tuple[str, ...]]:
        calls = [node for node in ast.walk(self._analysis_scope()) if isinstance(node, ast.Call)]
        recognized: list[tuple[int, ast.Call, str]] = []
        for call in calls:
            match = _matches_suffix(_qualified_name(call.func), _SINK_CALL_SUFFIXES)
            if match:
                recognized.append((abs(call.lineno - self.finding.start_line), call, match[1]))
        if recognized:
            _, call, sink_type = min(recognized, key=lambda item: item[0])
        else:
            on_line = [
                call
                for call in calls
                if call.lineno <= self.finding.start_line <= (call.end_lineno or call.lineno)
            ]
            if not on_line:
                return None, "scanner_reported_operation", self._fallback_expression(), ()
            call = min(on_line, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
            sink_type = "scanner_reported_call"

        name = _qualified_name(call.func) or "<callable>"
        argument_index = 1 if name.endswith("xpath") and len(call.args) > 1 else 0
        dangerous_argument = call.args[argument_index] if len(call.args) > argument_index else None
        conditions = tuple(
            "shell=True"
            for keyword in call.keywords
            if keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        )
        return call, sink_type, dangerous_argument, conditions

    def _fallback_expression(self) -> ast.AST | None:
        candidates = [
            node
            for node in ast.walk(self._analysis_scope())
            if isinstance(node, ast.stmt)
            and node.lineno <= self.finding.start_line <= (node.end_lineno or node.lineno)
        ]
        if not candidates:
            return None
        statement = min(candidates, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            return statement.value
        if isinstance(statement, ast.Expr):
            return statement.value
        if isinstance(statement, ast.Return):
            return statement.value
        return statement

    def _parameters(self, function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> set[str]:
        if function is None:
            return set()
        args = function.args
        return {
            item.arg
            for item in (*args.posonlyargs, *args.args, *args.kwonlyargs)
        }

    def _assignment_before(
        self,
        name: str,
        line: int,
        scope: ast.AST,
    ) -> ast.AST | None:
        matches: list[tuple[int, ast.AST]] = []
        uncertain: list[tuple[int, ast.AST]] = []
        for node in ast.walk(scope):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                continue
            if node.lineno >= line:
                continue
            reaches = self._assignment_can_reach_line(node, line, scope)
            destination = matches if reaches else uncertain
            if isinstance(node, ast.Assign):
                if any(name in _assigned_names(target) for target in node.targets):
                    destination.append((node.lineno, node.value))
            elif (
                isinstance(node, ast.AnnAssign)
                and node.value is not None
                and name in _assigned_names(node.target)
            ):
                destination.append((node.lineno, node.value))
            elif isinstance(node, ast.AugAssign) and name in _assigned_names(node.target):
                combined = ast.copy_location(
                    ast.BinOp(left=node.target, op=node.op, right=node.value),
                    node,
                )
                destination.append((node.lineno, combined))
        matches.extend(self._selected_match_assignments(name, line, scope))
        matches.extend(self._selected_if_assignments(name, line, scope))
        base = max(matches, key=lambda item: item[0])[1] if matches else None
        uncertain = [
            item
            for item in uncertain
            if self._conditional_assignment_is_feasible(item[1], line, scope)
        ]
        if not uncertain:
            return base
        values = [value for _, value in uncertain]
        if base is not None:
            values.append(base)
        return ast.copy_location(ast.Tuple(elts=values, ctx=ast.Load()), values[0])

    def _conditional_assignment_is_feasible(
        self,
        value: ast.AST,
        target_line: int,
        scope: ast.AST,
    ) -> bool:
        """Keep unknown branch writes; discard writes in statically dead branches."""
        parent = self._parent_map.get(value)
        child: ast.AST = value
        while parent is not None and parent is not scope:
            if isinstance(parent, ast.If) and target_line > (parent.end_lineno or parent.lineno):
                condition = self._constant_value(parent.test, parent.lineno, scope)
                if isinstance(condition, bool):
                    selected = parent.body if condition else parent.orelse
                    return any(child is item or child in ast.walk(item) for item in selected)
            if isinstance(parent, ast.Match) and target_line > (
                parent.end_lineno or parent.lineno
            ):
                subject = self._constant_value(parent.subject, parent.lineno, scope)
                if subject is not _UNRESOLVED_CONSTANT:
                    selected: list[ast.stmt] = []
                    for case in parent.cases:
                        if self._pattern_matches(case.pattern, subject):
                            selected = case.body
                            break
                    return any(child is item or child in ast.walk(item) for item in selected)
            child = parent
            parent = self._parent_map.get(parent)
        return True

    def _constant_value(
        self,
        node: ast.AST,
        line: int,
        scope: ast.AST,
        seen: frozenset[str] = frozenset(),
    ) -> object:
        """Evaluate a small literal-only subset for deterministic branch selection."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in seen:
                return _UNRESOLVED_CONSTANT
            candidates: list[tuple[int, ast.AST]] = []
            for candidate in ast.walk(scope):
                if not isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                    continue
                if candidate.lineno >= line:
                    continue
                if not self._assignment_can_reach_line(candidate, line, scope):
                    continue
                if isinstance(candidate, ast.Assign):
                    if any(node.id in _assigned_names(target) for target in candidate.targets):
                        candidates.append((candidate.lineno, candidate.value))
                elif candidate.value is not None and node.id in _assigned_names(candidate.target):
                    candidates.append((candidate.lineno, candidate.value))
            if not candidates:
                return _UNRESOLVED_CONSTANT
            _, value = max(candidates, key=lambda item: item[0])
            return self._constant_value(value, getattr(value, "lineno", line), scope, seen | {node.id})
        if isinstance(node, ast.Subscript):
            container = self._constant_value(node.value, line, scope, seen)
            index = self._constant_value(node.slice, line, scope, seen)
            if isinstance(container, (str, tuple)) and isinstance(index, int):
                try:
                    return container[index]
                except IndexError:
                    return _UNRESOLVED_CONSTANT
        if isinstance(node, ast.UnaryOp):
            operand = self._constant_value(node.operand, line, scope, seen)
            if operand is _UNRESOLVED_CONSTANT:
                return _UNRESOLVED_CONSTANT
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub) and isinstance(operand, (int, float)):
                return -operand
        if isinstance(node, ast.BinOp):
            left = self._constant_value(node.left, line, scope, seen)
            right = self._constant_value(node.right, line, scope, seen)
            if left is _UNRESOLVED_CONSTANT or right is _UNRESOLVED_CONSTANT:
                return _UNRESOLVED_CONSTANT
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
            except TypeError:
                return _UNRESOLVED_CONSTANT
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left = self._constant_value(node.left, line, scope, seen)
            right = self._constant_value(node.comparators[0], line, scope, seen)
            if left is _UNRESOLVED_CONSTANT or right is _UNRESOLVED_CONSTANT:
                return _UNRESOLVED_CONSTANT
            operator = node.ops[0]
            try:
                if isinstance(operator, ast.Gt):
                    return left > right
                if isinstance(operator, ast.GtE):
                    return left >= right
                if isinstance(operator, ast.Lt):
                    return left < right
                if isinstance(operator, ast.LtE):
                    return left <= right
                if isinstance(operator, ast.Eq):
                    return left == right
                if isinstance(operator, ast.NotEq):
                    return left != right
                if isinstance(operator, ast.In):
                    return left in right
                if isinstance(operator, ast.NotIn):
                    return left not in right
            except TypeError:
                return _UNRESOLVED_CONSTANT
        if isinstance(node, ast.IfExp):
            condition = self._constant_value(node.test, line, scope, seen)
            if not isinstance(condition, bool):
                return _UNRESOLVED_CONSTANT
            branch = node.body if condition else node.orelse
            return self._constant_value(branch, line, scope, seen)
        return _UNRESOLVED_CONSTANT

    @staticmethod
    def _pattern_matches(pattern: ast.pattern, value: object) -> bool:
        if value is _UNRESOLVED_CONSTANT:
            return False
        if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
            return pattern.value.value == value
        if isinstance(pattern, ast.MatchSingleton):
            return pattern.value is value
        if isinstance(pattern, ast.MatchOr):
            return any(CoreAnalysisEngine._pattern_matches(item, value) for item in pattern.patterns)
        return isinstance(pattern, ast.MatchAs) and pattern.pattern is None

    def _selected_match_assignments(
        self,
        name: str,
        line: int,
        scope: ast.AST,
    ) -> list[tuple[int, ast.AST]]:
        """Return assignments from statically selected match cases before a sink."""
        selected: list[tuple[int, ast.AST]] = []
        for match_node in ast.walk(scope):
            if not isinstance(match_node, ast.Match):
                continue
            if (match_node.end_lineno or match_node.lineno) >= line:
                continue
            subject = self._constant_value(match_node.subject, match_node.lineno, scope)
            for case in match_node.cases:
                if not self._pattern_matches(case.pattern, subject):
                    continue
                for candidate in ast.walk(ast.Module(body=case.body, type_ignores=[])):
                    if isinstance(candidate, ast.Assign):
                        if any(name in _assigned_names(target) for target in candidate.targets):
                            selected.append((candidate.lineno, candidate.value))
                    elif (
                        isinstance(candidate, ast.AnnAssign)
                        and candidate.value is not None
                        and name in _assigned_names(candidate.target)
                    ):
                        selected.append((candidate.lineno, candidate.value))
                break
        return selected

    def _selected_if_assignments(
        self,
        name: str,
        line: int,
        scope: ast.AST,
    ) -> list[tuple[int, ast.AST]]:
        """Return assignments from compile-time-selected ``if`` branches."""
        selected: list[tuple[int, ast.AST]] = []
        for if_node in ast.walk(scope):
            if not isinstance(if_node, ast.If):
                continue
            if (if_node.end_lineno or if_node.lineno) >= line:
                continue
            condition = self._constant_value(if_node.test, if_node.lineno, scope)
            if not isinstance(condition, bool):
                continue
            branch = if_node.body if condition else if_node.orelse
            for candidate in ast.walk(ast.Module(body=branch, type_ignores=[])):
                value: ast.AST | None = None
                if (
                    isinstance(candidate, ast.Assign)
                    and any(
                        name in _assigned_names(target)
                        for target in candidate.targets
                    )
                ) or (
                    isinstance(candidate, ast.AnnAssign)
                    and candidate.value is not None
                    and name in _assigned_names(candidate.target)
                ):
                    value = candidate.value
                if value is not None:
                    selected.append((candidate.lineno, value))
        return selected

    def _assignment_can_reach_line(
        self,
        assignment: ast.AST,
        target_line: int,
        scope: ast.AST,
    ) -> bool:
        """Reject branch-local overwrites when the target is after that branch."""
        parent = self._parent_map.get(assignment)
        while parent is not None and parent is not scope:
            if isinstance(parent, (ast.If, ast.Match, ast.For, ast.AsyncFor, ast.While)):
                end_line = parent.end_lineno or parent.lineno
                if target_line > end_line:
                    return False
            parent = self._parent_map.get(parent)
        return True

    def _subscript_assignment_before(
        self,
        node: ast.Subscript,
        line: int,
        scope: ast.AST,
    ) -> ast.AST | None:
        """Resolve the latest same-key dictionary/list write before a read."""
        container = _qualified_name(node.value)
        if container is None:
            return None
        expected_slice = ast.dump(node.slice, include_attributes=False)
        matches: list[tuple[int, ast.AST]] = []
        for candidate in ast.walk(scope):
            if not isinstance(candidate, ast.Assign) or candidate.lineno >= line:
                continue
            if not self._assignment_can_reach_line(candidate, line, scope):
                continue
            for target in candidate.targets:
                if not isinstance(target, ast.Subscript):
                    continue
                if _qualified_name(target.value) != container:
                    continue
                if ast.dump(target.slice, include_attributes=False) == expected_slice:
                    matches.append((candidate.lineno, candidate.value))
        return max(matches, key=lambda item: item[0])[1] if matches else None

    def _source_from_call(self, node: ast.Call) -> SourceEvidence | None:
        match = _matches_suffix(_qualified_name(node.func), _SOURCE_CALL_SUFFIXES)
        if match is None:
            name = _qualified_name(node.func)
            if name == "sys.argv" or (isinstance(node.func, ast.Subscript) and name == "sys.argv"):
                source_type = "command_line_argument"
            else:
                return None
        else:
            source_type = match[1]
        return SourceEvidence(
            expression=_safe_expression(node),
            source_type=source_type,
            user_controlled=True,
            file_path=self.finding.file_path,
            line=node.lineno,
            confidence="high",
        )

    def _config_get_value(self, node: ast.Call, scope: ast.AST) -> ast.AST | None:
        """Resolve a preceding ``ConfigParser.set`` for the same literal key."""
        name = _qualified_name(node.func)
        if not name or not name.endswith(".get") or len(node.args) < 2:
            return None
        receiver = name.rsplit(".", 1)[0]
        section = self._constant_value(node.args[0], node.lineno, scope)
        key = self._constant_value(node.args[1], node.lineno, scope)
        if section is _UNRESOLVED_CONSTANT or key is _UNRESOLVED_CONSTANT:
            return None
        matches: list[tuple[int, ast.AST]] = []
        for candidate in ast.walk(scope):
            if not isinstance(candidate, ast.Call) or candidate.lineno >= node.lineno:
                continue
            candidate_name = _qualified_name(candidate.func)
            if candidate_name != f"{receiver}.set" or len(candidate.args) < 3:
                continue
            candidate_section = self._constant_value(
                candidate.args[0], candidate.lineno, scope
            )
            candidate_key = self._constant_value(
                candidate.args[1], candidate.lineno, scope
            )
            if candidate_section == section and candidate_key == key:
                matches.append((candidate.lineno, candidate.args[2]))
        return max(matches, key=lambda item: item[0])[1] if matches else None

    def _local_source(self, node: ast.AST, source_type: str = "local_value") -> SourceEvidence:
        return SourceEvidence(
            expression=_safe_expression(node),
            source_type=source_type,
            user_controlled=False,
            file_path=self.finding.file_path,
            line=getattr(node, "lineno", None),
            confidence="high",
        )

    def _origin(
        self,
        node: ast.AST | None,
        *,
        scope: ast.AST,
        line: int,
        control_overrides: dict[str, bool | None],
        seen: frozenset[str] = frozenset(),
    ) -> _Origin:
        if node is None:
            return _Origin(None, (), (), (), None)
        if isinstance(node, ast.Constant):
            source = self._local_source(node, "local_constant")
            return _Origin(source, (), (), (), False)
        if isinstance(node, ast.Call):
            direct_source = self._source_from_call(node)
            if direct_source:
                step = self._step(1, "source", node)
                return _Origin(direct_source, (step,), (), (), True)

            name = _qualified_name(node.func) or "<callable>"
            config_value = self._config_get_value(node, scope)
            if config_value is not None:
                return self._origin(
                    config_value,
                    scope=scope,
                    line=getattr(config_value, "lineno", node.lineno),
                    control_overrides=control_overrides,
                    seen=seen,
                )
            sanitizer = _matches_suffix(name, _KNOWN_SANITIZER_SUFFIXES)
            is_custom = any(marker in name.lower() for marker in _CUSTOM_CONTROL_MARKERS)
            if sanitizer or is_custom:
                inner = node.args[0] if node.args else None
                origin = self._origin(
                    inner,
                    scope=scope,
                    line=node.lineno,
                    control_overrides=control_overrides,
                    seen=seen,
                )
                effective = True if sanitizer else control_overrides.get(name)
                control = SecurityControlEvidence(
                    symbol=name,
                    control_type=sanitizer[1] if sanitizer else "custom_sanitizer",
                    on_taint_path=True,
                    protects_target=effective if effective is not None else None,
                    effective=effective,
                    confidence="high" if effective is not None else "low",
                )
                unresolved = origin.unresolved_symbols
                if effective is None:
                    unresolved = tuple(dict.fromkeys((*unresolved, name)))
                reaches = False if effective is True else origin.source_reaches_sink
                return _Origin(
                    origin.source,
                    (*origin.steps, self._step(len(origin.steps) + 1, "security_control", node)),
                    (*origin.controls, control),
                    unresolved,
                    reaches,
                    origin.parameter_name,
                )

            if node.args:
                transparent_receiver = (
                    node.func.value
                    if isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"encode", "decode"}
                    else node.args[0]
                )
                inner = self._origin(
                    transparent_receiver,
                    scope=scope,
                    line=node.lineno,
                    control_overrides=control_overrides,
                    seen=seen,
                )
                if inner.source is not None or inner.parameter_name is not None:
                    is_transparent = any(
                        name == suffix or name.endswith(f".{suffix}")
                        for suffix in _KNOWN_TRANSPARENT_CALL_SUFFIXES
                    )
                    if is_transparent:
                        return _Origin(
                            inner.source,
                            (*inner.steps, self._step(len(inner.steps) + 1, "transform", node)),
                            inner.controls,
                            inner.unresolved_symbols,
                            inner.source_reaches_sink,
                            inner.parameter_name,
                        )
                    unresolved = tuple(dict.fromkeys((*inner.unresolved_symbols, name)))
                    return _Origin(
                        inner.source,
                        (*inner.steps, self._step(len(inner.steps) + 1, "custom_call", node)),
                        inner.controls,
                        unresolved,
                        None,
                        inner.parameter_name,
                    )
            return _Origin(None, (), (), (name,), None)

        if isinstance(node, ast.IfExp):
            condition = self._constant_value(node.test, line, scope)
            if isinstance(condition, bool):
                selected = node.body if condition else node.orelse
                return self._origin(
                    selected,
                    scope=scope,
                    line=line,
                    control_overrides=control_overrides,
                    seen=seen,
                )
            body = self._origin(
                node.body,
                scope=scope,
                line=line,
                control_overrides=control_overrides,
                seen=seen,
            )
            other = self._origin(
                node.orelse,
                scope=scope,
                line=line,
                control_overrides=control_overrides,
                seen=seen,
            )
            if any(
                origin.source is not None and origin.source.user_controlled
                for origin in (body, other)
            ):
                return body if body.source and body.source.user_controlled else other
            return body if body.source is not None else other

        if isinstance(node, ast.Attribute):
            name = _qualified_name(node)
            if name in {
                "request.path",
                "request.query_string",
                "request.data",
                "request.json",
                "request.remote_addr",
            }:
                source = SourceEvidence(
                    expression=_safe_expression(node),
                    source_type="http_request_attribute",
                    user_controlled=True,
                    file_path=self.finding.file_path,
                    line=node.lineno,
                    confidence="high",
                )
                return _Origin(source, (self._step(1, "source", node),), (), (), True)

        if isinstance(node, ast.Name):
            if node.id in seen:
                return _Origin(None, (), (), (node.id,), None)
            assignment = self._assignment_before(node.id, line, scope)
            if assignment is not None:
                origin = self._origin(
                    assignment,
                    scope=scope,
                    line=getattr(assignment, "lineno", line),
                    control_overrides=control_overrides,
                    seen=seen | {node.id},
                )
                return _Origin(
                    origin.source,
                    (*origin.steps, self._step(len(origin.steps) + 1, "assignment", node)),
                    origin.controls,
                    origin.unresolved_symbols,
                    origin.source_reaches_sink,
                    origin.parameter_name,
                )
            for loop in ast.walk(scope):
                if not isinstance(loop, (ast.For, ast.AsyncFor)) or loop.lineno >= line:
                    continue
                if node.id not in _assigned_names(loop.target):
                    continue
                loop_origin = self._origin(
                    loop.iter,
                    scope=scope,
                    line=loop.lineno,
                    control_overrides=control_overrides,
                    seen=seen | {node.id},
                )
                if loop_origin.source is not None:
                    return loop_origin
            if node.id in self._parameters(self._target_function):
                return _Origin(None, (), (), (node.id,), None, node.id)
            return _Origin(None, (), (), (node.id,), None)

        if isinstance(node, ast.Subscript):
            name = _qualified_name(node.value)
            if name in {"request.args", "request.form", "request.headers", "request.cookies", "os.environ", "sys.argv"}:
                source_type = "command_line_argument" if name == "sys.argv" else "request_or_environment_input"
                source = SourceEvidence(
                    expression=_safe_expression(node),
                    source_type=source_type,
                    user_controlled=True,
                    file_path=self.finding.file_path,
                    line=node.lineno,
                    confidence="high",
                )
                return _Origin(source, (self._step(1, "source", node),), (), (), True)
            assignment = self._subscript_assignment_before(node, line, scope)
            if assignment is not None:
                return self._origin(
                    assignment,
                    scope=scope,
                    line=getattr(assignment, "lineno", line),
                    control_overrides=control_overrides,
                    seen=seen,
                )
            if isinstance(node.value, ast.Name):
                augmented_values = [
                    candidate.value
                    for candidate in ast.walk(scope)
                    if isinstance(candidate, ast.AugAssign)
                    and candidate.lineno < line
                    and node.value.id in _assigned_names(candidate.target)
                ]
                for value in augmented_values:
                    augmented_origin = self._origin(
                        value,
                        scope=scope,
                        line=getattr(value, "lineno", line),
                        control_overrides=control_overrides,
                        seen=seen,
                    )
                    if (
                        augmented_origin.source is not None
                        and augmented_origin.source.user_controlled
                    ):
                        return augmented_origin
            return self._origin(
                node.value,
                scope=scope,
                line=line,
                control_overrides=control_overrides,
                seen=seen,
            )

        if isinstance(node, ast.BinOp):
            left = self._origin(
                node.left,
                scope=scope,
                line=line,
                control_overrides=control_overrides,
                seen=seen,
            )
            right = self._origin(
                node.right,
                scope=scope,
                line=line,
                control_overrides=control_overrides,
                seen=seen,
            )
            if left.source and left.source.user_controlled:
                return left
            if right.source and right.source.user_controlled:
                return right
            return left if left.source else right

        if isinstance(node, ast.JoinedStr):
            origins = [
                self._origin(
                    value.value,
                    scope=scope,
                    line=line,
                    control_overrides=control_overrides,
                    seen=seen,
                )
                for value in node.values
                if isinstance(value, ast.FormattedValue)
            ]
            for origin in origins:
                if origin.source is not None and origin.source.user_controlled:
                    return origin
            for origin in origins:
                if origin.source is not None or origin.parameter_name is not None:
                    return origin
            return _Origin(self._local_source(node, "formatted_local_value"), (), (), (), False)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            origins = [
                self._origin(
                    item,
                    scope=scope,
                    line=line,
                    control_overrides=control_overrides,
                    seen=seen,
                )
                for item in node.elts
            ]
            for origin in origins:
                if origin.source is not None and origin.source.user_controlled:
                    return origin
            for origin in origins:
                if origin.source is not None or origin.parameter_name is not None:
                    return origin
            return _Origin(None, (), (), (), None)

        return _Origin(self._local_source(node), (), (), (), False)

    def _step(self, order: int, kind: str, node: ast.AST) -> TaintStep:
        return TaintStep(
            order=order,
            kind=kind,
            expression=_safe_expression(node),
            function_id=self.target_function_id(),
            file_path=self.finding.file_path,
            line=getattr(node, "lineno", None),
        )

    def _dependency_names(
        self,
        node: ast.AST | None,
        *,
        line: int,
        scope: ast.AST,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
    ) -> set[str]:
        """Collect bounded identifier dependencies for guard-to-sink matching."""
        if node is None or depth >= 5:
            return set()
        names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
        expanded = set(names)
        for name in names - set(seen):
            assignment = self._assignment_before(name, line, scope)
            if assignment is not None:
                expanded.update(
                    self._dependency_names(
                        assignment,
                        line=getattr(assignment, "lineno", line),
                        scope=scope,
                        depth=depth + 1,
                        seen=seen | {name},
                    )
                )
        return expanded

    def _effective_exit_guards(
        self,
        dangerous_arg: ast.AST | None,
        *,
        sink_line: int,
        sink_type: str,
    ) -> tuple[SecurityControlEvidence, ...]:
        """Recognize a narrow early-exit guard that protects a path sink."""
        if sink_type != "file_access" or dangerous_arg is None:
            return ()
        scope = self._analysis_scope()
        dependencies = self._dependency_names(
            dangerous_arg,
            line=sink_line,
            scope=scope,
        )
        for candidate in ast.walk(scope):
            if (
                not isinstance(candidate, ast.If)
                or candidate.lineno >= sink_line
                or not any(isinstance(item, (ast.Return, ast.Raise)) for item in candidate.body)
            ):
                continue
            condition_names = {
                item.id for item in ast.walk(candidate.test) if isinstance(item, ast.Name)
            }
            blocked_parent_reference = any(
                isinstance(item, ast.Constant)
                and isinstance(item.value, str)
                and ".." in item.value
                for item in ast.walk(candidate.test)
            )
            if dependencies & condition_names and blocked_parent_reference:
                return (
                    SecurityControlEvidence(
                        symbol="early_exit_path_validation",
                        control_type="guard_parent_path_rejection",
                        on_taint_path=True,
                        protects_target=True,
                        effective=True,
                        confidence="high",
                    ),
                )
        return ()

    @staticmethod
    def _control_matches_sink(control_type: str, sink_type: str) -> bool:
        """Prevent a sanitizer for one vulnerability class from proving another safe."""
        compatible = {
            "output_encoding": {"html_rendering"},
            "html_sanitizer": {"html_rendering"},
            "shell_escaping": {"command_execution"},
            "url_encoding": {"file_access"},
            "type_validation": {
                "command_execution",
                "sql_query",
                "file_access",
                "xpath_query",
            },
        }
        allowed = compatible.get(control_type)
        return allowed is None or sink_type in allowed

    def _find_callers(self, function_name: str) -> list[tuple[ast.Call, ast.AST, ast.AST | None]]:
        callers: list[tuple[ast.Call, ast.AST, ast.AST | None]] = []
        for function in self._functions.values():
            if function is self._target_function:
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    name = _qualified_name(node.func)
                    if name == function_name or (name and name.endswith(f".{function_name}")):
                        callers.append((node, function, node.args[0] if node.args else None))
        return callers

    def _expand_parameter_origin(
        self,
        parameter_name: str,
        control_overrides: dict[str, bool | None],
    ) -> _Origin | None:
        if self._target_function is None:
            return None
        parameters = list(self._target_function.args.posonlyargs) + list(self._target_function.args.args)
        parameter_names = [item.arg for item in parameters]
        if parameter_name not in parameter_names:
            return None
        index = parameter_names.index(parameter_name)
        for call, caller, _ in self._find_callers(self._target_function.name):
            argument = call.args[index] if len(call.args) > index else None
            if argument is None:
                continue
            origin = self._origin(
                argument,
                scope=caller,
                line=call.lineno,
                control_overrides=control_overrides,
            )
            if origin.source is not None:
                caller_id = self._function_id(caller)
                boundary = TaintStep(
                    order=len(origin.steps) + 1,
                    kind="call_boundary",
                    expression=f"{caller_id} -> {self.target_function_id()}",
                    function_id=caller_id,
                    file_path=self.finding.file_path,
                    line=call.lineno,
                )
                return _Origin(
                    origin.source,
                    (*origin.steps, boundary),
                    origin.controls,
                    origin.unresolved_symbols,
                    origin.source_reaches_sink,
                )
        return None

    def build_evidence(
        self,
        *,
        expand_callers: bool = False,
        control_overrides: dict[str, bool | None] | None = None,
    ) -> EvidencePackage:
        """Xây dựng bằng chứng ban đầu hoặc đã mở rộng bằng cùng analysis engine."""
        overrides = control_overrides or {}
        sink_call, sink_type, dangerous_arg, dangerous_conditions = self._find_sink()
        sink_node = sink_call or dangerous_arg
        sink = SinkEvidence(
            expression=_safe_expression(sink_call or dangerous_arg),
            sink_type=sink_type,
            dangerous_argument=_safe_expression(dangerous_arg) if dangerous_arg else None,
            dangerous_conditions=dangerous_conditions,
            file_path=self.finding.file_path,
            line=getattr(sink_node, "lineno", self.finding.start_line),
        ) if sink_node is not None else None

        origin = self._origin(
            dangerous_arg,
            scope=self._analysis_scope(),
            line=getattr(sink_node, "lineno", self.finding.start_line),
            control_overrides=overrides,
        )
        incompatible_controls = tuple(
            control
            for control in origin.controls
            if control.effective is True
            and not self._control_matches_sink(control.control_type, sink_type)
        )
        if incompatible_controls:
            controls = tuple(
                replace(control, effective=False, protects_target=False)
                if control in incompatible_controls
                else control
                for control in origin.controls
            )
            reaches = (
                True
                if origin.source is not None and origin.source.user_controlled
                else origin.source_reaches_sink
            )
            origin = _Origin(
                origin.source,
                origin.steps,
                controls,
                origin.unresolved_symbols,
                reaches,
                origin.parameter_name,
            )
        guard_controls = self._effective_exit_guards(
            dangerous_arg,
            sink_line=getattr(sink_node, "lineno", self.finding.start_line),
            sink_type=sink_type,
        )
        if guard_controls:
            origin = _Origin(
                origin.source,
                origin.steps,
                (*origin.controls, *guard_controls),
                origin.unresolved_symbols,
                origin.source_reaches_sink,
                origin.parameter_name,
            )
        interprocedural = False
        if expand_callers and origin.parameter_name:
            expanded = self._expand_parameter_origin(origin.parameter_name, overrides)
            if expanded:
                origin = _Origin(
                    expanded.source,
                    (*expanded.steps, *origin.steps),
                    (*expanded.controls, *origin.controls),
                    tuple(symbol for symbol in origin.unresolved_symbols if symbol != origin.parameter_name),
                    expanded.source_reaches_sink,
                )
                interprocedural = True

        steps = list(origin.steps)
        if sink_node is not None:
            steps.append(self._step(len(steps) + 1, "sink", sink_node))
        steps = [
            TaintStep(
                order=index,
                kind=step.kind,
                expression=step.expression,
                function_id=step.function_id,
                file_path=step.file_path,
                line=step.line,
            )
            for index, step in enumerate(steps, start=1)
        ]

        unresolved = tuple(dict.fromkeys(origin.unresolved_symbols))
        source_resolved = origin.source is not None
        sink_resolved = sink is not None
        controls_resolved = all(control.effective is not None for control in origin.controls)
        path_complete = source_resolved and sink_resolved and controls_resolved and not unresolved
        reachability_resolved = origin.source_reaches_sink is not None and path_complete
        call_chain_complete = origin.parameter_name is None or interprocedural

        missing: list[str] = []
        if not source_resolved:
            missing.append("SOURCE_NOT_RESOLVED")
        if not path_complete:
            missing.append("TAINT_PATH_INCOMPLETE")
        if not call_chain_complete:
            missing.append("CALL_CHAIN_INCOMPLETE")
        if not reachability_resolved:
            missing.append("REACHABILITY_NOT_RESOLVED")
        if any(control.effective is None for control in origin.controls):
            missing.append("CUSTOM_SECURITY_CONTROL_NOT_ANALYZED")

        complete = (
            source_resolved
            and sink_resolved
            and path_complete
            and call_chain_complete
            and reachability_resolved
            and not unresolved
        )
        limitations = () if complete else ("STATIC_PYTHON_ANALYSIS_IS_CONSERVATIVE",)
        category = self._finding_category()
        relevant_code = self.sanitized_context.sanitized_snippet or "<context_unavailable>"
        return EvidencePackage(
            finding_id=self.finding.finding_instance_id,
            finding=FindingEvidence(
                rule_id=self.finding.rule_id,
                category=category,
                severity=self.finding.severity.value,
                message=self.finding.message,
                file_path=self.finding.file_path,
                start_line=self.finding.start_line,
                end_line=self.finding.end_line,
            ),
            relevant_code=RelevantCodeEvidence(
                scope_type=self.sanitized_context.context_strategy.value,
                function_name=self.sanitized_context.enclosing_function,
                class_name=self.sanitized_context.enclosing_class,
                start_line=self.sanitized_context.context_start_line,
                end_line=self.sanitized_context.context_end_line,
                code=relevant_code,
            ),
            source=origin.source,
            sink=sink,
            taint_path=TaintPathEvidence(
                path_type="interprocedural" if interprocedural else "local",
                steps=tuple(steps),
                source_reaches_sink=origin.source_reaches_sink,
                complete=path_complete,
            ),
            security_controls=origin.controls,
            context_completeness=ContextCompleteness(
                status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.PARTIAL,
                source_resolved=source_resolved,
                sink_resolved=sink_resolved,
                taint_path_complete=path_complete,
                call_chain_complete=call_chain_complete,
                reachability_resolved=reachability_resolved,
                unresolved_symbols=unresolved,
                missing_information=tuple(missing),
                limitations=limitations,
            ),
            provenance=(f"python_ast:{self.finding.file_path}",),
        )

    def _finding_category(self) -> str:
        for key in ("category", "cwe", "owasp"):
            value = self.finding.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list) and value:
                return ", ".join(str(item) for item in value[:3])
        return self.finding.finding_type.value

    def caller_evidence(self, function_id: str) -> tuple[list[dict[str, object]], bool]:
        """Trả về dữ kiện cấu trúc về caller của hàm trong đơn vị phân tích này."""
        function = self._functions.get(function_id)
        if function is None:
            return [], False
        callers = self._find_callers(function.name)
        return [
            {
                "function_id": self._function_id(caller),
                "file_path": self.finding.file_path,
                "line": call.lineno,
            }
            for call, caller, _ in callers
        ], bool(callers)

    def symbol_evidence(self, qualified_name: str) -> tuple[dict[str, object], bool]:
        """Trả về cấu trúc symbol có giới hạn mà không có mã nguồn hàm."""
        matches = [
            (function_id, function)
            for function_id, function in self._functions.items()
            if function_id == qualified_name or function_id.endswith(f"::{qualified_name}") or function.name == qualified_name
        ]
        if len(matches) != 1:
            return {}, False
        function_id, function = matches[0]
        return {
            "qualified_name": function_id,
            "file_path": self.finding.file_path,
            "line": function.lineno,
            "parameters": [argument.arg for argument in function.args.args],
            "calls": sorted(
                {
                    name
                    for node in ast.walk(function)
                    if isinstance(node, ast.Call)
                    if (name := _qualified_name(node.func)) is not None
                }
            )[:20],
        }, True

    def symbol_value_evidence(self, symbol: str) -> tuple[dict[str, object], bool]:
        """Mô tả giá trị symbol mà không trả về literal value."""
        value = self._assignment_before(symbol, self.finding.start_line + 1, self._analysis_scope())
        if value is None:
            return {}, False
        return {
            "symbol": symbol,
            "file_path": self.finding.file_path,
            "value_kind": value.__class__.__name__,
            "is_constant": isinstance(value, ast.Constant),
            "line": getattr(value, "lineno", None),
        }, True

    def analyze_security_control(self, symbol: str) -> bool | None:
        """Phân loại thận trọng sanitizer tự tạo trong cùng file."""
        matches = [function for function in self._functions.values() if function.name == symbol.split(".")[-1]]
        if len(matches) != 1:
            return None
        function = matches[0]
        parameters = self._parameters(function)
        returns = [node for node in ast.walk(function) if isinstance(node, ast.Return) and node.value is not None]
        if not returns:
            return None
        effective = False
        for return_node in returns:
            value = return_node.value
            if isinstance(value, ast.Call):
                if _matches_suffix(_qualified_name(value.func), _KNOWN_SANITIZER_SUFFIXES):
                    effective = True
                else:
                    return None
            elif isinstance(value, ast.Name) and value.id in parameters:
                continue
            else:
                return None
        return effective
