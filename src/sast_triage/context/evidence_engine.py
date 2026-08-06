"""Bounded Python AST analysis used to build provider-safe evidence.

The engine never executes target code. Raw source is retained only on this
internal object; all expressions leaving it are structural and omit literal
values.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

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

_SOURCE_CALL_SUFFIXES: dict[str, str] = {
    "input": "console_input",
    "request.args.get": "http_query_parameter",
    "request.form.get": "http_form_parameter",
    "request.get_json": "http_json_body",
    "request.cookies.get": "http_cookie",
    "request.headers.get": "http_header",
    "request.values.get": "http_request_value",
    "request.files.get": "http_file_upload",
    "os.environ.get": "environment_variable",
}

_SINK_CALL_SUFFIXES: dict[str, str] = {
    "execute": "sql_query",
    "executemany": "sql_query",
    "eval": "code_execution",
    "exec": "code_execution",
    "os.system": "command_execution",
    "subprocess.run": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.Popen": "command_execution",
    "render_template_string": "html_rendering",
    "mark_safe": "html_rendering",
    "Markup": "html_rendering",
    "xpath": "xpath_query",
    "fromstring": "xml_parsing",
    "parse": "xml_parsing",
    "open": "file_access",
}

_KNOWN_SANITIZER_SUFFIXES: dict[str, str] = {
    "html.escape": "output_encoding",
    "markupsafe.escape": "output_encoding",
    "bleach.clean": "html_sanitizer",
    "shlex.quote": "shell_escaping",
    "urllib.parse.quote": "url_encoding",
    "int": "type_validation",
    "float": "type_validation",
}

_CUSTOM_CONTROL_MARKERS = (
    "sanitize",
    "sanitise",
    "validate",
    "escape",
    "clean",
    "verify",
    "check",
)


@dataclass(frozen=True, slots=True)
class _Origin:
    source: SourceEvidence | None
    steps: tuple[TaintStep, ...]
    controls: tuple[SecurityControlEvidence, ...]
    unresolved_symbols: tuple[str, ...]
    source_reaches_sink: bool | None
    parameter_name: str | None = None


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _safe_expression(node: ast.AST | None) -> str:
    """Render AST structure without literal values or source text."""
    if node is None:
        return "<none>"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified_name(node) or "<attribute>"
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return "<string_literal>"
        if isinstance(node.value, bool):
            return "<boolean_literal>"
        if node.value is None:
            return "<none_literal>"
        if isinstance(node.value, (int, float, complex)):
            return "<number_literal>"
        return "<literal>"
    if isinstance(node, ast.Call):
        name = _qualified_name(node.func) or "<callable>"
        args = ", ".join(_safe_expression(arg) for arg in node.args[:3])
        if len(node.args) > 3:
            args = f"{args}, ..."
        return f"{name}({args})"
    if isinstance(node, ast.Subscript):
        return f"{_safe_expression(node.value)}[<index>]"
    if isinstance(node, ast.BinOp):
        return f"{_safe_expression(node.left)} <operator> {_safe_expression(node.right)}"
    if isinstance(node, ast.JoinedStr):
        return "<formatted_string>"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = ", ".join(_safe_expression(item) for item in node.elts[:3])
        return f"<{node.__class__.__name__.lower()}>({items})"
    if isinstance(node, ast.Dict):
        return "<dictionary_expression>"
    if isinstance(node, ast.UnaryOp):
        return f"<unary> {_safe_expression(node.operand)}"
    if isinstance(node, ast.Compare):
        return "<comparison_expression>"
    return f"<{node.__class__.__name__.lower()}_expression>"


def _matches_suffix(name: str | None, suffixes: dict[str, str]) -> tuple[str, str] | None:
    if name is None:
        return None
    for suffix, kind in suffixes.items():
        if name == suffix or name.endswith(f".{suffix}"):
            return suffix, kind
    return None


def _assigned_names(target: ast.AST) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        return tuple(
            name
            for item in target.elts
            for name in _assigned_names(item)
        )
    return ()


class CoreAnalysisEngine:
    """Create bounded, structural evidence from one Python source file."""

    def __init__(
        self,
        finding: NormalizedFinding,
        source: SourceReadResult,
        sanitized_context: SanitizedContext,
    ) -> None:
        """Initialize an internal analyzer for one finding and source file."""
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
        """Return the stable target function identifier, when available."""
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
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and node.lineno < line:
                if any(name in _assigned_names(target) for target in node.targets):
                    matches.append((node.lineno, node.value))
            elif (
                isinstance(node, ast.AnnAssign)
                and node.value is not None
                and node.lineno < line
                and name in _assigned_names(node.target)
            ):
                matches.append((node.lineno, node.value))
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
                inner = self._origin(
                    node.args[0],
                    scope=scope,
                    line=node.lineno,
                    control_overrides=control_overrides,
                    seen=seen,
                )
                if inner.source is not None or inner.parameter_name is not None:
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
        """Build initial or expanded evidence using the same analysis engine."""
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
        """Return structural caller facts for a function in this analysis unit."""
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
        """Return bounded symbol structure without function source."""
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
        """Describe a symbol value without returning the literal value."""
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
        """Conservatively classify a same-file custom sanitizer."""
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
