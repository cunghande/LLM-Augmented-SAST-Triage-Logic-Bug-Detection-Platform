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
class RepositoryEvidenceIndex:
    """Immutable structured index shared by sequential Module 1/Module 2 work."""

    repository_identifier: str
    components: tuple[RepositoryComponent, ...]
    functions: tuple[FunctionSymbol, ...]
    summaries: tuple[FunctionSummary, ...]
    calls: tuple[CallSite, ...]
    sinks: tuple[SinkCandidate, ...]
    skipped_files: int = 0

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
) -> RepositoryEvidenceIndex:
    """Build a bounded monorepo-aware index without retaining raw source text."""
    root = repository_root.resolve()
    marker_roots = {"."}
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
    for number, path in enumerate(sorted(root.rglob("*.py"))):
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
    return RepositoryEvidenceIndex(
        repository_identifier=repository_identifier,
        components=components,
        functions=frozen_functions,
        summaries=tuple(summaries),
        calls=tuple(calls),
        sinks=tuple(sinks),
        skipped_files=skipped,
    )
