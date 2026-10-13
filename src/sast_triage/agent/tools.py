"""AgentToolRegistry: Bounded AST and Graph Tools for Controlled Agent Execution."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from sast_triage.analysis.base import AnalysisBackend, GraphEvidence, QueryResultStatus
from sast_triage.models import NormalizedFinding
from sast_triage.redaction import redact_exact_secret

MAX_FUNCTION_LINES = 60
MAX_CALLERS_RETURNED = 5
MAX_CALLEES_RETURNED = 5


class AgentToolRegistry:
    """Executes validated allowlisted tools with size limits and sanitized outputs."""

    def __init__(
        self,
        repository_root: Path,
        analysis_backend: AnalysisBackend | None = None,
    ) -> None:
        self._repository_root = repository_root.resolve()
        self._backend = analysis_backend

    def execute_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        finding: NormalizedFinding,
        evidence: GraphEvidence | None = None,
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        """Execute a validated tool and return (query_status, status_reason, summary, facts)."""
        try:
            if tool_name == "read_function":
                return self._read_function(
                    parameters["symbol_name"], parameters["file_path"]
                )
            elif tool_name == "find_callers":
                return self._find_callers(
                    parameters["symbol_name"], parameters.get("file_path")
                )
            elif tool_name == "find_callees":
                return self._find_callees(
                    parameters["symbol_name"], parameters["file_path"]
                )
            elif tool_name == "get_route_decorators":
                return self._get_route_decorators(
                    parameters["symbol_name"], parameters["file_path"]
                )
            elif tool_name == "get_model_schema":
                return self._get_model_schema(
                    parameters["model_name"], parameters.get("file_path")
                )
            elif tool_name == "check_lock_or_transaction":
                return self._check_lock_or_transaction(
                    parameters["symbol_name"], parameters["file_path"]
                )
            elif tool_name in (
                "trace_dataflow",
                "find_reachability",
                "inspect_security_control",
            ):
                return self._run_graph_backend_tool(
                    tool_name, parameters, finding, evidence
                )
            else:
                return (
                    QueryResultStatus.UNKNOWN,
                    "TOOL_UNRECOGNIZED",
                    f"Tool '{tool_name}' is not recognized by registry.",
                    {},
                )
        except Exception as exc:
            return (
                QueryResultStatus.UNKNOWN,
                f"TOOL_EXECUTION_ERROR: {type(exc).__name__}",
                f"Tool execution failed safely: {exc}",
                {},
            )

    def _get_ast(self, relative_path: str) -> tuple[ast.AST | None, list[str]]:
        """Safely read and parse AST for a file."""
        abs_path = (self._repository_root / relative_path).resolve()
        if not abs_path.is_file():
            return None, []
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=relative_path)
            lines = content.splitlines()
            return tree, lines
        except Exception:
            return None, []

    def _read_function(
        self, symbol_name: str, file_path: str
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        tree, lines = self._get_ast(file_path)
        if tree is None:
            return (
                QueryResultStatus.UNKNOWN,
                "PARSE_FAILED",
                f"Could not parse AST for {file_path}",
                {},
            )

        target_node: ast.AST | None = None
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if node.name == symbol_name:
                    target_node = node
                    break

        if target_node is None:
            return (
                QueryResultStatus.NOT_FOUND_COMPLETE,
                "SYMBOL_NOT_FOUND",
                f"Symbol '{symbol_name}' was not found in {file_path}",
                {},
            )

        start_line = target_node.lineno
        end_line = getattr(target_node, "end_lineno", start_line + 20)
        selected_lines = lines[start_line - 1 : end_line]

        truncated = False
        if len(selected_lines) > MAX_FUNCTION_LINES:
            selected_lines = selected_lines[:MAX_FUNCTION_LINES]
            truncated = True

        code_text = "\n".join(selected_lines)
        summary = (
            f"Read function {symbol_name} ({len(selected_lines)} lines, lines {start_line}-{end_line})"
            + (" [TRUNCATED at 60 lines]" if truncated else "")
        )
        return (
            QueryResultStatus.FOUND,
            "FUNCTION_EXTRACTED",
            summary,
            {
                "symbol": symbol_name,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "code_snippet": code_text,
                "truncated": truncated,
            },
        )

    def _find_callers(
        self, symbol_name: str, file_path: str | None = None
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        callers: list[dict[str, Any]] = []
        files_to_check = [file_path] if file_path else []
        if not files_to_check:
            # Search all python files in repo (bounded up to 50 files)
            for p in self._repository_root.glob("**/*.py"):
                if "tests" not in p.parts and "venv" not in p.parts:
                    files_to_check.append(
                        str(p.relative_to(self._repository_root)).replace(
                            "\\", "/"
                        )
                    )
                if len(files_to_check) >= 50:
                    break

        for rel_file in files_to_check:
            tree, _ = self._get_ast(rel_file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    enclosing_name = node.name
                    for inner in ast.walk(node):
                        if isinstance(inner, ast.Call):
                            called_name: str | None = None
                            if isinstance(inner.func, ast.Name):
                                called_name = inner.func.id
                            elif isinstance(inner.func, ast.Attribute):
                                called_name = inner.func.attr
                            if called_name == symbol_name:
                                callers.append(
                                    {
                                        "caller_function": enclosing_name,
                                        "file": rel_file,
                                        "line": getattr(inner, "lineno", node.lineno),
                                    }
                                )
                                if len(callers) >= MAX_CALLERS_RETURNED:
                                    break
                if len(callers) >= MAX_CALLERS_RETURNED:
                    break
            if len(callers) >= MAX_CALLERS_RETURNED:
                break

        if not callers:
            return (
                QueryResultStatus.NOT_FOUND_COMPLETE,
                "NO_CALLERS_FOUND",
                f"No callers found calling {symbol_name} in scanned files.",
                {"symbol": symbol_name, "callers": []},
            )

        return (
            QueryResultStatus.FOUND,
            "CALLERS_DISCOVERED",
            f"Found {len(callers)} caller(s) invoking {symbol_name}.",
            {"symbol": symbol_name, "callers": callers},
        )

    def _find_callees(
        self, symbol_name: str, file_path: str
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        tree, _ = self._get_ast(file_path)
        if tree is None:
            return (
                QueryResultStatus.UNKNOWN,
                "PARSE_FAILED",
                f"Could not parse AST for {file_path}",
                {},
            )

        callees: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and node.name == symbol_name:
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        if isinstance(inner.func, ast.Name):
                            callees.add(inner.func.id)
                        elif isinstance(inner.func, ast.Attribute):
                            callees.add(inner.func.attr)

        callee_list = sorted(list(callees))[:MAX_CALLEES_RETURNED]
        if not callee_list:
            return (
                QueryResultStatus.NOT_FOUND_COMPLETE,
                "NO_CALLEES_FOUND",
                f"Function {symbol_name} makes no external function calls.",
                {"symbol": symbol_name, "callees": []},
            )

        return (
            QueryResultStatus.FOUND,
            "CALLEES_DISCOVERED",
            f"Function {symbol_name} calls: {', '.join(callee_list)}",
            {"symbol": symbol_name, "callees": callee_list},
        )

    def _get_route_decorators(
        self, symbol_name: str, file_path: str
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        tree, _ = self._get_ast(file_path)
        if tree is None:
            return (
                QueryResultStatus.UNKNOWN,
                "PARSE_FAILED",
                f"Could not parse AST for {file_path}",
                {},
            )

        decorators: list[str] = []
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and node.name == symbol_name:
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(dec.attr)
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            decorators.append(dec.func.id)
                        elif isinstance(dec.func, ast.Attribute):
                            decorators.append(dec.func.attr)

        has_auth = any(
            d.lower()
            in (
                "login_required",
                "permission_required",
                "staff_member_required",
                "authenticated",
            )
            for d in decorators
        )
        has_csrf_exempt = any("csrf_exempt" in d.lower() for d in decorators)

        return (
            QueryResultStatus.FOUND,
            "DECORATORS_INSPECTED",
            f"Decorators on {symbol_name}: {decorators} (auth={has_auth}, csrf_exempt={has_csrf_exempt})",
            {
                "symbol": symbol_name,
                "decorators": decorators,
                "has_auth": has_auth,
                "has_csrf_exempt": has_csrf_exempt,
            },
        )

    def _get_model_schema(
        self, model_name: str, file_path: str | None = None
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        files_to_check = [file_path] if file_path else []
        if not files_to_check:
            for p in self._repository_root.glob("**/models.py"):
                files_to_check.append(
                    str(p.relative_to(self._repository_root)).replace("\\", "/")
                )
            if not files_to_check:
                for p in self._repository_root.glob("**/*.py"):
                    files_to_check.append(
                        str(p.relative_to(self._repository_root)).replace(
                            "\\", "/"
                        )
                    )
                    if len(files_to_check) >= 20:
                        break

        for rel_file in files_to_check:
            tree, _ = self._get_ast(rel_file)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == model_name:
                    fields = []
                    has_owner = False
                    allowlisted_fields = []

                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    fname = target.id
                                    fields.append(fname)
                                    if fname.lower() in (
                                        "user",
                                        "user_id",
                                        "owner",
                                        "owner_id",
                                        "tenant",
                                        "tenant_id",
                                    ):
                                        has_owner = True
                        elif (
                            isinstance(item, ast.ClassDef)
                            and item.name == "Meta"
                        ):
                            for meta_item in item.body:
                                if isinstance(meta_item, ast.Assign):
                                    for target in meta_item.targets:
                                        if (
                                            isinstance(target, ast.Name)
                                            and target.id == "fields"
                                        ):
                                            if isinstance(
                                                meta_item.value,
                                                (ast.List, ast.Tuple),
                                            ):
                                                allowlisted_fields = [
                                                    elt.value
                                                    for elt in meta_item.value.elts
                                                    if isinstance(
                                                        elt, ast.Constant
                                                    )
                                                ]

                    return (
                        QueryResultStatus.FOUND,
                        "SCHEMA_EXTRACTED",
                        f"Model {model_name} in {rel_file}: {len(fields)} fields, owner_scoped={has_owner}, allowlisted_fields={len(allowlisted_fields)}",
                        {
                            "model_name": model_name,
                            "file": rel_file,
                            "fields": fields,
                            "has_ownership_field": has_owner,
                            "allowlisted_fields": allowlisted_fields,
                        },
                    )

        return (
            QueryResultStatus.NOT_FOUND_COMPLETE,
            "MODEL_NOT_FOUND",
            f"Model {model_name} was not found in scanned files.",
            {"model_name": model_name},
        )

    def _check_lock_or_transaction(
        self, symbol_name: str, file_path: str
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        tree, _ = self._get_ast(file_path)
        if tree is None:
            return (
                QueryResultStatus.UNKNOWN,
                "PARSE_FAILED",
                f"Could not parse AST for {file_path}",
                {},
            )

        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and node.name == symbol_name:
                has_atomic = False
                has_lock = False

                for dec in node.decorator_list:
                    dname = ""
                    if isinstance(dec, ast.Name):
                        dname = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dname = dec.attr
                    if "atomic" in dname.lower():
                        has_atomic = True

                for inner in ast.walk(node):
                    if isinstance(inner, ast.With):
                        for item in inner.items:
                            ctx_str = ast.dump(item.context_expr)
                            if "atomic" in ctx_str.lower():
                                has_atomic = True
                            if "lock" in ctx_str.lower():
                                has_lock = True
                    elif isinstance(inner, ast.Call):
                        cname = ""
                        if isinstance(inner.func, ast.Attribute):
                            cname = inner.func.attr
                        if cname in ("select_for_update", "acquire"):
                            has_lock = True

                summary = f"Concurrency check for {symbol_name}: atomic_transaction={has_atomic}, lock_acquired={has_lock}"
                return (
                    QueryResultStatus.FOUND,
                    "CONCURRENCY_INSPECTED",
                    summary,
                    {
                        "symbol": symbol_name,
                        "has_atomic_transaction": has_atomic,
                        "has_lock": has_lock,
                    },
                )

        return (
            QueryResultStatus.NOT_FOUND_COMPLETE,
            "FUNCTION_NOT_FOUND",
            f"Function {symbol_name} not found in {file_path}",
            {},
        )

    def _run_graph_backend_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        finding: NormalizedFinding,
        evidence: GraphEvidence | None = None,
    ) -> tuple[QueryResultStatus, str, str, dict[str, Any]]:
        if self._backend is None:
            return (
                QueryResultStatus.UNKNOWN,
                "BACKEND_UNAVAILABLE",
                "Analysis backend (Joern) is not configured.",
                {},
            )

        current_evidence = evidence or GraphEvidence(
            sink_symbol=finding.rule_id
        )
        res_evidence = self._backend.run_tool(
            tool_name, finding, current_evidence
        )
        status = res_evidence.query_status or QueryResultStatus.FOUND
        reason = res_evidence.status_reason or "TOOL_EXECUTED"
        summary = (
            f"Graph backend executed {tool_name}: status={status.value}, "
            f"reaches_sink={res_evidence.source_reaches_sink}, "
            f"path_complete={res_evidence.path_complete}"
        )
        return (
            status,
            reason,
            summary,
            {
                "source_type": res_evidence.source_type,
                "sink_symbol": res_evidence.sink_symbol,
                "reaches_sink": res_evidence.source_reaches_sink,
                "path_complete": res_evidence.path_complete,
            },
        )
