"""Pure Python-AST helpers and security API classifications."""

from __future__ import annotations

import ast

_SOURCE_CALL_SUFFIXES: dict[str, str] = {
    "input": "console_input",
    "request.args.get": "http_query_parameter",
    "request.form.get": "http_form_parameter",
    "request.form.getlist": "http_form_parameter_list",
    "request.args.getlist": "http_query_parameter_list",
    "request.headers.getlist": "http_header_list",
    "request.headers.get_all": "http_header_list",
    "request.form.keys": "http_form_key",
    "request.args.keys": "http_query_key",
    "request.headers.keys": "http_header_key",
    "request.get_json": "http_json_body",
    "request.cookies.get": "http_cookie",
    "request.headers.get": "http_header",
    "request.values.get": "http_request_value",
    "request.files.get": "http_file_upload",
    "get_form_parameter": "wrapped_http_form_parameter",
    "get_query_parameter": "wrapped_http_query_parameter",
    "get_header": "wrapped_http_header",
    "get_cookie": "wrapped_http_cookie",
    "os.environ.get": "environment_variable",
}

# These calls preserve whether their first argument is attacker-controlled. They
# are not sanitizers; treating them as transparent avoids turning a known local
# constant into UNKNOWN merely because it is encoded or decoded before a sink.
_KNOWN_TRANSPARENT_CALL_SUFFIXES: frozenset[str] = frozenset(
    {
        "base64.b64encode",
        "base64.b64decode",
        "base64.urlsafe_b64encode",
        "base64.urlsafe_b64decode",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "encode",
        "decode",
    }
)

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

_UNRESOLVED_CONSTANT = object()


def _qualified_name(node: ast.AST) -> str | None:
    """Return a dotted name for simple ``Name``/``Attribute`` expressions."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _safe_expression(node: ast.AST | None) -> str:
    """Project AST structure without retaining literal values or raw source."""
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


def _matches_suffix(
    name: str | None,
    suffixes: dict[str, str],
) -> tuple[str, str] | None:
    """Match a dotted symbol against a classified suffix mapping."""
    if name is None:
        return None
    for suffix, kind in suffixes.items():
        if name == suffix or name.endswith(f".{suffix}"):
            return suffix, kind
    return None


def _assigned_names(target: ast.AST) -> tuple[str, ...]:
    """Return names bound by a simple or destructuring assignment target."""
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        return tuple(
            name
            for item in target.elts
            for name in _assigned_names(item)
        )
    return ()
