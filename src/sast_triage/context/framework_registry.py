"""Small, versioned framework facts used by the bounded Python index.

These are analyst-maintained API names, not LLM-generated rules.  The module
returns only classifications and never retains source text or literal values.
"""

from __future__ import annotations

import ast

FRAMEWORK_REGISTRY_VERSION = "python-web-frameworks-v1"

_SOURCE_SUFFIXES: dict[str, str] = {
    "request.args.get": "http_query_parameter",
    "request.args.getlist": "http_query_parameter_list",
    "request.form.get": "http_form_parameter",
    "request.form.getlist": "http_form_parameter_list",
    "request.GET.get": "django_query_parameter",
    "request.POST.get": "django_form_parameter",
    "request.get_json": "http_json_body",
    "request.json.get": "http_json_body",
    "request.cookies.get": "http_cookie",
    "request.headers.get": "http_header",
    "request.values.get": "http_request_value",
    "request.files.get": "http_file_upload",
    "request.query_params.get": "fastapi_query_parameter",
    "request.path_params.get": "fastapi_path_parameter",
    "request.state": "http_request_state",
}
_ROUTE_DECORATOR_SUFFIXES = ("route", "get", "post", "put", "patch", "delete", "api_view")


def source_type_for_call(name: str | None) -> str | None:
    """Return a maintained user-input classification for one API call."""
    if name is None:
        return None
    return next(
        (
            source_type
            for suffix, source_type in _SOURCE_SUFFIXES.items()
            if name == suffix or name.endswith(f".{suffix}")
        ),
        None,
    )


def endpoint_source_type(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Classify a conventional Python web entrypoint without reading its body."""
    decorator_names = [
        _qualified_name(item.func) if isinstance(item, ast.Call) else _qualified_name(item)
        for item in function.decorator_list
    ]
    if any(
        name is not None
        and any(name == suffix or name.endswith(f".{suffix}") for suffix in _ROUTE_DECORATOR_SUFFIXES)
        for name in decorator_names
    ):
        return "http_route_parameter"
    parameters = (*function.args.posonlyargs, *function.args.args)
    if parameters and parameters[0].arg in {"request", "req"}:
        return "http_request_object"
    return None


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
