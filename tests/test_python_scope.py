"""Unit tests for Python AST Scope Analyzer."""

import pytest

from sast_triage.context.python_scope import (
    ENCLOSING_SCOPE_EXCEEDED_LIMIT,
    NO_ENCLOSING_SCOPE,
    PYTHON_AST_PARSE_FAILED,
    PythonScopeResult,
    select_python_scope,
)
from sast_triage.context.reader import SourceReadResult
from sast_triage.errors import SastTriageError
from sast_triage.models import ContextStrategy

SOURCE_CANARY = "SOURCE_CANARY_DO_NOT_LEAK"


def make_source(code: str) -> SourceReadResult:
    """Helper to create a SourceReadResult from raw code string."""
    return SourceReadResult(
        relative_path="app/services/calculator.py",
        text=code,
        size_bytes=len(code.encode("utf-8")),
        encoding="utf-8",
    )


# --- 1. Function Selection ---


def test_select_sync_function() -> None:
    code = """# module header
def calculate_total(items):
    # comment
    total = sum(items)
    return total
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=4)

    assert isinstance(res, PythonScopeResult)
    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "calculate_total"
    assert res.enclosing_class is None
    assert res.context_start_line == 2
    assert res.context_end_line == 5
    assert res.selected_text is not None
    assert "total = sum(items)" in res.selected_text
    assert "# comment" in res.selected_text


def test_select_async_function() -> None:
    code = """async def fetch_data(url):
    result = await client.get(url)
    return result
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=2)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "fetch_data"
    assert res.enclosing_class is None
    assert res.selected_text is not None
    assert "await client.get" in res.selected_text


def test_select_method_in_class() -> None:
    code = """class CalculatorService:
    def process_payment(self, amount):
        eval(amount)
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=3)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "process_payment"
    assert res.enclosing_class == "CalculatorService"


def test_select_nested_function_in_method() -> None:
    code = """class AuditService:
    def outer_method(self):
        def inner_helper():
            exec('unsafe')
        inner_helper()
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=4)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "inner_helper"
    assert res.enclosing_class == "AuditService"


def test_select_multi_line_finding_range() -> None:
    code = """def multi_line_fn():
    line1 = 1
    line2 = 2
    line3 = 3
    return line1 + line2 + line3
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=2, finding_end_line=4)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "multi_line_fn"
    assert res.selected_text is not None


# --- 2. Class Selection ---


def test_select_class_level_scope() -> None:
    code = """class DatabaseConfig:
    DEFAULT_PORT = 5432
    MAX_CONNECTIONS = 100
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=2)

    assert res.strategy == ContextStrategy.PYTHON_CLASS
    assert res.enclosing_class == "DatabaseConfig"
    assert res.enclosing_function is None


def test_select_module_level_no_scope() -> None:
    code = """import os
import sys

x = 10
y = 20
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=4)

    assert res.strategy == ContextStrategy.UNAVAILABLE
    assert res.selected_text is None
    assert res.enclosing_function is None
    assert res.enclosing_class is None
    assert NO_ENCLOSING_SCOPE in res.diagnostic_reasons


# --- 3. AST Failure & Syntax Errors ---


def test_ast_parse_syntax_error() -> None:
    code = """def broken_function(:
    syntax error here (((
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=1)

    assert res.strategy == ContextStrategy.UNAVAILABLE
    assert res.selected_text is None
    assert PYTHON_AST_PARSE_FAILED in res.diagnostic_reasons


# --- 4. Limits ---


def test_scope_exceeds_max_scope_lines() -> None:
    body = "\n".join([f"    x_{i} = {i}" for i in range(50)])
    code = f"def long_function():\n{body}\n    return True\n"
    source = make_source(code)

    res = select_python_scope(source, finding_start_line=10, max_scope_lines=30)

    assert res.strategy == ContextStrategy.UNAVAILABLE
    assert res.selected_text is None
    assert res.scope_exceeded_limit is True
    assert res.enclosing_function == "long_function"
    assert ENCLOSING_SCOPE_EXCEEDED_LIMIT in res.diagnostic_reasons


def test_scope_exceeds_max_context_characters() -> None:
    code = """def char_heavy_function():
    # """ + ("A" * 500) + """
    return True
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=2, max_context_characters=200)

    assert res.strategy == ContextStrategy.UNAVAILABLE
    assert res.selected_text is None
    assert res.scope_exceeded_limit is True
    assert ENCLOSING_SCOPE_EXCEEDED_LIMIT in res.diagnostic_reasons


def test_reject_invalid_scope_limits() -> None:
    source = make_source("x = 1\n")
    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, 1, max_scope_lines=0)
    assert exc_info.value.error_code == "CONTEXT_INVALID_SCOPE_LIMIT"

    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, 1, max_context_characters=-5)
    assert exc_info.value.error_code == "CONTEXT_INVALID_SCOPE_LIMIT"


# --- 5. Line Ranges & Rejection ---


def test_reject_start_line_zero() -> None:
    source = make_source("x = 1\n")
    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, 0)
    assert exc_info.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_reject_end_line_earlier_than_start() -> None:
    source = make_source("x = 1\ny = 2\n")
    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, finding_start_line=2, finding_end_line=1)
    assert exc_info.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_reject_line_range_exceeds_source_line_count() -> None:
    source = make_source("x = 1\n")
    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, finding_start_line=10)
    assert exc_info.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_empty_source_rejects_positive_lines() -> None:
    source = SourceReadResult(relative_path="empty.py", text="", size_bytes=0, encoding="utf-8")
    with pytest.raises(SastTriageError) as exc_info:
        select_python_scope(source, 1)
    assert exc_info.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


# --- 6. Source Preservation & Formatting ---


def test_selected_text_preserves_indentation_and_comments() -> None:
    code = """class Service:
    def method(self):
        # Important comment
        val = (
            1 + 2
        )
        return val
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=4)

    assert res.selected_text is not None
    assert "# Important comment" in res.selected_text
    assert "        val = (" in res.selected_text


# --- 7. Imports & Decorators ---


def test_collect_module_imports() -> None:
    code = """import os
import sys
from pathlib import Path
from typing import (
    Any,
    Callable,
)

def run():
    pass
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=10, max_import_lines=10)

    assert len(res.limited_imports) == 4
    assert res.limited_imports[0] == "import os"
    assert res.limited_imports[1] == "import sys"
    assert res.limited_imports[2] == "from pathlib import Path"
    assert "from typing import (" in res.limited_imports[3]


def test_collect_imports_respects_line_budget() -> None:
    code = """import os
import sys
import math
import json
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=1, max_import_lines=2)

    assert len(res.limited_imports) == 2
    assert res.limited_imports == ("import os", "import sys")


def test_collect_decorators() -> None:
    code = """@app.route('/api')
@auth_required
def endpoint():
    return {'status': 'ok'}
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=3)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.context_start_line == 1
    assert len(res.limited_decorators) == 2
    assert res.limited_decorators[0] == "@app.route('/api')"
    assert res.limited_decorators[1] == "@auth_required"


def test_finding_on_decorator_line() -> None:
    code = """@decorated_fn
def target():
    pass
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=1)

    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.enclosing_function == "target"


# --- 8. Security Invariants & Canary Protection ---


def test_canary_in_body_imports_decorators_absent_from_repr() -> None:
    code = f"""import os  # {SOURCE_CANARY}

@{SOURCE_CANARY}_decorator
def sensitive_function():
    secret_var = '{SOURCE_CANARY}'
    return secret_var
"""
    source = make_source(code)
    res = select_python_scope(source, finding_start_line=5)

    assert res.selected_text is not None
    assert SOURCE_CANARY in res.selected_text
    assert SOURCE_CANARY in res.limited_imports[0]
    assert SOURCE_CANARY in res.limited_decorators[0]

    # repr and str of PythonScopeResult MUST NOT contain canary!
    res_repr = repr(res)
    res_str = str(res)

    assert SOURCE_CANARY not in res_repr
    assert SOURCE_CANARY not in res_str
    assert "enclosing_function='sensitive_function'" in res_repr


def test_python_scope_result_is_frozen() -> None:
    source = make_source("def fn(): pass\n")
    res = select_python_scope(source, 1)

    with pytest.raises(AttributeError):
        res.enclosing_function = "mutated"  # type: ignore[misc]


def test_input_source_read_result_not_mutated() -> None:
    source = make_source("def fn(): pass\n")
    original_text = source.text
    select_python_scope(source, 1)
    assert source.text == original_text
