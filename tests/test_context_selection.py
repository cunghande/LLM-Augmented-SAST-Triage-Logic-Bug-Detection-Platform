"""Unit tests for Raw Context Selection."""

import pytest

from sast_triage.context.python_scope import (
    ENCLOSING_SCOPE_EXCEEDED_LIMIT,
    NO_ENCLOSING_SCOPE,
    PYTHON_AST_PARSE_FAILED,
    PythonScopeResult,
)
from sast_triage.context.reader import SourceReadResult
from sast_triage.context.selection import (
    CONTEXT_TRUNCATED_TO_LIMIT,
    FINDING_EXCEEDS_CONTEXT_LIMIT,
    GITLEAKS_REDACTION_REQUIRED,
    LINE_WINDOW_FALLBACK,
    RawContextSelection,
    select_raw_context,
)
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    ScannerType,
    Severity,
)

CANARY = "SOURCE_CANARY_DO_NOT_LEAK"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    file_path: str = "app/service.py",
    start_line: int = 1,
    end_line: int | None = None,
    finding_id: str = "find123456789012",
) -> NormalizedFinding:
    actual_end = start_line if end_line is None else end_line
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=scanner,
        finding_type=FindingType.SAST if scanner == ScannerType.SEMGREP else FindingType.SECRET,
        rule_id="rule-01",
        file_path=file_path,
        start_line=start_line,
        end_line=actual_end,
        severity=Severity.HIGH if scanner == ScannerType.SEMGREP else Severity.UNKNOWN,
        message="Finding message",
        snippet="snippet",
    )


def make_source(code: str, relative_path: str = "app/service.py") -> SourceReadResult:
    return SourceReadResult(
        relative_path=relative_path,
        text=code,
        size_bytes=len(code.encode("utf-8")),
        encoding="utf-8",
    )


# --- 1. Semgrep with AST Scope ---


def test_semgrep_ast_function_scope_success() -> None:

    """Behavior Protected: Semgrep uses PYTHON_FUNCTION strategy when valid AST function scope is provided.

    Expected Result: strategy == ContextStrategy.PYTHON_FUNCTION, selected_text matches AST scope text.
    Category: Happy Path
    """
    code = "def process():\n    x = 10\n    return x\n"
    source = make_source(code)
    finding = make_finding(start_line=2, end_line=2)
    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        selected_text=code,
        context_start_line=1,
        context_end_line=3,
        enclosing_function="process",
    )

    res = select_raw_context(finding, source, scope)

    assert isinstance(res, RawContextSelection)
    assert res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert res.selected_text == code
    assert res.enclosing_function == "process"
    assert res.context_available is True
    assert res.truncated is False


def test_semgrep_ast_class_scope_success() -> None:

    """Behavior Protected: Semgrep uses PYTHON_CLASS strategy when valid AST class scope is provided.

    Expected Result: strategy == ContextStrategy.PYTHON_CLASS, enclosing_class == 'Service'.
    Category: Happy Path
    """
    code = "class Service:\n    VERSION = 1\n"
    source = make_source(code)
    finding = make_finding(start_line=2, end_line=2)
    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_CLASS,
        selected_text=code,
        context_start_line=1,
        context_end_line=2,
        enclosing_class="Service",
    )

    res = select_raw_context(finding, source, scope)

    assert res.strategy == ContextStrategy.PYTHON_CLASS
    assert res.enclosing_class == "Service"
    assert res.selected_text == code


def test_semgrep_ast_metadata_preserved() -> None:

    """Behavior Protected: AST enclosing_function and enclosing_class metadata are preserved in RawContextSelection.

    Expected Result: enclosing_function == 'method', enclosing_class == 'Class'.
    Category: Happy Path
    """
    code = "class Class:\n    def method(self):\n        pass\n"
    source = make_source(code)
    finding = make_finding(start_line=3)
    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        selected_text=code,
        enclosing_function="method",
        enclosing_class="Class",
    )

    res = select_raw_context(finding, source, scope)
    assert res.enclosing_function == "method"
    assert res.enclosing_class == "Class"


def test_semgrep_ast_imports_decorators_preserved() -> None:

    """Behavior Protected: Imports and decorators from scope are preserved internally in RawContextSelection.

    Expected Result: limited_imports == ('import os',), limited_decorators == ('@auth',)
    Category: Happy Path
    """
    code = "@auth\ndef fn(): pass\n"
    source = make_source(code)
    finding = make_finding(start_line=2)
    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        selected_text=code,
        limited_imports=("import os",),
        limited_decorators=("@auth",),
    )

    res = select_raw_context(finding, source, scope)
    assert res.limited_imports == ("import os",)
    assert res.limited_decorators == ("@auth",)


# --- 2. Semgrep Fallback ---


def test_semgrep_fallback_no_scope() -> None:

    """Behavior Protected: Semgrep falls back to LINE_WINDOW when scope is None.

    Expected Result: strategy == ContextStrategy.LINE_WINDOW, diagnostic LINE_WINDOW_FALLBACK included.
    Category: Fallback Path
    """
    lines = [f"line_{i}\n" for i in range(1, 30)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=15, end_line=15)

    res = select_raw_context(finding, source, scope=None, line_window_before=5, line_window_after=5)

    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert res.context_start_line == 10
    assert res.context_end_line == 20
    assert LINE_WINDOW_FALLBACK in res.diagnostic_reasons


def test_semgrep_fallback_ast_parse_failed() -> None:

    """Behavior Protected: Semgrep falls back to LINE_WINDOW when AST parse failed and preserves diagnostic.

    Expected Result: strategy == ContextStrategy.LINE_WINDOW, PYTHON_AST_PARSE_FAILED in diagnostic_reasons.
    Category: Fallback Path
    """
    source = make_source("def broken(\n")
    finding = make_finding(start_line=1)
    scope = PythonScopeResult(
        strategy=ContextStrategy.UNAVAILABLE,
        selected_text=None,
        diagnostic_reasons=(PYTHON_AST_PARSE_FAILED,),
    )

    res = select_raw_context(finding, source, scope)

    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert PYTHON_AST_PARSE_FAILED in res.diagnostic_reasons
    assert LINE_WINDOW_FALLBACK in res.diagnostic_reasons


def test_semgrep_fallback_no_enclosing_scope() -> None:

    """Behavior Protected: Semgrep falls back to LINE_WINDOW when no enclosing scope is found.

    Expected Result: NO_ENCLOSING_SCOPE preserved in diagnostic_reasons.
    Category: Fallback Path
    """
    source = make_source("x = 10\n")
    finding = make_finding(start_line=1)
    scope = PythonScopeResult(
        strategy=ContextStrategy.UNAVAILABLE,
        selected_text=None,
        diagnostic_reasons=(NO_ENCLOSING_SCOPE,),
    )

    res = select_raw_context(finding, source, scope)

    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert NO_ENCLOSING_SCOPE in res.diagnostic_reasons


def test_semgrep_fallback_oversized_scope() -> None:

    """Behavior Protected: Semgrep falls back to LINE_WINDOW when AST scope exceeded size limits.

    Expected Result: ENCLOSING_SCOPE_EXCEEDED_LIMIT preserved in diagnostic_reasons.
    Category: Fallback Path
    """
    source = make_source("def big():\n    pass\n")
    finding = make_finding(start_line=2)
    scope = PythonScopeResult(
        strategy=ContextStrategy.UNAVAILABLE,
        selected_text=None,
        enclosing_function="big",
        diagnostic_reasons=(ENCLOSING_SCOPE_EXCEEDED_LIMIT,),
        scope_exceeded_limit=True,
    )

    res = select_raw_context(finding, source, scope)

    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert res.enclosing_function == "big"
    assert ENCLOSING_SCOPE_EXCEEDED_LIMIT in res.diagnostic_reasons


def test_semgrep_fallback_clamp_start() -> None:

    """Behavior Protected: Line window start line is clamped to 1 when near top of file.

    Expected Result: context_start_line == 1.
    Category: Edge Case
    """
    lines = [f"l_{i}\n" for i in range(1, 10)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=2)

    res = select_raw_context(finding, source, line_window_before=10)
    assert res.context_start_line == 1


def test_semgrep_fallback_clamp_end() -> None:

    """Behavior Protected: Line window end line is clamped to total_source_lines when near bottom of file.

    Expected Result: context_end_line == total_source_lines.
    Category: Edge Case
    """
    lines = [f"l_{i}\n" for i in range(1, 10)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=8)

    res = select_raw_context(finding, source, line_window_after=10)
    assert res.context_end_line == 9


def test_semgrep_fallback_multiline_finding() -> None:

    """Behavior Protected: Multi-line finding range is fully covered by line window.

    Expected Result: finding_start_line and finding_end_line covered inside context_start_line..context_end_line.
    Category: Happy Path
    """
    lines = [f"line_{i}\n" for i in range(1, 30)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=10, end_line=15)

    res = select_raw_context(finding, source, line_window_before=2, line_window_after=2)

    assert res.context_start_line == 8
    assert res.context_end_line == 17


# --- 3. Gitleaks ---


def test_gitleaks_always_uses_line_window() -> None:

    """Behavior Protected: Gitleaks finding ALWAYS uses raw LINE_WINDOW strategy for selected_text.

    Expected Result: strategy == ContextStrategy.LINE_WINDOW.
    Category: Happy Path
    """
    code = "def secret_fn():\n    AWS_KEY = 'SECRET'\n    return AWS_KEY\n"
    source = make_source(code)
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2)

    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        selected_text=code,
        enclosing_function="secret_fn",
    )

    res = select_raw_context(finding, source, scope)

    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert GITLEAKS_REDACTION_REQUIRED in res.diagnostic_reasons


def test_gitleaks_does_not_use_ast_body() -> None:

    """Behavior Protected: Gitleaks does NOT use full AST function body as selected_text.

    Expected Result: selected_text is line window around finding, not full function body.
    Category: Security
    """
    lines = [f"line_{i}\n" for i in range(1, 50)]
    source = make_source("".join(lines))
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=25)

    res = select_raw_context(finding, source, line_window_before=2, line_window_after=2)

    assert res.context_start_line == 23
    assert res.context_end_line == 27
    assert len(res.selected_text.splitlines()) == 5  # 5 lines, not 50 lines


def test_gitleaks_preserves_ast_metadata() -> None:

    """Behavior Protected: Gitleaks preserves AST scope metadata (enclosing_function/class) while using line window.

    Expected Result: enclosing_function == 'secret_fn', enclosing_class == 'SecretService'.
    Category: Happy Path
    """
    source = make_source("class SecretService:\n    def secret_fn(self):\n        pass\n")
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=3)

    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        enclosing_function="secret_fn",
        enclosing_class="SecretService",
    )

    res = select_raw_context(finding, source, scope)

    assert res.enclosing_function == "secret_fn"
    assert res.enclosing_class == "SecretService"
    assert res.strategy == ContextStrategy.LINE_WINDOW


def test_gitleaks_diagnostic_redaction_required() -> None:

    """Behavior Protected: Diagnostic GITLEAKS_REDACTION_REQUIRED is added to RawContextSelection for Gitleaks.

    Expected Result: GITLEAKS_REDACTION_REQUIRED in diagnostic_reasons.
    Category: Security
    """
    source = make_source("KEY = 1\n")
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=1)

    res = select_raw_context(finding, source)
    assert GITLEAKS_REDACTION_REQUIRED in res.diagnostic_reasons


def test_gitleaks_strategy_is_line_window_not_redacted() -> None:

    """Behavior Protected: Strategy is LINE_WINDOW (not REDACTED_LINE_WINDOW) prior to sanitization.

    Expected Result: res.strategy == ContextStrategy.LINE_WINDOW.
    Category: Contract Verification
    """
    source = make_source("KEY = 1\n")
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=1)

    res = select_raw_context(finding, source)
    assert res.strategy == ContextStrategy.LINE_WINDOW
    assert res.strategy != ContextStrategy.REDACTED_LINE_WINDOW


# --- 4. Limits & Truncation ---


def test_reject_negative_line_windows() -> None:

    """Behavior Protected: Negative line_window_before or line_window_after parameter raises SastTriageError.

    Expected Result: SastTriageError with CONTEXT_INVALID_SELECTION_LIMIT.
    Category: Failure Path
    """
    source = make_source("x = 1\n")
    finding = make_finding(start_line=1)

    with pytest.raises(SastTriageError) as exc:
        select_raw_context(finding, source, line_window_before=-1)
    assert exc.value.error_code == "CONTEXT_INVALID_SELECTION_LIMIT"

    with pytest.raises(SastTriageError) as exc:
        select_raw_context(finding, source, line_window_after=-5)
    assert exc.value.error_code == "CONTEXT_INVALID_SELECTION_LIMIT"


def test_reject_invalid_max_context_characters() -> None:

    """Behavior Protected: Non-positive max_context_characters parameter raises SastTriageError.

    Expected Result: SastTriageError with CONTEXT_INVALID_SELECTION_LIMIT.
    Category: Failure Path
    """
    source = make_source("x = 1\n")
    finding = make_finding(start_line=1)

    with pytest.raises(SastTriageError) as exc:
        select_raw_context(finding, source, max_context_characters=0)
    assert exc.value.error_code == "CONTEXT_INVALID_SELECTION_LIMIT"


def test_context_truncated_to_limit() -> None:

    """Behavior Protected: Context exceeding character limit is line-truncated surrounding finding.

    Expected Result: truncated == True, CONTEXT_TRUNCATED_TO_LIMIT in diagnostic_reasons.
    Category: Truncation
    """
    # 10 lines of 50 chars each = 500 chars total
    lines = [f"# line {i:02d} " + ("A" * 40) + "\n" for i in range(1, 11)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=5, end_line=5)

    # Set max limit to 150 chars (covers ~3 lines)
    res = select_raw_context(finding, source, line_window_before=4, line_window_after=4, max_context_characters=150)

    assert res.truncated is True
    assert res.context_available is True
    assert CONTEXT_TRUNCATED_TO_LIMIT in res.diagnostic_reasons
    assert len(res.selected_text) <= 150


def test_truncation_preserves_finding_lines() -> None:

    """Behavior Protected: Line truncation does NOT cut finding lines from selected_text.

    Expected Result: finding lines are contained within truncated selected_text range.
    Category: Truncation Security
    """
    lines = [f"# line {i:02d} " + ("B" * 30) + "\n" for i in range(1, 11)]
    source = make_source("".join(lines))
    finding = make_finding(start_line=5, end_line=5)

    res = select_raw_context(finding, source, line_window_before=4, line_window_after=4, max_context_characters=100)

    assert res.context_start_line <= 5
    assert res.context_end_line >= 5
    assert "line 05" in res.selected_text


def test_truncated_flag_set() -> None:

    """Behavior Protected: truncated flag is True when truncation occurs and False when not.

    Expected Result: res.truncated is set accurately.
    Category: Happy Path
    """
    source = make_source("line1\nline2\nline3\nline4\nline5\n")
    finding = make_finding(start_line=3)

    res_normal = select_raw_context(finding, source, max_context_characters=1000)
    assert res_normal.truncated is False

    res_trunc = select_raw_context(finding, source, line_window_before=2, line_window_after=2, max_context_characters=10)
    assert res_trunc.truncated is True


def test_finding_lines_exceed_limit() -> None:

    """Behavior Protected: If finding lines alone exceed max_context_characters, context_available is False.

    Expected Result: context_available == False, selected_text == None, FINDING_EXCEEDS_CONTEXT_LIMIT diagnostic.
    Category: Failure Path / Boundary Limit
    """
    long_line = "# finding line " + ("X" * 300) + "\n"
    source = make_source(long_line)
    finding = make_finding(start_line=1)

    res = select_raw_context(finding, source, max_context_characters=100)

    assert res.context_available is False
    assert res.selected_text is None
    assert FINDING_EXCEEDS_CONTEXT_LIMIT in res.diagnostic_reasons


# --- 5. Consistency ---


def test_file_path_mismatch_rejected() -> None:

    """Behavior Protected: Mismatch between finding.file_path and source.relative_path raises SastTriageError.

    Expected Result: SastTriageError with CONTEXT_INVALID_FINDING_LINE_RANGE.
    Category: Failure Path
    """
    source = make_source("x = 1\n", relative_path="app/service.py")
    finding = make_finding(file_path="app/other_service.py")

    with pytest.raises(SastTriageError) as exc:
        select_raw_context(finding, source)
    assert exc.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_finding_line_exceeds_source_lines_rejected() -> None:

    """Behavior Protected: Finding start line exceeding source line count raises SastTriageError.

    Expected Result: SastTriageError with CONTEXT_INVALID_FINDING_LINE_RANGE.
    Category: Failure Path
    """
    source = make_source("line1\nline2\n")
    finding = make_finding(start_line=10)

    with pytest.raises(SastTriageError) as exc:
        select_raw_context(finding, source)
    assert exc.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_inputs_not_mutated() -> None:

    """Behavior Protected: Input finding, source, and scope objects are not mutated by select_raw_context.

    Expected Result: Input objects retain original field values.
    Category: Immutability
    """
    source = make_source("def fn(): pass\n")
    finding = make_finding(start_line=1)

    orig_source_text = source.text
    orig_finding_rule = finding.rule_id

    select_raw_context(finding, source)

    assert source.text == orig_source_text
    assert finding.rule_id == orig_finding_rule


# --- 6. Security ---


def test_canary_absent_from_selection_repr() -> None:

    """Behavior Protected: Source canary in selected_text, imports, or decorators is ABSENT from repr and str.

    Expected Result: CANARY not in repr(res), CANARY not in str(res).
    Category: Security Invariant
    """
    code = f"# {CANARY}\ndef secure_fn():\n    secret = '{CANARY}'\n"
    source = make_source(code)
    finding = make_finding(start_line=2)

    scope = PythonScopeResult(
        strategy=ContextStrategy.PYTHON_FUNCTION,
        selected_text=code,
        limited_imports=(f"import os  # {CANARY}",),
        limited_decorators=(f"@{CANARY}_decorator",),
    )

    res = select_raw_context(finding, source, scope)

    # Canary IS in internal raw fields
    assert CANARY in res.selected_text
    assert CANARY in res.limited_imports[0]
    assert CANARY in res.limited_decorators[0]

    # Canary MUST NOT be in repr or str!
    res_repr = repr(res)
    res_str = str(res)

    assert CANARY not in res_repr
    assert CANARY not in res_str


def test_absolute_path_absent_from_result() -> None:

    """Behavior Protected: Absolute repository paths do not appear in RawContextSelection.

    Expected Result: No absolute drive or POSIX prefix in repr(res).
    Category: Security Invariant
    """
    source = make_source("x = 1\n", relative_path="src/app.py")
    finding = make_finding(file_path="src/app.py")

    res = select_raw_context(finding, source)
    res_repr = repr(res)

    assert "C:\\" not in res_repr
    assert "/home/" not in res_repr


def test_no_model_dump_method() -> None:

    """Behavior Protected: RawContextSelection does NOT expose model_dump or serialization API.

    Expected Result: hasattr(res, 'model_dump') is False, hasattr(res, 'model_dump_json') is False.
    Category: Security Contract
    """
    source = make_source("x = 1\n")
    finding = make_finding()

    res = select_raw_context(finding, source)

    assert not hasattr(res, "model_dump")
    assert not hasattr(res, "model_dump_json")
