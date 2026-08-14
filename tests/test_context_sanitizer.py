"""Unit tests for Context Sanitizer."""

import pytest

from sast_triage.context.sanitizer import (
    REDACTED_GITLEAKS_FINDING_LINE,
    REDACTED_PRIVATE_KEY_BLOCK,
    REDACTED_SECRET,
    sanitize_context,
)
from sast_triage.context.selection import RawContextSelection
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    MissingContextReason,
    NormalizedFinding,
    PathCategory,
    ScannerType,
    Severity,
)

CANARY = "CONTEXT_SECRET_CANARY_DO_NOT_LEAK"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    file_path: str = "src/app.py",
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
    )


def make_raw_context(
    finding: NormalizedFinding,
    selected_text: str = "def fn():\n    pass\n",
    strategy: ContextStrategy = ContextStrategy.PYTHON_FUNCTION,
    context_start_line: int = 1,
    context_end_line: int = 10,
    context_available: bool = True,
    enclosing_function: str | None = None,
    enclosing_class: str | None = None,
    limited_imports: tuple[str, ...] = (),
    limited_decorators: tuple[str, ...] = (),
) -> RawContextSelection:
    finding_end = finding.end_line if finding.end_line is not None else finding.start_line
    return RawContextSelection(
        finding_id=finding.finding_instance_id,
        scanner=finding.scanner,
        strategy=strategy,
        selected_text=selected_text if context_available else None,
        context_start_line=context_start_line if context_available else None,
        context_end_line=context_end_line if context_available else None,
        finding_start_line=finding.start_line,
        finding_end_line=finding_end,
        enclosing_function=enclosing_function,
        enclosing_class=enclosing_class,
        limited_imports=limited_imports,
        limited_decorators=limited_decorators,
        context_available=context_available,
    )


# --- 1. Gitleaks Sanitization ---


def test_gitleaks_finding_line_masked_line_by_line() -> None:
    """Behavior Protected: Gitleaks finding line is replaced line-by-line with safe marker preserving indentation.

    Expected Result: Line is replaced with '# <REDACTED_GITLEAKS_FINDING_LINE>'.
    Category: Gitleaks Safety
    """
    code = "def load_config():\n    api_key = 'raw-secret'\n    return True\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2, end_line=2)
    raw = make_raw_context(finding, selected_text=code, strategy=ContextStrategy.LINE_WINDOW, context_start_line=1, context_end_line=3)

    res = sanitize_context(finding, raw)

    assert res.context_strategy == ContextStrategy.REDACTED_LINE_WINDOW
    assert f"# {REDACTED_GITLEAKS_FINDING_LINE}" in res.sanitized_snippet
    assert "raw-secret" not in res.sanitized_snippet
    assert res.redactions_applied >= 1
    assert "GITLEAKS_FINDING_LINE" in res.redaction_types


def test_gitleaks_multiple_finding_lines_masked() -> None:
    """Behavior Protected: Multiple consecutive finding lines are masked preserving line count.

    Expected Result: Both finding lines masked with marker.
    Category: Gitleaks Safety
    """
    code = "def config():\n    k1 = 'sec1'\n    k2 = 'sec2'\n    return True\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2, end_line=3)
    raw = make_raw_context(finding, selected_text=code, strategy=ContextStrategy.LINE_WINDOW, context_start_line=1, context_end_line=4)

    res = sanitize_context(finding, raw)

    assert res.sanitized_snippet.count(REDACTED_GITLEAKS_FINDING_LINE) == 2
    assert "sec1" not in res.sanitized_snippet
    assert "sec2" not in res.sanitized_snippet


def test_gitleaks_raw_canary_absent() -> None:
    """Behavior Protected: Raw secret canary in finding line is absent from sanitized output.

    Expected Result: CANARY not in res.sanitized_snippet.
    Category: Gitleaks Security
    """
    code = f"def fn():\n    SECRET = '{CANARY}'\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2)
    raw = make_raw_context(finding, selected_text=code, context_start_line=1, context_end_line=2)

    res = sanitize_context(finding, raw)
    assert CANARY not in res.sanitized_snippet


def test_gitleaks_surrounding_safe_lines_preserved() -> None:
    """Behavior Protected: Surrounding non-finding lines are preserved in Gitleaks context.

    Expected Result: 'def load_config():' and 'return True' preserved.
    Category: Happy Path
    """
    code = "def load_config():\n    api_key = 'sec'\n    return True\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2)
    raw = make_raw_context(finding, selected_text=code, context_start_line=1, context_end_line=3)

    res = sanitize_context(finding, raw)
    assert "def load_config():" in res.sanitized_snippet
    assert "return True" in res.sanitized_snippet


def test_gitleaks_ast_metadata_preserved() -> None:
    """Behavior Protected: AST enclosing_function/class metadata preserved for Gitleaks.

    Expected Result: enclosing_function == 'load_config'.
    Category: Happy Path
    """
    code = "def load_config():\n    api_key = 'sec'\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=2)
    raw = make_raw_context(finding, selected_text=code, context_start_line=1, context_end_line=2, enclosing_function="load_config")

    res = sanitize_context(finding, raw)
    assert res.enclosing_function == "load_config"


def test_gitleaks_unmappable_line_range_unavailable() -> None:
    """Behavior Protected: If finding line range cannot map into selected context, context is unavailable.

    Expected Result: context_available == False, sanitized_snippet == None.
    Category: Failure Path
    """
    code = "def fn():\n    pass\n"
    finding = make_finding(scanner=ScannerType.GITLEAKS, start_line=50)
    raw = make_raw_context(finding, selected_text=code, context_start_line=1, context_end_line=2)

    res = sanitize_context(finding, raw)
    assert res.context_available is False
    assert res.sanitized_snippet is None
    assert MissingContextReason.CONTEXT_SANITIZATION_FAILED in res.missing_context_reasons


# --- 2. Semgrep Generic Sanitization ---


def test_semgrep_function_strategy_preserved() -> None:
    """Behavior Protected: Semgrep function scope context preserves PYTHON_FUNCTION strategy.

    Expected Result: context_strategy == ContextStrategy.PYTHON_FUNCTION.
    Category: Happy Path
    """
    code = "def clean():\n    x = 1\n"
    finding = make_finding(start_line=2)
    raw = make_raw_context(finding, selected_text=code, strategy=ContextStrategy.PYTHON_FUNCTION)

    res = sanitize_context(finding, raw)
    assert res.context_strategy == ContextStrategy.PYTHON_FUNCTION


def test_semgrep_class_strategy_preserved() -> None:
    """Behavior Protected: Semgrep class scope context preserves PYTHON_CLASS strategy.

    Expected Result: context_strategy == ContextStrategy.PYTHON_CLASS.
    Category: Happy Path
    """
    code = "class Config:\n    VAR = 1\n"
    finding = make_finding(start_line=2)
    raw = make_raw_context(finding, selected_text=code, strategy=ContextStrategy.PYTHON_CLASS)

    res = sanitize_context(finding, raw)
    assert res.context_strategy == ContextStrategy.PYTHON_CLASS


def test_semgrep_password_assignment_redacted() -> None:
    """Behavior Protected: Literal password assignment is redacted with <REDACTED_SECRET>.

    Expected Result: password = "<REDACTED_SECRET>".
    Category: Generic Redaction
    """
    code = "password = 'super_secret_pass'\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "super_secret_pass" not in res.sanitized_snippet
    assert f"password = '{REDACTED_SECRET}'" in res.sanitized_snippet
    assert "CREDENTIAL_ASSIGNMENT" in res.redaction_types


def test_semgrep_api_key_assignment_redacted() -> None:
    """Behavior Protected: Literal api_key assignment is redacted.

    Expected Result: api_key = "<REDACTED_SECRET>".
    Category: Generic Redaction
    """
    code = 'api_key = "AKIA1234567890"\n'
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "AKIA1234567890" not in res.sanitized_snippet
    assert f'api_key = "{REDACTED_SECRET}"' in res.sanitized_snippet


def test_semgrep_bearer_token_redacted() -> None:
    """Behavior Protected: Authorization Bearer header token is redacted.

    Expected Result: Authorization: Bearer <REDACTED_SECRET>.
    Category: Generic Redaction
    """
    code = "headers = {'Authorization': 'Bearer my_secret_token_123'}\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "my_secret_token_123" not in res.sanitized_snippet
    assert f"Bearer {REDACTED_SECRET}" in res.sanitized_snippet
    assert "AUTHORIZATION_BEARER" in res.redaction_types


def test_semgrep_private_key_block_redacted() -> None:
    """Behavior Protected: PEM private key block is replaced with <REDACTED_PRIVATE_KEY_BLOCK>.

    Expected Result: PEM block replaced.
    Category: Generic Redaction
    """
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\n"
    code = f"key = '''{pem}'''\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "MIIEowIBAAKCAQEA0" not in res.sanitized_snippet
    assert REDACTED_PRIVATE_KEY_BLOCK in res.sanitized_snippet
    assert "PRIVATE_KEY_BLOCK" in res.redaction_types


def test_semgrep_connection_url_redacted() -> None:
    """Behavior Protected: Connection URL password is redacted preserving scheme, user, and host.

    Expected Result: postgresql://admin:<REDACTED_SECRET>@localhost:5432/db.
    Category: Generic Redaction
    """
    code = 'db_url = "postgresql://admin:secret_pass123@localhost:5432/db"\n'
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "secret_pass123" not in res.sanitized_snippet
    assert f"postgresql://admin:{REDACTED_SECRET}@localhost:5432/db" in res.sanitized_snippet
    assert "CONNECTION_URL" in res.redaction_types


def test_semgrep_non_literal_expressions_preserved() -> None:
    """Behavior Protected: Non-literal expressions (function calls, dict lookups) are NOT redacted.

    Expected Result: token = load_token() and password = req.form['password'] preserved intact.
    Category: Triage Evidence Preservation
    """
    code = "token = load_token()\npassword = request.form['password']\nsecret = settings.get('SECRET')\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert "token = load_token()" in res.sanitized_snippet
    assert "password = request.form['password']" in res.sanitized_snippet
    assert "secret = settings.get('SECRET')" in res.sanitized_snippet


# --- 3. Imports & Decorators ---


def test_imports_and_decorators_sanitized() -> None:
    """Behavior Protected: Imports and decorators are sanitized independently.

    Expected Result: Credentials inside import and decorator strings are redacted.
    Category: Complete Surface Redaction
    """
    code = "def fn(): pass\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(
        finding,
        selected_text=code,
        limited_imports=("import os  # secret='imp_secret'",),
        limited_decorators=("@auth(token='dec_token')",),
    )

    res = sanitize_context(finding, raw)
    assert res.limited_imports is not None
    assert res.limited_decorators is not None
    assert "imp_secret" not in res.limited_imports[0]
    assert "dec_token" not in res.limited_decorators[0]
    assert REDACTED_SECRET in res.limited_imports[0]
    assert REDACTED_SECRET in res.limited_decorators[0]


def test_canary_absent_from_serialized_output() -> None:
    """Behavior Protected: Raw secret canary does not appear in model_dump() or model_dump_json().

    Expected Result: CANARY not in serialized JSON.
    Category: Security Boundary
    """
    code = f"password = '{CANARY}'\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    dump_dict = res.model_dump()
    dump_json = res.model_dump_json()

    assert CANARY not in str(dump_dict)
    assert CANARY not in dump_json


# --- 4. Idempotency ---


def test_idempotency_sanitizing_already_sanitized_context() -> None:
    """Behavior Protected: Sanitizing text containing placeholders is idempotent and does not nest placeholders.

    Expected Result: No nested placeholders generated, redactions_applied is 0 on second pass.
    Category: Idempotency
    """
    code = f"password = '{REDACTED_SECRET}'\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw)
    assert res.sanitized_snippet == f"password = '{REDACTED_SECRET}'\n"
    assert res.redactions_applied == 0


# --- 5. Consistency & Validation ---


def test_finding_id_mismatch_rejected() -> None:
    """Behavior Protected: Mismatch between raw_context.finding_id and finding.finding_instance_id raises SastTriageError.

    Expected Result: SastTriageError raised.
    Category: Failure Path
    """
    finding = make_finding(finding_id="id1")
    raw = RawContextSelection(
        finding_id="id2",
        scanner=ScannerType.SEMGREP,
        strategy=ContextStrategy.PYTHON_FUNCTION,
        finding_start_line=1,
        finding_end_line=1,
    )

    with pytest.raises(SastTriageError) as exc:
        sanitize_context(finding, raw)
    assert exc.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_scanner_mismatch_rejected() -> None:
    """Behavior Protected: Mismatch between raw_context.scanner and finding.scanner raises SastTriageError.

    Expected Result: SastTriageError raised.
    Category: Failure Path
    """
    finding = make_finding(scanner=ScannerType.SEMGREP)
    raw = RawContextSelection(
        finding_id=finding.finding_instance_id,
        scanner=ScannerType.GITLEAKS,
        strategy=ContextStrategy.LINE_WINDOW,
        finding_start_line=1,
        finding_end_line=1,
    )

    with pytest.raises(SastTriageError) as exc:
        sanitize_context(finding, raw)
    assert exc.value.error_code == "CONTEXT_INVALID_FINDING_LINE_RANGE"


def test_unavailable_raw_context_handled() -> None:
    """Behavior Protected: Unavailable raw context produces SanitizedContext with context_available=False and sanitized_snippet=None.

    Expected Result: res.context_available is False.
    Category: Fallback Path
    """
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, context_available=False)

    res = sanitize_context(finding, raw)
    assert res.context_available is False
    assert res.sanitized_snippet is None
    assert res.context_strategy == ContextStrategy.UNAVAILABLE


def test_inputs_not_mutated() -> None:
    """Behavior Protected: Input finding and raw_context objects are not mutated.

    Expected Result: Original field values unchanged.
    Category: Immutability
    """
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding)

    orig_rule = finding.rule_id
    orig_raw_id = raw.finding_id

    sanitize_context(finding, raw)

    assert finding.rule_id == orig_rule
    assert raw.finding_id == orig_raw_id


# --- 6. Forbidden Values Defense-in-Depth ---


def test_forbidden_value_redacted_success() -> None:
    """Behavior Protected: If a forbidden value is successfully redacted, context remains available.

    Expected Result: context_available is True, forbidden value redacted.
    Category: Defense-in-Depth Leak Check
    """
    secret_value = "super_secret_forbidden_token_99"
    code = f"api_key = '{secret_value}'\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw, forbidden_values=(secret_value,))

    assert res.context_available is True
    assert secret_value not in res.sanitized_snippet


def test_forbidden_value_leaked_causes_context_unavailable() -> None:
    """Behavior Protected: If a forbidden value remains unredacted in output, context becomes unavailable.

    Expected Result: context_available is False, sanitized_snippet is None.
    Category: Defense-in-Depth Leak Check
    """
    unredactable_secret = "unredactable_custom_canary_value"
    code = f"# Some comment with {unredactable_secret}\n"
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding, selected_text=code)

    res = sanitize_context(finding, raw, forbidden_values=(unredactable_secret,))

    assert res.context_available is False
    assert res.sanitized_snippet is None
    assert res.context_strategy == ContextStrategy.UNAVAILABLE


def test_forbidden_value_empty_or_placeholder_rejected() -> None:
    """Behavior Protected: Empty string or placeholder in forbidden_values parameter raises SastTriageError.

    Expected Result: SastTriageError raised.
    Category: Failure Path
    """
    finding = make_finding(start_line=1)
    raw = make_raw_context(finding)

    with pytest.raises(SastTriageError) as exc:
        sanitize_context(finding, raw, forbidden_values=("",))
    assert exc.value.error_code == "CONTEXT_INVALID_FORBIDDEN_VALUE"

    with pytest.raises(SastTriageError) as exc:
        sanitize_context(finding, raw, forbidden_values=(REDACTED_SECRET,))
    assert exc.value.error_code == "CONTEXT_INVALID_FORBIDDEN_VALUE"


# --- 7. Path Category Classification ---


def test_path_category_classification_examples() -> None:
    """Behavior Protected: Relative file paths are classified into correct PathCategory enum values.

    Expected Result: Correct PathCategory returned for fixtures, tests, docs, examples, and src.
    Category: Domain Classification
    """
    finding_fixture = make_finding(file_path="tests/fixtures/config.py")
    res_fixture = sanitize_context(finding_fixture, make_raw_context(finding_fixture))
    assert res_fixture.path_category == PathCategory.FIXTURE

    finding_test = make_finding(file_path="tests/unit/test_auth.py")
    res_test = sanitize_context(finding_test, make_raw_context(finding_test))
    assert res_test.path_category == PathCategory.TEST

    finding_doc = make_finding(file_path="docs/api.md")
    res_doc = sanitize_context(finding_doc, make_raw_context(finding_doc))
    assert res_doc.path_category == PathCategory.DOCUMENTATION

    finding_ex = make_finding(file_path="examples/demo.py")
    res_ex = sanitize_context(finding_ex, make_raw_context(finding_ex))
    assert res_ex.path_category == PathCategory.EXAMPLE

    finding_unk = make_finding(file_path="src/contest_service.py")
    res_unk = sanitize_context(finding_unk, make_raw_context(finding_unk))
    assert res_unk.path_category == PathCategory.UNKNOWN
