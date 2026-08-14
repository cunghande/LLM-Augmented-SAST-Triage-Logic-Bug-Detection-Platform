"""Joint audit integration tests for full context extraction & sanitization pipeline.

Pipeline flow tested:
read_repository_source
  -> select_python_scope
  -> select_raw_context
  -> sanitize_context
  -> SanitizedContext
"""

from pathlib import Path

from sast_triage.context import (
    PythonScopeResult,
    SourceReadResult,
    read_repository_source,
    sanitize_context,
    select_python_scope,
    select_raw_context,
)
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    MissingContextReason,
    NormalizedFinding,
    SanitizedContext,
    ScannerType,
    Severity,
)

CANARY_SECRET = "PIPELINE_CANARY_SECRET_DO_NOT_LEAK"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    file_path: str = "app/service.py",
    start_line: int = 5,
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


# --- 1. Semgrep AST Success End-to-End ---


def test_pipeline_semgrep_ast_success(tmp_path: Path) -> None:
    """Requirement Protected: Semgrep finding in valid Python function uses PYTHON_FUNCTION end-to-end.

    Pipeline Stages: read_repository_source -> select_python_scope -> select_raw_context -> sanitize_context.
    Expected Output: strategy PYTHON_FUNCTION, password redacted, canary absent from serialization.
    Test Category: End-to-End Happy Path
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "service.py"
    source_file.parent.mkdir(parents=True)

    code = f"""import os

class PaymentService:
    def process_payment(self, amount):
        # Sensitive credential assignment
        password = '{CANARY_SECRET}'
        return f"Paid {{amount}}"
"""
    source_file.write_text(code, encoding="utf-8")

    # Step 1: Read source
    src_res = read_repository_source(repo_root, "app/service.py")
    assert isinstance(src_res, SourceReadResult)

    # Step 2: Python Scope AST Analysis (finding on line 6: password = ...)
    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/service.py", start_line=6, end_line=6)
    scope_res = select_python_scope(src_res, finding.start_line, finding.end_line)
    assert isinstance(scope_res, PythonScopeResult)
    assert scope_res.strategy == ContextStrategy.PYTHON_FUNCTION
    assert scope_res.enclosing_function == "process_payment"
    assert scope_res.enclosing_class == "PaymentService"

    # Step 3: Raw Context Selection
    raw_res = select_raw_context(finding, src_res, scope_res)
    assert raw_res.strategy == ContextStrategy.PYTHON_FUNCTION

    # Step 4: Context Sanitization
    sanitized = sanitize_context(finding, raw_res)
    assert isinstance(sanitized, SanitizedContext)
    assert sanitized.context_strategy == ContextStrategy.PYTHON_FUNCTION
    assert sanitized.context_available is True
    assert sanitized.enclosing_function == "process_payment"
    assert sanitized.enclosing_class == "PaymentService"
    assert CANARY_SECRET not in sanitized.sanitized_snippet
    assert "<REDACTED_SECRET>" in sanitized.sanitized_snippet

    # Verify serialization boundary safety
    dump_json = sanitized.model_dump_json()
    assert CANARY_SECRET not in dump_json


# --- 2. Semgrep AST Fallback End-to-End ---


def test_pipeline_semgrep_ast_fallback(tmp_path: Path) -> None:
    """Requirement Protected: Semgrep finding in broken Python source falls back to LINE_WINDOW strategy.

    Pipeline Stages: read_repository_source -> select_python_scope -> select_raw_context -> sanitize_context.
    Expected Output: strategy LINE_WINDOW, diagnostic semantics preserved, credential sanitized.
    Test Category: End-to-End Fallback
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "broken.py"
    source_file.parent.mkdir(parents=True)

    code = f"""def broken_syntax(:
    api_key = '{CANARY_SECRET}'
"""
    source_file.write_text(code, encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/broken.py")
    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/broken.py", start_line=2)

    scope_res = select_python_scope(src_res, finding.start_line)
    assert scope_res.strategy == ContextStrategy.UNAVAILABLE

    raw_res = select_raw_context(finding, src_res, scope_res)
    assert raw_res.strategy == ContextStrategy.LINE_WINDOW

    sanitized = sanitize_context(finding, raw_res)
    assert sanitized.context_strategy == ContextStrategy.LINE_WINDOW
    assert sanitized.context_available is True
    assert CANARY_SECRET not in sanitized.sanitized_snippet
    assert "<REDACTED_SECRET>" in sanitized.sanitized_snippet


# --- 3. Gitleaks Masking End-to-End ---


def test_pipeline_gitleaks_masking(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks finding line is masked line-by-line while preserving line count and safe surrounding lines.

    Pipeline Stages: read_repository_source -> select_python_scope -> select_raw_context -> sanitize_context.
    Expected Output: strategy REDACTED_LINE_WINDOW, finding line masked with '# <REDACTED_GITLEAKS_FINDING_LINE>', raw secret absent from json/dump/repr/str.
    Test Category: End-to-End Security
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "config.py"
    source_file.parent.mkdir(parents=True)

    code = f"""def load_credentials():
    # Safe comment
    AWS_SECRET = '{CANARY_SECRET}'
    return True
"""
    source_file.write_text(code, encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/config.py")
    finding = make_finding(scanner=ScannerType.GITLEAKS, file_path="app/config.py", start_line=3)

    scope_res = select_python_scope(src_res, finding.start_line)
    raw_res = select_raw_context(finding, src_res, scope_res)
    assert raw_res.strategy == ContextStrategy.LINE_WINDOW

    sanitized = sanitize_context(finding, raw_res)
    assert sanitized.context_strategy == ContextStrategy.REDACTED_LINE_WINDOW
    assert sanitized.context_available is True
    assert "# <REDACTED_GITLEAKS_FINDING_LINE>" in sanitized.sanitized_snippet
    assert "def load_credentials():" in sanitized.sanitized_snippet
    assert "return True" in sanitized.sanitized_snippet

    # Security check: secret absent from all representations
    assert CANARY_SECRET not in sanitized.model_dump_json()
    assert CANARY_SECRET not in str(sanitized.model_dump())
    assert CANARY_SECRET not in repr(sanitized)
    assert CANARY_SECRET not in str(sanitized)


# --- 4. Truncated Context End-to-End ---


def test_pipeline_truncated_context(tmp_path: Path) -> None:
    """Requirement Protected: Truncated context preserves finding lines and applies line-offset masking accurately.

    Pipeline Stages: read_repository_source -> select_raw_context -> sanitize_context.
    Expected Output: final truncated=True, line mapping accurate, finding line masked.
    Test Category: End-to-End Boundary & Truncation
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "large.py"
    source_file.parent.mkdir(parents=True)

    # 40 lines of text, finding on line 20
    lines = [f"# line {i:02d} " + ("X" * 30) + "\n" for i in range(1, 41)]
    lines[19] = f"    SECRET = '{CANARY_SECRET}'\n"  # line 20
    source_file.write_text("".join(lines), encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/large.py")
    finding = make_finding(scanner=ScannerType.GITLEAKS, file_path="app/large.py", start_line=20)

    # Force truncation by restricting max_context_characters to 200
    raw_res = select_raw_context(finding, src_res, line_window_before=15, line_window_after=15, max_context_characters=200)
    assert raw_res.truncated is True
    assert raw_res.context_start_line > 1

    sanitized = sanitize_context(finding, raw_res)
    assert sanitized.truncated is True
    assert sanitized.context_available is True
    assert "# <REDACTED_GITLEAKS_FINDING_LINE>" in sanitized.sanitized_snippet
    assert CANARY_SECRET not in sanitized.sanitized_snippet


# --- 5. Unavailable Context End-to-End ---


def test_pipeline_unavailable_context(tmp_path: Path) -> None:
    """Requirement Protected: Finding line exceeding character limit results in unavailable context with proper missing reason.

    Pipeline Stages: read_repository_source -> select_raw_context -> sanitize_context.
    Expected Output: context_available=False, sanitized_snippet=None, MissingContextReason.SOURCE_FILE_TOO_LARGE.
    Test Category: End-to-End Failure Path
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "huge_line.py"
    source_file.parent.mkdir(parents=True)

    # Single line exceeding 500 characters
    huge_line = "# line 1 " + ("Y" * 600) + "\n"
    source_file.write_text(huge_line, encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/huge_line.py")
    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/huge_line.py", start_line=1)

    raw_res = select_raw_context(finding, src_res, max_context_characters=200)
    assert raw_res.context_available is False

    sanitized = sanitize_context(finding, raw_res)
    assert sanitized.context_available is False
    assert sanitized.sanitized_snippet is None
    assert sanitized.context_strategy == ContextStrategy.UNAVAILABLE
    assert MissingContextReason.SOURCE_FILE_TOO_LARGE in sanitized.missing_context_reasons


# --- 6. Forbidden-Value Failure & Cleanup End-to-End ---


def test_pipeline_forbidden_value_failure(tmp_path: Path) -> None:
    """Requirement Protected: Unredacted forbidden value causes CONTEXT_SANITIZATION_FAILED and full cleanup of output text fields.

    Pipeline Stages: read_repository_source -> select_raw_context -> sanitize_context.
    Expected Output: context_available=False, missing_context_reasons=[CONTEXT_SANITIZATION_FAILED], limited_imports=None, limited_decorators=None, forbidden value absent from output.
    Test Category: End-to-End Security & Cleanup
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "unredactable.py"
    source_file.parent.mkdir(parents=True)

    unredactable = "FORBIDDEN_CUSTOM_TOKEN_99999"
    code = f"# Custom comment: {unredactable}\ndef fn(): pass\n"
    source_file.write_text(code, encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/unredactable.py")
    finding = make_finding(scanner=ScannerType.SEMGREP, file_path="app/unredactable.py", start_line=1)

    raw_res = select_raw_context(finding, src_res)

    sanitized = sanitize_context(finding, raw_res, forbidden_values=(unredactable,))
    assert sanitized.context_available is False
    assert sanitized.sanitized_snippet is None
    assert sanitized.limited_imports is None
    assert sanitized.limited_decorators is None
    assert sanitized.context_strategy == ContextStrategy.UNAVAILABLE
    assert sanitized.missing_context_reasons == [MissingContextReason.CONTEXT_SANITIZATION_FAILED]

    # Security check: forbidden value not in serialized output
    dump_json = sanitized.model_dump_json()
    assert unredactable not in dump_json
    assert "INVALID_FINDING_LINE_RANGE" not in dump_json


# --- 7. Gitleaks Line Mapping Offset Audit ---


def test_pipeline_gitleaks_line_mapping_offset(tmp_path: Path) -> None:
    """Requirement Protected: Gitleaks line masking relative index calculation is exact when context_start_line > 1.

    Pipeline Stages: read_repository_source -> select_raw_context -> sanitize_context.
    Expected Output: Exactly line 25 masked, lines 24 and 26 preserved unmasked.
    Test Category: Edge Case Line Mapping
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_file = repo_root / "app" / "offset.py"
    source_file.parent.mkdir(parents=True)

    lines = [f"    var_{i:02d} = {i}\n" for i in range(1, 51)]
    lines[24] = f"    SECRET_KEY = '{CANARY_SECRET}'\n"  # line 25 (1-based)
    source_file.write_text("".join(lines), encoding="utf-8")

    src_res = read_repository_source(repo_root, "app/offset.py")
    finding = make_finding(scanner=ScannerType.GITLEAKS, file_path="app/offset.py", start_line=25)

    raw_res = select_raw_context(finding, src_res, line_window_before=5, line_window_after=5)
    assert raw_res.context_start_line == 20
    assert raw_res.context_end_line == 30

    sanitized = sanitize_context(finding, raw_res)
    assert sanitized.context_available is True
    snippet_lines = sanitized.sanitized_snippet.splitlines()

    # Index of line 25 in snippet (context starts at line 20, so line 25 is index 5)
    assert "# <REDACTED_GITLEAKS_FINDING_LINE>" in snippet_lines[5]
    assert "var_24 = 24" in snippet_lines[4]
    assert "var_26 = 26" in snippet_lines[6]
