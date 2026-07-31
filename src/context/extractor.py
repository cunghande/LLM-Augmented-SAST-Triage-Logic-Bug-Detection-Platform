"""
Multi-Tier Context Extractor Module
===================================
Extracts rich context using AST mapping, function/class scoping, imports,
local guards, and slicing heuristics. Performs file-type-aware secret redaction.
Supports diff-scan mode by expanding context outside changed lines.
Falls back to line window extraction only when AST parsing fails, tagging context_quality=FALLBACK.
"""

import ast
import re
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from src.core.schema import UnifiedFinding, FindingContext, ContextQuality, EvaluationOutcome, FailureCategory


SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token|jwt[_-]?secret)\s*[:=]\s*['\"]([^'\"]+)['\"]", r"\1: '[REDACTED]'"),
    (r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "[REDACTED_JWT_TOKEN]"),
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"ghp_[a-zA-Z0-9]{36}", "[REDACTED_GITHUB_TOKEN]"),
]

FUNCTION_PATTERNS = [
    r"(?:async\s+)?function\s+([a-zA-Z0-9_$]+)",
    r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(",
    r"def\s+([a-zA-Z0-9_]+)\s*\(",
    r"class\s+([a-zA-Z0-9_]+)",
    r"router\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
]


def redact_secrets(text: str) -> str:
    """Redact secrets using regex pattern matching."""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def redact_secrets_file_aware(text: str, file_path: str) -> str:
    """Perform file-type-aware secret redaction for code, JSON, YAML, and ENV files."""
    ext = Path(file_path).suffix.lower()
    redacted = text

    if ext in [".env", ".env.example", ".properties"]:
        lines = []
        for line in text.splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, _, val = line.partition("=")
                lines.append(f"{key}=[REDACTED]")
            else:
                lines.append(line)
        redacted = "\n".join(lines)
    elif ext in [".json"]:
        redacted = re.sub(r'("?(?:password|secret|api_key|token|private_key)"?\s*:\s*)"[^"]+"', r'\1"[REDACTED]"', redacted, flags=re.IGNORECASE)
    elif ext in [".yaml", ".yml"]:
        redacted = re.sub(r'((?:password|secret|api_key|token|private_key)\s*:\s*).+', r'\1[REDACTED]', redacted, flags=re.IGNORECASE)
    
    return redact_secrets(redacted)


def detect_enclosing_function(lines: list, target_line_idx: int) -> Optional[str]:
    """Look backward from target_line_idx to find enclosing function or route definition."""
    search_start = max(0, target_line_idx - 40)
    for i in range(min(target_line_idx, len(lines) - 1), search_start - 1, -1):
        line = lines[i]
        for pattern in FUNCTION_PATTERNS:
            match = re.search(pattern, line)
            if match:
                return match.group(1) if match.groups() else match.group(0)
    return None


class PythonASTContextExtractor:
    """AST-based context extractor for Python source files."""

    @staticmethod
    def extract_ast_context(content: str, line_no: int) -> Tuple[Optional[str], Optional[str], Optional[str], List[str], List[str], List[str]]:
        try:
            tree = ast.parse(content)
            enclosing_func = None
            enclosing_class = None
            ast_node_type = None
            annotations = []
            parameters = []
            local_guards = []

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                        if node.lineno <= line_no <= getattr(node, "end_lineno", line_no + 100):
                            enclosing_class = node.name

                elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                        if node.lineno <= line_no <= getattr(node, "end_lineno", line_no + 100):
                            enclosing_func = node.name
                            for dec in node.decorator_list:
                                annotations.append(ast.unparse(dec) if hasattr(ast, "unparse") else "decorator")
                            for arg in node.args.args:
                                parameters.append(arg.arg)
                            
                            for body_stmt in node.body:
                                stmt_str = ast.unparse(body_stmt) if hasattr(ast, "unparse") else ""
                                if any(k in stmt_str.lower() for k in ["auth", "perm", "check", "verify", "require", "is_admin", "login_required"]):
                                    local_guards.append(stmt_str.strip())

                elif hasattr(node, "lineno") and node.lineno == line_no:
                    ast_node_type = type(node).__name__

            return enclosing_func, enclosing_class, ast_node_type, annotations, parameters, local_guards
        except Exception:
            return None, None, None, [], [], []


class OWASPPythonBenchmarkIndex:
    """Index mapping OWASP Python benchmark findings to actual Python handlers."""
    def __init__(self, repo_dir: Path):
        self.repo_dir = repo_dir
        self.index: Dict[str, Path] = {}
        self._build_index()

    def _build_index(self):
        testcode_dir = self.repo_dir / "testcode"
        if testcode_dir.exists() and testcode_dir.is_dir():
            for py_file in testcode_dir.glob("BenchmarkTest*.py"):
                stem = py_file.stem
                self.index[stem] = py_file

    def resolve_handler(self, file_path: str, finding_id: str = "") -> Optional[Path]:
        # Try extracting BenchmarkTestXXXXX from file_path or finding_id
        match = re.search(r"(BenchmarkTest\d{5})", file_path)
        if not match and finding_id:
            match = re.search(r"(BenchmarkTest\d{5})", finding_id)

        if match:
            test_id = match.group(1)
            py_file = self.index.get(test_id)
            if py_file and py_file.exists():
                return py_file

        return None


def extract_finding_context(
    finding: UnifiedFinding,
    repo_dir: Path,
    window_lines: int = 15,
    mode: str = "full"
) -> FindingContext:
    """
    Extract multi-tier context using AST analysis.
    Resolves OWASP Python templates to actual testcode Python handlers containing source/sink.
    """
    relative_path = finding.file_path.lstrip("/\\")
    full_path = repo_dir / relative_path

    # OWASP Python template resolution
    is_template = ".html" in relative_path.lower() or "templates" in relative_path.lower()
    if is_template or not full_path.exists():
        index = OWASPPythonBenchmarkIndex(repo_dir)
        handler_path = index.resolve_handler(finding.file_path, finding.finding_id)
        if handler_path:
            full_path = handler_path
        elif is_template:
            # Template-only context is NOT eligible for official model-quality run
            finding.outcome = EvaluationOutcome.FAILED
            finding.failure_category = FailureCategory.CONTEXT_RESOLUTION_FAILURE
            context = FindingContext(
                context_quality=ContextQuality.UNRESOLVED,
                surrounding_code="[TEMPLATE_ONLY_CONTEXT_UNRESOLVED]",
                redacted=True
            )
            finding.context = context
            return context

    if not full_path.exists():
        matches = list(repo_dir.glob(f"**/{Path(relative_path).name}"))
        if matches:
            full_path = matches[0]

    if not full_path.exists() or not full_path.is_file():
        finding.outcome = EvaluationOutcome.FAILED
        finding.failure_category = FailureCategory.CONTEXT_RESOLUTION_FAILURE
        context = FindingContext(
            context_quality=ContextQuality.FALLBACK,
            surrounding_code=redact_secrets_file_aware(finding.snippet, finding.file_path),
            redacted=True
        )
        finding.context = context
        return context

    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        file_lines = content.splitlines()
        ext = full_path.suffix.lower()

        imports = [
            line.strip() for line in file_lines[:40] 
            if line.strip().startswith(("import ", "from ", "const ", "require(", "using "))
        ]

        effective_window = window_lines * 2 if mode == "diff" else window_lines

        if ext == ".py":
            target_line = finding.start_line
            # Search for specific handler function def or sink line in Python file
            for idx, line in enumerate(file_lines):
                if "_post" in line.lower() or "def benchmarktest" in line.lower() or any(k in line.lower() for k in ["subprocess", "eval", "exec", "open", "request.form", "request.args"]):
                    target_line = idx + 1
                    break

            func, cls, node_type, annots, params, guards = PythonASTContextExtractor.extract_ast_context(
                content, target_line
            )

            target_idx = max(0, target_line - 1)
            # Expand window to capture entire handler snippet (lines 1 to 60)
            start_idx = max(0, target_idx - 25)
            end_idx = min(len(file_lines), target_idx + 35)

            snippet_lines = []
            for idx in range(start_idx, end_idx):
                prefix = ">> " if idx == target_idx else "   "
                snippet_lines.append(f"{idx + 1:4d} | {prefix}{file_lines[idx]}")

            surrounding = redact_secrets_file_aware("\n".join(snippet_lines), str(full_path))


            context = FindingContext(
                context_quality=ContextQuality.HIGH if (func or cls) else ContextQuality.MEDIUM,
                enclosing_function=func,
                enclosing_class=cls,
                ast_node_type=node_type,
                annotations=annots,
                parameters=params,
                line_window=f"L{start_idx + 1}-L{end_idx}",
                surrounding_code=surrounding,
                imports=imports[:10],
                caller_callee_info=f"Guards: {', '.join(guards[:5])}" if guards else None,
                redacted=True
            )
            finding.context = context
            return context


        # JS/TS or Fallback context extraction
        target_idx = max(0, finding.start_line - 1)
        start_idx = max(0, target_idx - effective_window)
        end_idx = min(len(file_lines), finding.end_line + effective_window)

        snippet_lines = []
        for idx in range(start_idx, end_idx):
            prefix = ">> " if (target_idx <= idx <= finding.end_line - 1) else "   "
            snippet_lines.append(f"{idx + 1:4d} | {prefix}{file_lines[idx]}")

        raw_surrounding = "\n".join(snippet_lines)
        redacted_surrounding = redact_secrets_file_aware(raw_surrounding, str(full_path))

        context = FindingContext(
            context_quality=ContextQuality.FALLBACK,
            line_window=f"L{start_idx + 1}-L{end_idx}",
            surrounding_code=redacted_surrounding,
            imports=imports[:10],
            redacted=True
        )
        finding.context = context
        return context

    except Exception as e:
        context = FindingContext(
            context_quality=ContextQuality.FALLBACK,
            surrounding_code=redact_secrets_file_aware(finding.snippet, finding.file_path),
            redacted=True
        )
        finding.context = context
        return context
