import re
from pathlib import Path
from typing import Optional, Tuple
from src.core.schema import UnifiedFinding, FindingContext


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
    """Redact hardcoded secrets from code snippet or text."""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def detect_enclosing_function(lines: list, target_line_idx: int) -> Optional[str]:
    """Look backward from target_line_idx to find the enclosing function or route definition."""
    search_start = max(0, target_line_idx - 40)
    for i in range(target_line_idx, search_start - 1, -1):
        line = lines[i]
        for pattern in FUNCTION_PATTERNS:
            match = re.search(pattern, line)
            if match:
                return match.group(1) if match.groups() else match.group(0)
    return None


def extract_finding_context(
    finding: UnifiedFinding,
    repo_dir: Path,
    window_lines: int = 15
) -> FindingContext:
    """Extract code context window and enclosing function for a finding."""
    relative_path = finding.file_path.lstrip("/\\")
    full_path = repo_dir / relative_path

    if not full_path.exists():
        # Try finding file recursively if exact relative path fails
        matches = list(repo_dir.glob(f"**/{Path(relative_path).name}"))
        if matches:
            full_path = matches[0]

    if not full_path.exists() or not full_path.is_file():
        context = FindingContext(
            surrounding_code=redact_secrets(finding.snippet),
            redacted=True
        )
        finding.context = context
        return context

    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        file_lines = content.splitlines()
        
        target_idx = max(0, finding.start_line - 1)
        start_idx = max(0, target_idx - window_lines)
        end_idx = min(len(file_lines), finding.end_line + window_lines)

        snippet_lines = []
        for idx in range(start_idx, end_idx):
            prefix = ">> " if (target_idx <= idx <= finding.end_line - 1) else "   "
            snippet_lines.append(f"{idx + 1:4d} | {prefix}{file_lines[idx]}")

        raw_surrounding = "\n".join(snippet_lines)
        redacted_surrounding = redact_secrets(raw_surrounding)
        
        enclosing_func = detect_enclosing_function(file_lines, target_idx)

        # Extract imports from top 30 lines
        imports = [line.strip() for line in file_lines[:30] if line.strip().startswith(("import ", "const ", "require("))]

        context = FindingContext(
            enclosing_function=enclosing_func,
            line_window=f"L{start_idx + 1}-L{end_idx}",
            surrounding_code=redacted_surrounding,
            imports=imports[:10],
            redacted=True
        )
        finding.context = context
        return context
    except Exception as e:
        context = FindingContext(
            surrounding_code=redact_secrets(finding.snippet),
            redacted=True
        )
        finding.context = context
        return context
