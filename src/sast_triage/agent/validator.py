"""ActionValidator: Strictly validates LLM-proposed actions before execution."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sast_triage.agent.models import ActionValidationResult, AgentAction
from sast_triage.agent.ledger import EvidenceLedger
from sast_triage.context.reader import _is_invalid_relative_path_string

ALLOWLISTED_TOOLS = frozenset({
    "trace_dataflow",
    "find_reachability",
    "inspect_security_control",
    "find_callers",
    "find_callees",
    "read_function",
    "get_route_decorators",
    "get_model_schema",
    "check_lock_or_transaction",
    "DONE",
})

_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\.]*$")


class ActionValidator:
    """Validates tool allowlists, parameter schemas, path containment, and query duplication."""

    def __init__(self, repository_root: Path) -> None:
        self._repository_root = repository_root.resolve()

    def validate_action(
        self,
        action: AgentAction,
        ledger: EvidenceLedger,
    ) -> ActionValidationResult:
        """Validate an agent action against all security and structural constraints."""
        tool = action.tool
        params = action.parameters

        # 1. Whitelist Check
        if tool not in ALLOWLISTED_TOOLS:
            return ActionValidationResult(
                is_valid=False,
                error_code="TOOL_NOT_ALLOWLISTED",
                error_message=f"Tool '{tool}' is not in allowlist of permitted actions.",
            )

        if tool == "DONE":
            return ActionValidationResult(
                is_valid=True,
                canonical_signature="DONE",
            )

        # 2. Parameter Schema & Path/Symbol Verification
        file_path: str | None = None
        symbol_name: str | None = None

        if tool in ("find_callees", "read_function", "get_route_decorators", "check_lock_or_transaction"):
            if not isinstance(params.get("symbol_name"), str) or not params["symbol_name"].strip():
                return ActionValidationResult(
                    is_valid=False,
                    error_code="MISSING_REQUIRED_SYMBOL",
                    error_message=f"Tool '{tool}' requires non-empty 'symbol_name'.",
                )
            if not isinstance(params.get("file_path"), str) or not params["file_path"].strip():
                return ActionValidationResult(
                    is_valid=False,
                    error_code="MISSING_REQUIRED_FILE",
                    error_message=f"Tool '{tool}' requires non-empty 'file_path'.",
                )
            symbol_name = params["symbol_name"].strip()
            file_path = params["file_path"].strip()

        elif tool == "find_callers":
            if not isinstance(params.get("symbol_name"), str) or not params["symbol_name"].strip():
                return ActionValidationResult(
                    is_valid=False,
                    error_code="MISSING_REQUIRED_SYMBOL",
                    error_message="find_callers requires non-empty 'symbol_name'.",
                )
            symbol_name = params["symbol_name"].strip()
            if "file_path" in params and params["file_path"]:
                file_path = str(params["file_path"]).strip()

        elif tool == "get_model_schema":
            if not isinstance(params.get("model_name"), str) or not params["model_name"].strip():
                return ActionValidationResult(
                    is_valid=False,
                    error_code="MISSING_REQUIRED_MODEL",
                    error_message="get_model_schema requires non-empty 'model_name'.",
                )
            symbol_name = params["model_name"].strip()
            if "file_path" in params and params["file_path"]:
                file_path = str(params["file_path"]).strip()

        elif tool in ("trace_dataflow", "find_reachability", "inspect_security_control"):
            symbol_name = params.get("target_symbol")

        # 3. Symbol Format Check
        if symbol_name and not _IDENTIFIER_REGEX.match(symbol_name):
            return ActionValidationResult(
                is_valid=False,
                error_code="INVALID_SYMBOL_FORMAT",
                error_message=f"Symbol '{symbol_name}' contains invalid identifier characters.",
            )

        # 4. Path Containment & Existence Check
        resolved_file_str = ""
        if file_path:
            if _is_invalid_relative_path_string(file_path):
                return ActionValidationResult(
                    is_valid=False,
                    error_code="PATH_TRAVERSAL_DETECTED",
                    error_message="file_path cannot be absolute, rooted, or contain invalid traversal tokens.",
                )

            # Prevent traversal sequences like '..'
            normalized_parts = Path(file_path).parts
            if ".." in normalized_parts:
                return ActionValidationResult(
                    is_valid=False,
                    error_code="PATH_TRAVERSAL_DETECTED",
                    error_message="file_path cannot contain '..' directory traversal segments.",
                )

            try:
                candidate = (self._repository_root / file_path).resolve()
                if not candidate.is_relative_to(self._repository_root):
                    return ActionValidationResult(
                        is_valid=False,
                        error_code="PATH_OUTSIDE_REPOSITORY",
                        error_message="file_path escapes repository root boundary.",
                    )
                if not candidate.is_file():
                    return ActionValidationResult(
                        is_valid=False,
                        error_code="FILE_NOT_FOUND",
                        error_message=f"Target file does not exist in repository: {file_path}",
                    )
                resolved_file_str = str(candidate.relative_to(self._repository_root)).replace("\\", "/")
            except Exception as exc:
                return ActionValidationResult(
                    is_valid=False,
                    error_code="PATH_VALIDATION_ERROR",
                    error_message=f"Could not validate path: {exc}",
                )

        # 5. Canonical Signature & Deduplication Check
        canonical_sig = f"{tool}:{resolved_file_str}:{symbol_name or ''}"
        if ledger.has_signature(canonical_sig):
            return ActionValidationResult(
                is_valid=False,
                error_code="DUPLICATE_QUERY",
                error_message=f"Action '{canonical_sig}' has already been executed in this session.",
                canonical_signature=canonical_sig,
            )

        return ActionValidationResult(
            is_valid=True,
            canonical_signature=canonical_sig,
        )
