"""JSON report writer for SAST Triage Platform.

Serializes a BatchResult to a UTF-8 JSON file using atomic write semantics
with defense-in-depth forbidden field and value leak checks.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sast_triage.errors import SastTriageError
from sast_triage.models import BatchResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Placeholder strings that are known-safe and must NOT be used as forbidden
# values (they exist specifically to replace secrets, not to be treated as
# secrets themselves).
_KNOWN_SAFE_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "<REDACTED_SECRET>",
        "<REDACTED_PRIVATE_KEY_BLOCK>",
        "<REDACTED_GITLEAKS_FINDING_LINE>",
    }
)

# Keys that must never appear in the serialized report dictionary tree.
# "snippet" from NormalizedFinding is intentionally excluded — it is a
# scanner-facing safe snippet per parser contract.
_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "sanitized_context",
        "sanitized_snippet",
        "raw_source",
        "source_snippet",
        "selected_text",
        "raw_match",
        "Secret",
        "function_body",
    }
)

# Error codes produced by this module.
_EC_INVALID_INPUT = "REPORT_INVALID_INPUT"
_EC_OUTPUT_EXISTS = "REPORT_OUTPUT_EXISTS"
_EC_FORBIDDEN_FIELD = "REPORT_FORBIDDEN_FIELD"
_EC_LEAK_CHECK_FAILED = "REPORT_LEAK_CHECK_FAILED"
_EC_WRITE_ERROR = "REPORT_WRITE_ERROR"
_EC_SERIALIZATION_ERROR = "REPORT_SERIALIZATION_ERROR"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_forbidden_keys(node: Any, *, path: str = "") -> None:
    """Recursively traverse a JSON-safe dictionary and raise if a forbidden
    key is encountered.

    Parameters
    ----------
    node:
        Current node in the serialized tree (dict, list, or scalar).
    path:
        Human-readable dotted key path for the error message (does not
        contain report payload values).
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _FORBIDDEN_KEYS:
                raise SastTriageError(
                    f"Serialized report contains forbidden field: {key!r}",
                    error_code=_EC_FORBIDDEN_FIELD,
                )
            _check_forbidden_keys(value, path=f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _check_forbidden_keys(item, path=f"{path}[{index}]")
    # Scalars (str, int, float, bool, None) are not keys — skip.


def _validate_input(
    batch_result: BatchResult,
    output_path: Path,
    forbidden_values: tuple[str, ...],
    overwrite: bool,
) -> None:
    """Validate all inputs before any serialization or file I/O.

    Raises SastTriageError with a safe message on any violation.
    """
    # --- batch_result type ---
    if not isinstance(batch_result, BatchResult):
        raise SastTriageError(
            "batch_result must be a BatchResult instance.",
            error_code=_EC_INVALID_INPUT,
        )

    # --- output_path basic checks ---
    if not isinstance(output_path, Path):
        raise SastTriageError(
            "output_path must be a pathlib.Path instance.",
            error_code=_EC_INVALID_INPUT,
        )
    if output_path == Path("") or str(output_path).strip() == "":
        raise SastTriageError(
            "output_path must not be an empty path.",
            error_code=_EC_INVALID_INPUT,
        )
    if output_path.is_dir():
        raise SastTriageError(
            "output_path points to a directory; a file path is required.",
            error_code=_EC_INVALID_INPUT,
        )

    parent = output_path.parent
    if not parent.exists():
        raise SastTriageError(
            "Parent directory of output_path does not exist.",
            error_code=_EC_INVALID_INPUT,
        )
    if not parent.is_dir():
        raise SastTriageError(
            "Parent of output_path is not a directory.",
            error_code=_EC_INVALID_INPUT,
        )

    # --- overwrite=False guard (checked early, before any I/O) ---
    if not overwrite and output_path.exists():
        raise SastTriageError(
            "Output file already exists and overwrite=False.",
            error_code=_EC_OUTPUT_EXISTS,
        )

    # --- forbidden_values ---
    for fv in forbidden_values:
        if not isinstance(fv, str) or not fv.strip():
            raise SastTriageError(
                "forbidden_values must not contain empty or whitespace-only strings.",
                error_code=_EC_INVALID_INPUT,
            )
        if fv in _KNOWN_SAFE_PLACEHOLDERS:
            raise SastTriageError(
                "forbidden_values contains a known-safe redaction placeholder "
                f"({fv!r}), which must not be treated as a secret.",
                error_code=_EC_INVALID_INPUT,
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write_json_report(
    batch_result: BatchResult,
    output_path: Path,
    *,
    forbidden_values: tuple[str, ...] = (),
    overwrite: bool = True,
) -> Path:
    """Serialize a BatchResult to a UTF-8 JSON file with atomic write semantics.

    The function performs defense-in-depth leak checks before any disk I/O:

    1. Structural forbidden-key check on the serialized dictionary tree.
    2. Substring forbidden-value check on the final JSON text.

    The file is written to a temporary sibling path and atomically renamed
    to *output_path* only after all checks pass.

    Parameters
    ----------
    batch_result:
        The completed batch triage result to serialize.
    output_path:
        Destination file path. The parent directory must already exist.
    forbidden_values:
        Caller-supplied strings that must not appear in the serialized JSON.
        Used to carry canary / secret values that would indicate a leak.
        Must not be empty, whitespace-only, or known-safe placeholders.
    overwrite:
        If *False*, raise ``REPORT_OUTPUT_EXISTS`` when *output_path* already
        exists. If *True* (default), atomically replace the existing file.

    Returns
    -------
    Path
        The resolved path of the written report file.

    Raises
    ------
    SastTriageError
        On any input validation failure, forbidden field/value detection,
        or I/O error. The ``error_code`` attribute identifies the category.
    """
    # Step 1 – input validation (fast-fail, no I/O except stat calls).
    _validate_input(batch_result, output_path, forbidden_values, overwrite)

    # Step 2 – serialization (entirely in memory, no file created yet).
    try:
        # Pydantic v2: mode="json" serializes enums as string values and
        # datetimes as ISO-8601 strings.  We request a plain dict so that
        # json.dumps controls formatting.
        serialized_dict: dict[str, Any] = batch_result.model_dump(mode="json")
    except Exception as exc:
        raise SastTriageError(
            "Serialization of BatchResult failed unexpectedly.",
            error_code=_EC_SERIALIZATION_ERROR,
        ) from exc

    # Step 3 – structural forbidden-key check on the dict tree.
    _check_forbidden_keys(serialized_dict)

    # Step 4 – convert dict to JSON text.
    try:
        json_text: str = json.dumps(
            serialized_dict,
            indent=2,
            ensure_ascii=False,
        )
        # Guarantee trailing newline.
        if not json_text.endswith("\n"):
            json_text += "\n"
    except Exception as exc:
        raise SastTriageError(
            "JSON encoding of serialized report failed.",
            error_code=_EC_SERIALIZATION_ERROR,
        ) from exc

    # Step 5 – forbidden-value substring check on final text.
    # Deduplicate to avoid redundant scans without storing values.
    seen_forbidden: set[str] = set()
    for fv in forbidden_values:
        if fv in seen_forbidden:
            continue
        seen_forbidden.add(fv)
        if fv in json_text:
            raise SastTriageError(
                "Serialized report contains a forbidden value. Report not written.",
                error_code=_EC_LEAK_CHECK_FAILED,
            )
    del seen_forbidden  # Explicit cleanup — forbidden values must not linger.

    # Step 6 – atomic write.
    #
    # Create a temporary file in the same directory as the output so that
    # os.replace() is guaranteed to be atomic (same filesystem).
    # Do NOT use a predictable global temp path.
    parent_dir = output_path.parent
    tmp_path: Path | None = None

    try:
        # delete=False: we manage the lifetime manually so that we can rename
        # the file atomically.  On Windows, NamedTemporaryFile with delete=True
        # cannot be renamed while open.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent_dir,
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(json_text)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        # os.replace is atomic on POSIX; on Windows it overwrites atomically.
        os.replace(tmp_path, output_path)
        tmp_path = None  # Successfully renamed; no cleanup needed.
    except SastTriageError:
        raise  # Re-raise our own errors without wrapping.
    except Exception as exc:
        raise SastTriageError(
            "Failed to write JSON report to disk.",
            error_code=_EC_WRITE_ERROR,
        ) from exc
    finally:
        # Best-effort cleanup of the temporary file if rename did not occur.
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass  # Cannot do much here; the temp file will be left behind.

    return output_path.resolve()
