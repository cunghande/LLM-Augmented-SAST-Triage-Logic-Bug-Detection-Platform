"""Tests for fail-closed bounded Python path verification."""

import pytest

from sast_triage.context.local_verifier import (
    verify_intrinsic_security_usage,
    verify_sanitized_python_flow,
)
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    ScannerType,
    Severity,
)


def _finding(rule_id: str, line: int) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=f"local-verifier-{line}",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        file_path="app.py",
        start_line=line,
        end_line=line,
        severity=Severity.HIGH,
        message="safe test message",
    )


@pytest.mark.parametrize(
    ("code", "rule_id", "sink_line"),
    [
        (
            """\
def endpoint():
    param = request.headers.get("value")
    possible = "ABC"
    guess = possible[1]
    match guess:
        case "A":
            bar = param
        case "B":
            bar = "safe"
        case _:
            bar = param
    return pickle.loads(base64.b64decode(bar))
""",
            "python.security.insecure-deserialization",
            12,
        ),
        (
            """\
def endpoint():
    param = request.args.get("value")
    number = 86
    if 7 * 42 - number > 200:
        bar = "safe"
    else:
        bar = param
    return yaml.load(bar)
""",
            "python.security.insecure-deserialization",
            8,
        ),
        (
            """\
def endpoint():
    param = request.args.get("value")
    values = []
    values.append("safe")
    values.append(param)
    values.append("more-safe")
    values.pop(0)
    bar = values[1]
    return pickle.loads(bar)
""",
            "python.security.insecure-deserialization",
            9,
        ),
    ],
)
def test_path_sensitive_verifier_proves_safe_final_values(
    code: str,
    rule_id: str,
    sink_line: int,
) -> None:
    result = verify_sanitized_python_flow(
        _finding(rule_id, sink_line),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is True
    assert result.target_paths > 0


def test_path_sensitive_verifier_does_not_clear_attacker_flow() -> None:
    code = """\
def endpoint():
    param = request.form.get("value")
    command = f"echo {param}"
    return subprocess.run(command, shell=True)
"""

    result = verify_sanitized_python_flow(
        _finding("python.audit.subprocess-shell-true", 4),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is False


def test_unknown_loop_assignment_fails_closed() -> None:
    code = """\
def endpoint():
    param = ""
    for name in request.form.keys():
        param = name
    command = f"echo {param}"
    return subprocess.run(command, shell=True)
"""

    result = verify_sanitized_python_flow(
        _finding("python.audit.subprocess-shell-true", 6),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is False


def test_guard_return_is_reported_but_not_assumed_effective() -> None:
    code = """\
def endpoint():
    param = request.args.get("name")
    if "../" in param:
        return "blocked"
    return open(param)
"""

    result = verify_sanitized_python_flow(
        _finding("python.security.path-traversal-open", 5),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is False
    assert result.unresolved_guard_observed is True


def test_static_route_proves_request_path_segment_is_not_attacker_controlled() -> None:
    code = """\
@app.route("/fixed/endpoint")
def endpoint():
    parts = request.path.split("/")
    param = parts[1]
    return pickle.loads(param)
"""

    result = verify_sanitized_python_flow(
        _finding("python.security.insecure-deserialization", 5),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is True


def test_dynamic_route_does_not_prove_request_path_safe() -> None:
    code = """\
@app.route("/objects/<object_id>")
def endpoint(object_id):
    parts = request.path.split("/")
    param = parts[2]
    return pickle.loads(param)
"""

    result = verify_sanitized_python_flow(
        _finding("python.security.insecure-deserialization", 5),
        code,
        context_start_line=1,
    )

    assert result.negative_taint_proven is False


def test_intrinsic_hash_usage_is_proven_for_sensitive_storage() -> None:
    code = """\
def endpoint(value):
    digest = hashlib.md5(value).digest()
    password_file = open("passwordFile.txt", "ab")
    password_file.write(digest)
"""

    result = verify_intrinsic_security_usage(
        _finding("python.security.insecure-hash-algorithm-md5", 2),
        code,
        context_start_line=1,
    )

    assert result.security_sensitive_usage_proven is True
    assert result.usage_kind == "security_sensitive_storage"


def test_intrinsic_hash_checksum_does_not_gain_security_proof() -> None:
    code = """\
def checksum(value):
    digest = hashlib.md5(value).hexdigest()
    output = open("cache-checksum.txt", "w")
    output.write(digest)
"""

    result = verify_intrinsic_security_usage(
        _finding("python.security.insecure-hash-algorithm-md5", 2),
        code,
        context_start_line=1,
    )

    assert result.security_sensitive_usage_proven is False


def test_unrelated_sensitive_literal_does_not_gain_security_proof() -> None:
    code = """\
def checksum(value):
    digest = hashlib.sha1(value).hexdigest()
    log.info("password reset requested")
    return digest
"""

    result = verify_intrinsic_security_usage(
        _finding("python.security.insecure-hash-algorithm-sha1", 2),
        code,
        context_start_line=1,
    )

    assert result.security_sensitive_usage_proven is False
