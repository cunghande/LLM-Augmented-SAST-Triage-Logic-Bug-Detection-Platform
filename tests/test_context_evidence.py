"""Tests for bounded context evidence and system-controlled expansion."""

from pathlib import Path

from sast_triage.analysis.base import GraphEvidence
from sast_triage.context.evidence_agent import EvidenceExpansionAgent
from sast_triage.context.evidence_engine import CoreAnalysisEngine
from sast_triage.context.evidence_models import EvidenceStatus
from sast_triage.context.evidence_service import (
    _merge_bounded_local_verification,
    build_evidence_context,
    project_evidence,
)
from sast_triage.context.evidence_tools import EvidenceToolbox
from sast_triage.context.reader import SourceReadResult
from sast_triage.context.sufficiency import requires_context_expansion
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
    TriageInput,
)
from sast_triage.pipeline.finding import triage_finding
from sast_triage.triage.fake_provider import FakeTriageProvider


def _inputs(
    code: str,
    finding_line: int,
    *,
    sanitized_code: str | None = None,
) -> tuple[NormalizedFinding, SourceReadResult, SanitizedContext]:
    line_count = len(code.splitlines())
    finding = NormalizedFinding(
        finding_instance_id="evidence-finding-001",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.security.test",
        rule_name="Test rule",
        file_path="app.py",
        start_line=finding_line,
        end_line=finding_line,
        severity=Severity.HIGH,
        message="Potential security-sensitive data flow.",
        metadata={"category": "security"},
    )
    source = SourceReadResult(
        relative_path="app.py",
        text=code,
        size_bytes=len(code.encode("utf-8")),
    )
    context = SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet=sanitized_code if sanitized_code is not None else code,
        context_strategy=ContextStrategy.PYTHON_FUNCTION,
        context_start_line=1,
        context_end_line=line_count,
        finding_start_line=finding_line,
        finding_end_line=finding_line,
        enclosing_function=None,
        enclosing_class=None,
        limited_imports=None,
        limited_decorators=None,
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
        missing_context_reasons=[],
        redactions_applied=0,
        redaction_types=[],
        truncated=False,
    )
    return finding, source, context


def test_source_and_sink_in_same_function_is_complete() -> None:
    code = (
        "def handler():\n"
        "    user = request.args.get('q')\n"
        "    cursor.execute(user)\n"
    )
    finding, source, context = _inputs(code, 3)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.source is not None
    assert evidence.source.user_controlled is True
    assert evidence.sink is not None
    assert evidence.sink.sink_type == "sql_query"
    assert evidence.taint_path.path_type == "local"
    assert evidence.taint_path.source_reaches_sink is True
    assert evidence.context_completeness.status == EvidenceStatus.COMPLETE
    assert requires_context_expansion(evidence) is False


def test_branch_default_does_not_hide_request_source_through_f_string() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    if not param:\n"
        "        param = ''\n"
        "    filename = f'/tmp/{param}'\n"
        "    open(filename, 'wb')\n"
    )
    finding, source, context = _inputs(code, 6)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.source is not None
    assert evidence.source.user_controlled is True
    assert evidence.taint_path.source_reaches_sink is True


def test_dictionary_write_and_augmented_f_string_preserve_taint() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    values = {}\n"
        "    values['selected'] = param\n"
        "    bar = values['selected']\n"
        "    command = 'sh -c '\n"
        "    command += f'echo {bar}'\n"
        "    subprocess.run(command, shell=True)\n"
    )
    finding, source, context = _inputs(code, 8)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.source is not None
    assert evidence.source.user_controlled is True
    assert evidence.taint_path.source_reaches_sink is True


def test_constant_match_selects_only_feasible_safe_assignment() -> None:
    code = (
        "def handler():\n"
        "    param = request.headers.get('value')\n"
        "    selector = 'ABC'[1]\n"
        "    match selector:\n"
        "        case 'A':\n"
        "            bar = param\n"
        "        case 'B':\n"
        "            bar = 'safe'\n"
        "    pickle.loads(bar)\n"
    )
    finding, source, context = _inputs(code, 9)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.source is not None
    assert evidence.source.source_type == "local_constant"
    assert evidence.source.user_controlled is False
    assert evidence.taint_path.source_reaches_sink is False


def test_constant_if_and_transparent_decode_prove_safe_final_value() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    number = 86\n"
        "    if 7 * 42 - number > 200:\n"
        "        value = 'fixed'\n"
        "    else:\n"
        "        value = param\n"
        "    decoded = base64.b64decode(value)\n"
        "    pickle.loads(decoded)\n"
    )
    finding, source, context = _inputs(code, 9)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.taint_path.source_reaches_sink is False
    assert evidence.context_completeness.status == EvidenceStatus.COMPLETE


def test_config_get_for_same_literal_key_resolves_constant_value() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    config.set('section', 'unsafe', param)\n"
        "    config.set('section', 'safe', 'fixed')\n"
        "    value = config.get('section', 'safe')\n"
        "    subprocess.run(value, shell=True)\n"
    )
    finding, source, context = _inputs(code, 6)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.taint_path.source_reaches_sink is False
    assert evidence.context_completeness.status == EvidenceStatus.COMPLETE


def test_early_exit_parent_path_guard_is_effective_for_target_sink() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    if '../' in param:\n"
        "        return 'blocked'\n"
        "    filename = f'/tmp/{param}'\n"
        "    open(filename, 'rb')\n"
    )
    finding, source, context = _inputs(code, 6)

    evidence = CoreAnalysisEngine(finding, source, context).build_evidence()

    assert evidence.security_controls[0].symbol == "early_exit_path_validation"
    assert evidence.security_controls[0].effective is True


def test_path_sensitive_negative_refines_joern_may_flow() -> None:
    code = (
        "def handler():\n"
        "    param = request.form.get('value')\n"
        "    value = param\n"
        "    value = 'fixed'\n"
        "    subprocess.run(value, shell=True)\n"
    )
    finding, source, context = _inputs(code, 5)
    local = CoreAnalysisEngine(finding, source, context).build_evidence()
    graph = GraphEvidence(
        sink_symbol="run",
        source_type="user_controlled_call",
        source_reaches_sink=True,
        path_complete=True,
        reachability_resolved=True,
        provenance=("JOERN_CPG", "JOERN_DATAFLOW"),
    )

    merged = _merge_bounded_local_verification(finding, graph, local)

    assert merged.source_reaches_sink is False
    assert "BOUNDED_LOCAL_NEGATIVE_PROOF" in merged.provenance
    assert "JOERN_MAY_FLOW_REFINED_BY_LOCAL_PROOF" in merged.provenance


def test_local_positive_never_refines_joern_flow_to_negative() -> None:
    code = (
        "def handler():\n"
        "    value = request.form.get('value')\n"
        "    subprocess.run(value, shell=True)\n"
    )
    finding, source, context = _inputs(code, 3)
    local = CoreAnalysisEngine(finding, source, context).build_evidence()
    graph = GraphEvidence(
        sink_symbol="run",
        source_type="user_controlled_call",
        source_reaches_sink=True,
        path_complete=True,
        reachability_resolved=True,
        provenance=("JOERN_CPG", "JOERN_DATAFLOW"),
    )

    merged = _merge_bounded_local_verification(finding, graph, local)

    assert merged.source_reaches_sink is True
    assert "BOUNDED_LOCAL_NEGATIVE_PROOF" not in merged.provenance


def test_source_in_caller_and_sink_in_callee_is_expanded() -> None:
    code = (
        "def execute_query(query):\n"
        "    cursor.execute(query)\n"
        "\n"
        "def handler():\n"
        "    value = request.args.get('q')\n"
        "    execute_query(value)\n"
    )
    finding, source, context = _inputs(code, 2)
    engine = CoreAnalysisEngine(finding, source, context)

    initial = engine.build_evidence()
    expanded = EvidenceExpansionAgent(engine).expand()

    assert requires_context_expansion(initial) is True
    assert expanded.tool_calls <= 5
    assert expanded.evidence.source is not None
    assert expanded.evidence.taint_path.path_type == "interprocedural"
    assert expanded.evidence.taint_path.source_reaches_sink is True
    assert expanded.evidence.context_completeness.status == EvidenceStatus.COMPLETE


def test_valid_custom_sanitizer_breaks_taint_path() -> None:
    code = (
        "import html\n"
        "def custom_sanitize(value):\n"
        "    return html.escape(value)\n"
        "\n"
        "def handler():\n"
        "    user = request.args.get('q')\n"
        "    safe = custom_sanitize(user)\n"
        "    return render_template_string(safe)\n"
    )
    finding, source, context = _inputs(code, 8)
    engine = CoreAnalysisEngine(finding, source, context)

    expanded = EvidenceExpansionAgent(engine).expand().evidence

    assert expanded.security_controls[0].symbol == "custom_sanitize"
    assert expanded.security_controls[0].effective is True
    assert expanded.security_controls[0].protects_target is True
    assert expanded.taint_path.source_reaches_sink is False
    assert expanded.context_completeness.status == EvidenceStatus.COMPLETE


def test_invalid_custom_sanitizer_does_not_break_taint_path() -> None:
    code = (
        "def custom_sanitize(value):\n"
        "    return value\n"
        "\n"
        "def handler():\n"
        "    user = request.args.get('q')\n"
        "    safe = custom_sanitize(user)\n"
        "    return render_template_string(safe)\n"
    )
    finding, source, context = _inputs(code, 7)
    engine = CoreAnalysisEngine(finding, source, context)

    expanded = EvidenceExpansionAgent(engine).expand().evidence

    assert expanded.security_controls[0].effective is False
    assert expanded.security_controls[0].protects_target is False
    assert expanded.taint_path.source_reaches_sink is True
    assert expanded.context_completeness.status == EvidenceStatus.COMPLETE


def test_unresolved_source_remains_partial_and_requires_review() -> None:
    code = "def execute_query(query):\n    cursor.execute(query)\n"
    finding, source, context = _inputs(code, 2)

    expanded = EvidenceExpansionAgent(CoreAnalysisEngine(finding, source, context)).expand()

    assert expanded.tool_calls <= 5
    assert expanded.evidence.source is None
    assert expanded.evidence.context_completeness.status == EvidenceStatus.PARTIAL
    assert "SOURCE_NOT_RESOLVED" in expanded.evidence.context_completeness.missing_information
    assert requires_context_expansion(expanded.evidence) is True


def test_tool_wrapper_shape_and_limits() -> None:
    code = "def execute_query(query):\n    cursor.execute(query)\n"
    finding, source, context = _inputs(code, 2)
    engine = CoreAnalysisEngine(finding, source, context)
    toolbox = EvidenceToolbox(engine)

    result = toolbox.trace_taint_path(finding.finding_instance_id, 5)
    invalid_depth = toolbox.find_callers(engine.target_function_id() or "", 6)

    assert set(result.to_json_dict()) == {
        "status",
        "complete",
        "evidence",
        "limitations",
        "provenance",
    }
    assert invalid_depth.to_json_dict()["status"] == "error"
    assert invalid_depth.to_json_dict()["limitations"] == ["INVALID_OR_EXCESSIVE_MAX_DEPTH"]


def test_all_six_tools_share_safe_structural_engine() -> None:
    code = (
        "def custom_sanitize(value):\n"
        "    return value\n"
        "def execute_query(query):\n"
        "    cursor.execute(query)\n"
        "def handler():\n"
        "    value = request.args.get('q')\n"
        "    execute_query(value)\n"
    )
    finding, source, context = _inputs(code, 4)
    engine = CoreAnalysisEngine(finding, source, context)
    function_id = engine.target_function_id() or ""

    first = EvidenceToolbox(engine)
    results = [
        first.trace_taint_path(finding.finding_instance_id, 5),
        first.find_callers(function_id, 5),
        first.find_entrypoint_path(function_id, 5),
        first.inspect_symbol("custom_sanitize"),
        first.resolve_symbol_value("query", "app.py"),
    ]
    second = EvidenceToolbox(engine)
    results.append(second.analyze_security_control("custom_sanitize", "sql_query"))

    assert all(set(result.to_json_dict()) == {
        "status", "complete", "evidence", "limitations", "provenance"
    } for result in results)
    assert all("SCANNER_SNIPPET_MUST_NOT_BE_USED" not in str(result.to_json_dict()) for result in results)


def test_projection_contains_no_raw_ast_or_unsanitized_secret() -> None:
    secret = "RAW_SECRET_CANARY_DO_NOT_SEND"
    code = (
        "def handler():\n"
        f"    password = '{secret}'\n"
        "    cursor.execute(password)\n"
    )
    sanitized = code.replace(secret, "<REDACTED_SECRET>")
    finding, source, context = _inputs(code, 3, sanitized_code=sanitized)

    result = build_evidence_context(finding, source, context)
    projection = project_evidence(result.evidence)
    serialized = result.context.sanitized_snippet or ""

    assert secret not in serialized
    assert "SCANNER_SNIPPET_MUST_NOT_BE_USED" not in serialized
    assert "ast_dump" not in serialized
    assert projection["finding"] == {
        "rule_id": "python.security.test",
        "category": "security",
        "severity": "HIGH",
        "message": "Potential security-sensitive data flow.",
        "file_path": "app.py",
        "start_line": 3,
        "end_line": 3,
    }
    assert set(projection["security_controls"]) == {
        "guards",
        "validations",
        "sanitizers",
        "safe_api_usage",
    }
    assert str(Path.cwd().resolve()) not in serialized


class _CapturingProvider:
    def __init__(self) -> None:
        self.received: TriageInput | None = None
        self._delegate = FakeTriageProvider()

    def triage(self, triage_input: TriageInput):
        self.received = triage_input
        return self._delegate.triage(triage_input)


def test_semgrep_pipeline_sends_evidence_projection_to_provider(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    code = (
        "def handler():\n"
        "    user = request.args.get('q')\n"
        "    cursor.execute(user)\n"
    )
    (repo / "app.py").write_text(code, encoding="utf-8")
    finding, _, _ = _inputs(code, 3)
    provider = _CapturingProvider()

    result = triage_finding(finding, repo, provider, prompt_type="fake.tp.high")

    assert result.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert provider.received is not None
    snippet = provider.received.context.sanitized_snippet or ""
    assert '"context_completeness"' in snippet
    assert '"status":"complete"' in snippet
    assert "SCANNER_SNIPPET_MUST_NOT_BE_USED" not in snippet


def test_semgrep_pipeline_forces_manual_review_when_source_unresolved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    code = "def execute_query(query):\n    cursor.execute(query)\n"
    (repo / "app.py").write_text(code, encoding="utf-8")
    finding, _, _ = _inputs(code, 2)

    result = triage_finding(
        finding,
        repo,
        FakeTriageProvider(),
        prompt_type="fake.tp.high",
    )

    assert result.triage_decision is not None
    assert result.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert result.policy_decision.escalated is True
    assert result.policy_decision.reasons == [
        "Context evidence is incomplete after bounded expansion."
    ]
