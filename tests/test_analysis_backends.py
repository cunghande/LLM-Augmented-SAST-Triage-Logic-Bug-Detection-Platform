"""Tests for bounded Joern analysis backend contracts."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from sast_triage.analysis.base import (
    AnalysisIdentity,
    GraphEvidence,
    GraphStep,
)
from sast_triage.analysis.joern import (
    JoernAnalysisBackend,
    _extract_json,
    _relative_cpg_path,
    _sink_call_regex,
)
from sast_triage.analysis.rule_semantics import RuleMechanism, rule_mechanism
from sast_triage.context.evidence_agent import GraphEvidenceExpansionAgent
from sast_triage.context.evidence_service import build_evidence_context
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
)


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="joern-test-finding",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.command-injection",
        rule_name="Command injection",
        file_path="service.py",
        start_line=5,
        end_line=5,
        severity=Severity.HIGH,
        message="Potential command injection",
        metadata={},
    )


class _SequenceBackend:
    identity = AnalysisIdentity("joern", "test", "test", "complete", 0.0)
    logic_index = None

    def __init__(self) -> None:
        self.calls: list[str] = []

    def discover_findings(
        self, existing: tuple[NormalizedFinding, ...]
    ) -> tuple[NormalizedFinding, ...]:
        return ()

    def initial_evidence(self, finding: NormalizedFinding) -> GraphEvidence:
        return GraphEvidence(sink_symbol="run", sink_type="command_execution")

    def run_tool(
        self,
        tool_name: str,
        finding: NormalizedFinding,
        evidence: GraphEvidence,
        *,
        max_depth: int,
        max_paths: int,
        max_nodes: int,
    ) -> GraphEvidence:
        self.calls.append(tool_name)
        if tool_name == "trace_dataflow":
            path = (
                GraphStep("call", "get", "routes.py", 5),
                GraphStep("call", "run", "service.py", 5),
            )
            return GraphEvidence(
                source_type="user_controlled_call",
                source_file="routes.py",
                source_line=5,
                source_user_controlled=True,
                paths=(path,),
                source_reaches_sink=True,
                path_complete=True,
                provenance=("JOERN_DATAFLOW",),
            )
        if tool_name == "find_reachability":
            return GraphEvidence(
                callers=(GraphStep("caller", "route", "routes.py", 4),),
                reachability_resolved=True,
                provenance=("JOERN_CALL_GRAPH",),
            )
        return GraphEvidence(provenance=("JOERN_CONTROL_FLOW",))


def test_graph_agent_runs_one_allowlisted_tool_per_iteration() -> None:
    backend = _SequenceBackend()
    result = GraphEvidenceExpansionAgent(
        backend,
        _finding(),
        backend.initial_evidence(_finding()),
    ).expand()

    assert result.tool_names == (
        "trace_dataflow",
        "find_reachability",
        "inspect_security_control",
    )
    assert result.tool_calls == 3
    assert result.evidence.source_reaches_sink is True
    assert "AGENT_NO_PROGRESS" not in result.evidence.limitations


def test_graph_agent_stops_when_a_query_makes_no_progress() -> None:
    backend = _SequenceBackend()
    backend.run_tool = lambda *args, **kwargs: GraphEvidence()  # type: ignore[method-assign]

    result = GraphEvidenceExpansionAgent(
        backend,
        _finding(),
        GraphEvidence(sink_symbol="run"),
    ).expand()

    assert result.tool_calls == 1
    assert "AGENT_NO_PROGRESS" in result.evidence.limitations


def test_graph_agent_hard_stops_after_five_tool_calls() -> None:
    backend = _SequenceBackend()
    call_number = 0

    def incomplete_progress(*args: object, **kwargs: object) -> GraphEvidence:
        nonlocal call_number
        call_number += 1
        return GraphEvidence(
            callers=(GraphStep("candidate", f"caller_{call_number}", "app.py", call_number),)
        )

    backend.run_tool = incomplete_progress  # type: ignore[method-assign]
    result = GraphEvidenceExpansionAgent(
        backend,
        _finding(),
        GraphEvidence(sink_symbol="run"),
    ).expand()

    assert result.tool_calls == 5
    assert "MAX_TOOL_CALLS_REACHED" in result.evidence.limitations


def test_joern_projection_rejects_absolute_and_parent_paths() -> None:
    assert _relative_cpg_path("/workspace/repository/pkg/app.py") == "pkg/app.py"
    with pytest.raises(ValueError):
        _relative_cpg_path("/etc/passwd")
    with pytest.raises(ValueError):
        _relative_cpg_path("../outside.py")


def test_joern_target_uses_rule_scoped_sink_and_full_finding_range() -> None:
    finding = _finding().model_copy(update={"start_line": 5, "end_line": 20})

    target = JoernAnalysisBackend._target_expression(finding)

    assert "l >= 5 && l <= 20" in target
    assert _sink_call_regex(finding) == "(?i)(system|run|call|popen)"
    assert "loads" not in _sink_call_regex(finding)


@pytest.mark.parametrize(
    ("rule_id", "expected_call"),
    (
        ("python.sqlalchemy.security.audit.avoid-sqlalchemy-text", "text"),
        ("python.lang.security.audit.dynamic-urllib-use-detected", "urlopen"),
        ("python.flask.security.audit.secure-set-cookie", "set_cookie"),
        ("python.lang.security.deserialization.pickle.avoid-pickle", "dumps"),
        ("python.flask.security.audit.render-template-string", "render_template_string"),
    ),
)
def test_joern_sink_mapping_covers_framework_rules(
    rule_id: str,
    expected_call: str,
) -> None:
    finding = _finding().model_copy(
        update={"rule_id": rule_id, "rule_name": None, "message": rule_id}
    )

    assert expected_call in _sink_call_regex(finding)


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    (
        ("python.flask.security.audit.render-template-string", RuleMechanism.TAINT_FLOW),
        ("python.sqlalchemy.security.audit.avoid-sqlalchemy-text", RuleMechanism.TAINT_FLOW),
        ("python.lang.security.deserialization.pickle.avoid-pickle", RuleMechanism.TAINT_FLOW),
        ("python.lang.security.audit.dynamic-urllib-use-detected", RuleMechanism.TAINT_FLOW),
        ("python.flask.security.audit.secure-set-cookie", RuleMechanism.CONFIGURATION),
    ),
)
def test_rule_semantics_cover_target_frameworks(
    rule_id: str,
    expected: RuleMechanism,
) -> None:
    finding = _finding().model_copy(update={"rule_id": rule_id})

    assert rule_mechanism(finding) == expected


def test_complete_ssti_graph_projects_taint_mechanism() -> None:
    finding = _finding().model_copy(
        update={"rule_id": "python.flask.security.audit.render-template-string"}
    )
    context = SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet="sanitized code",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=5,
        finding_start_line=5,
        finding_end_line=5,
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )

    result = build_evidence_context(
        finding,
        context,
        analysis_backend=_SequenceBackend(),
    )
    projection = json.loads(result.context.sanitized_snippet or "{}")

    assert result.complete is True
    assert projection["deterministic_verification"]["mechanism"] == "taint_flow"
    assert projection["deterministic_verification"]["source_reaches_sink"] is True


def test_template_finding_uses_safe_fallback_instead_of_python_cpg() -> None:
    finding = _finding().model_copy(
        update={
            "rule_id": "python.flask.security.xss.template-unescaped-with-safe",
            "file_path": "templates/home.html",
        }
    )
    context = SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet="{{ note.text | safe }}",
        context_strategy=ContextStrategy.LINE_WINDOW,
        context_start_line=1,
        context_end_line=5,
        finding_start_line=5,
        finding_end_line=5,
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )

    result = build_evidence_context(
        finding,
        context,
        analysis_backend=_SequenceBackend(),
    )
    projection = json.loads(result.context.sanitized_snippet or "{}")

    assert result.complete is False
    assert result.tool_names == ("template_context_projection",)
    assert projection["sink"]["sink_type"] == "html_rendering"
    assert "NON_PYTHON_TEMPLATE_DATAFLOW_UNSUPPORTED" in projection[
        "context_completeness"
    ]["limitations"]


def test_joern_source_selector_excludes_deserialization_sinks() -> None:
    selector = JoernAnalysisBackend._source_expression(_finding(), same_file=True)

    assert "loads" not in selector
    assert "SOURCE_RECEIVER" not in selector
    assert "isIdentifier" in selector


def test_joern_json_projection_rejects_malformed_output() -> None:
    with pytest.raises(ValueError):
        _extract_json("not a projected JSON value")


def test_joern_query_timeout_becomes_partial_safe_evidence() -> None:
    class TimeoutClient:
        def execute(self, _query: str) -> dict[str, object]:
            raise TimeoutError

    backend = object.__new__(JoernAnalysisBackend)
    backend._client = TimeoutClient()  # type: ignore[attr-defined]
    backend._query_durations = []  # type: ignore[attr-defined]

    evidence = backend.initial_evidence(_finding())

    assert evidence.sink_symbol is None
    assert evidence.limitations == ("JOERN_INITIAL_QUERY_FAILED",)


def test_joern_fails_fast_when_docker_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unavailable(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr("sast_triage.analysis.joern.subprocess.run", unavailable)
    with pytest.raises(SastTriageError) as captured:
        JoernAnalysisBackend(tmp_path, "example/repo", module2_enabled=False)
    assert captured.value.error_code == "ANALYSIS_JOERN_DOCKER_UNAVAILABLE"


def test_containerized_joern_reuses_daemon_mount_and_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = object.__new__(JoernAnalysisBackend)
    backend._repository = Path("/workspace/repository")  # type: ignore[attr-defined]
    backend._docker_network = "sast-triage-runtime"  # type: ignore[attr-defined]
    backend._container_name = "sast-triage-joern-test"  # type: ignore[attr-defined]
    backend._port = 54321  # type: ignore[attr-defined]
    backend._image = "sast-triage-joern:4.0.600"  # type: ignore[attr-defined]
    backend._username = "user"  # type: ignore[attr-defined]
    backend._password = "password"  # type: ignore[attr-defined]
    calls: list[tuple[str, ...]] = []

    def docker(*arguments: str, timeout: float = 120.0) -> CompletedProcess[str]:
        del timeout
        calls.append(arguments)
        if arguments[0] == "inspect":
            return CompletedProcess(
                arguments,
                0,
                stdout=(
                    '[{"Mounts":[{"Destination":"/workspace/repository",'
                    '"Source":"/daemon/target-repo"}]}]'
                ),
                stderr="",
            )
        return CompletedProcess(arguments, 0, stdout="container-id", stderr="")

    monkeypatch.setattr("sast_triage.analysis.joern.socket.gethostname", lambda: "app-id")
    backend._docker = docker  # type: ignore[method-assign]

    backend._start_container()

    run = calls[-1]
    assert ("--network", "sast-triage-runtime") == run[5:7]
    assert "--publish" not in run
    assert (
        "type=bind,source=/daemon/target-repo,"
        "target=/workspace/repository,readonly"
    ) in run


def test_containerized_joern_rejects_missing_repository_mount() -> None:
    backend = object.__new__(JoernAnalysisBackend)
    backend._repository = Path("/workspace/repository")  # type: ignore[attr-defined]
    backend._docker_network = "sast-triage-runtime"  # type: ignore[attr-defined]
    backend._docker = lambda *args, **kwargs: CompletedProcess(  # type: ignore[method-assign]
        args, 0, stdout='[{"Mounts":[]}]', stderr=""
    )

    with pytest.raises(SastTriageError) as captured:
        backend._docker_repository_source()

    assert captured.value.error_code == "ANALYSIS_JOERN_REPOSITORY_MOUNT_UNAVAILABLE"


def test_graph_projection_does_not_retain_source_canary() -> None:
    canary = "JOERN_RAW_SOURCE_CANARY_DO_NOT_LEAK"
    evidence = GraphEvidence(
        source_type="user_controlled_call",
        source_file="routes.py",
        sink_symbol="run",
        sink_file="service.py",
        provenance=("JOERN_CPG",),
    )
    assert canary not in repr(asdict(evidence))
