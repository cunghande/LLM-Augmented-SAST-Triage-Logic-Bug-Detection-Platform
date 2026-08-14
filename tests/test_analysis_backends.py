"""Tests for bounded native/Joern analysis backend contracts."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

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
from sast_triage.context.evidence_agent import GraphEvidenceExpansionAgent
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    ScannerType,
    Severity,
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
    repository_index = None

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
