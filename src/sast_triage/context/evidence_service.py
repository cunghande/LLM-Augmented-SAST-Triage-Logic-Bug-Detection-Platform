"""Dịch vụ chiếu bằng chứng an toàn cho ranh giới provider."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

from sast_triage.analysis.base import (
    AnalysisBackend,
    GraphControl,
    GraphEvidence,
    GraphStep,
)
from sast_triage.context.evidence_agent import (
    EvidenceExpansionAgent,
    GraphEvidenceExpansionAgent,
)
from sast_triage.context.evidence_engine import CoreAnalysisEngine
from sast_triage.context.evidence_models import (
    ContextCompleteness,
    EvidencePackage,
    EvidenceStatus,
    FindingEvidence,
    RelevantCodeEvidence,
    SecurityControlEvidence,
    SinkEvidence,
    SourceEvidence,
    TaintPathEvidence,
    TaintStep,
)
from sast_triage.context.reader import SourceReadResult
from sast_triage.context.repository_index import RepositoryEvidenceIndex
from sast_triage.models import NormalizedFinding, SanitizedContext
from sast_triage.rule_semantics import classify_rule_semantics

MAX_EVIDENCE_CODE_CHARACTERS = 6_000
MAX_EVIDENCE_JSON_CHARACTERS = 12_000


@dataclass(frozen=True, slots=True)
class EvidenceContextResult:
    """Kết quả nội bộ được pipeline finding sử dụng."""

    context: SanitizedContext
    evidence: EvidencePackage
    complete: bool
    tool_calls: int
    tool_names: tuple[str, ...]


def _merge_bounded_local_verification(
    finding: NormalizedFinding,
    graph: GraphEvidence,
    local: EvidencePackage,
) -> GraphEvidence:
    """Add source-free same-file proof while giving Joern positive flow precedence."""
    controls = tuple(
        GraphControl(
            symbol=control.symbol,
            control_type=control.control_type,
            on_path=control.on_taint_path,
            effective=control.effective,
        )
        for control in local.security_controls
    )
    merged_controls = tuple(dict.fromkeys((*graph.controls, *controls)))
    local_complete = local.context_completeness.status == EvidenceStatus.COMPLETE
    local_flow = local.taint_path.source_reaches_sink if local_complete else None
    intrinsic = any(
        token in finding.rule_id.lower()
        for token in ("insecure-hash", "weak-random", "secure-cookie")
    )

    if intrinsic or local_flow is None or (
        graph.source_reaches_sink is True and local_flow is True
    ):
        return replace(
            graph,
            controls=merged_controls,
            provenance=tuple(
                dict.fromkeys((*graph.provenance, "BOUNDED_LOCAL_AST_VERIFIER"))
            ),
        )

    local_steps = tuple(
        GraphStep(
            kind=step.kind,
            symbol=step.expression,
            file_path=step.file_path,
            line=step.line,
        )
        for step in local.taint_path.steps
    )
    source = local.source
    limitations = tuple(
        item
        for item in graph.limitations
        if item
        not in {"JOERN_LOCAL_FLOW_NOT_FOUND", "JOERN_CROSS_FILE_FLOW_NOT_FOUND"}
    )
    provenance_label = (
        "BOUNDED_LOCAL_POSITIVE_PROOF"
        if local_flow is True
        else "BOUNDED_LOCAL_NEGATIVE_PROOF"
    )
    refinement = (
        ("JOERN_MAY_FLOW_REFINED_BY_LOCAL_PROOF",)
        if graph.source_reaches_sink is True and local_flow is False
        else ()
    )
    return replace(
        graph,
        source_type=(source.source_type if source is not None else graph.source_type),
        source_file=(source.file_path if source is not None else graph.source_file),
        source_line=(source.line if source is not None else graph.source_line),
        source_user_controlled=(
            source.user_controlled if source is not None else graph.source_user_controlled
        ),
        paths=((local_steps,) if local_steps else graph.paths),
        controls=merged_controls,
        source_reaches_sink=local_flow,
        path_complete=True,
        reachability_resolved=True,
        limitations=limitations,
        provenance=tuple(
            dict.fromkeys(
                (*graph.provenance, "BOUNDED_LOCAL_AST_VERIFIER", provenance_label)
                + refinement
            )
        ),
    )


def _graph_evidence_package(
    finding: NormalizedFinding,
    sanitized_context: SanitizedContext,
    graph: GraphEvidence,
) -> EvidencePackage:
    """Convert a source-free graph projection into the existing evidence contract."""
    source = (
        SourceEvidence(
            expression="<joern_source>",
            source_type=graph.source_type,
            user_controlled=graph.source_user_controlled is True,
            file_path=graph.source_file or finding.file_path,
            line=graph.source_line,
            confidence="high" if graph.source_reaches_sink is True else "medium",
        )
        if graph.source_type is not None
        else None
    )
    sink = (
        SinkEvidence(
            expression=f"<{graph.sink_symbol}>",
            sink_type=graph.sink_type or "rule_specific_sink",
            dangerous_argument="<joern_target_argument>",
            dangerous_conditions=(),
            file_path=graph.sink_file or finding.file_path,
            line=graph.sink_line or finding.start_line,
        )
        if graph.sink_symbol is not None
        else None
    )
    selected_path = graph.paths[0] if graph.paths else ()
    steps = tuple(
        TaintStep(
            order=index,
            kind=step.kind,
            expression=f"<{step.symbol}>",
            function_id=step.symbol,
            file_path=step.file_path,
            line=step.line,
        )
        for index, step in enumerate(selected_path, start=1)
    )
    controls = tuple(
        SecurityControlEvidence(
            symbol=control.symbol,
            control_type=control.control_type,
            on_taint_path=control.on_path,
            protects_target=True if control.on_path else None,
            effective=control.effective,
            confidence="high" if control.effective is not None else "medium",
        )
        for control in graph.controls
    )
    intrinsic = any(
        token in finding.rule_id.lower()
        for token in ("insecure-hash", "weak-random", "secure-cookie")
    )
    sink_resolved = sink is not None
    source_resolved = source is not None
    negative_proven = (
        graph.source_reaches_sink is False
        and graph.path_complete
        and graph.reachability_resolved
        and "BOUNDED_LOCAL_NEGATIVE_PROOF" in graph.provenance
    )
    complete = (
        sink_resolved
        and (
            intrinsic
            or negative_proven
            or (
                source_resolved
                and graph.source_reaches_sink is True
                and graph.path_complete
                and graph.reachability_resolved
                and "JOERN_CONTROL_FLOW" in graph.provenance
            )
        )
    )
    missing: list[str] = []
    if not sink_resolved:
        missing.append("SINK_NOT_RESOLVED")
    if not intrinsic and not source_resolved and not negative_proven:
        missing.append("SOURCE_NOT_RESOLVED")
    if not intrinsic and not graph.path_complete:
        missing.append("TAINT_PATH_INCOMPLETE")
    if not intrinsic and not graph.reachability_resolved:
        missing.append("REACHABILITY_NOT_RESOLVED")
    if (
        not intrinsic
        and not negative_proven
        and "JOERN_CONTROL_FLOW" not in graph.provenance
    ):
        missing.append("SECURITY_CONTROL_NOT_ANALYZED")

    return EvidencePackage(
        finding_id=finding.finding_instance_id,
        finding=FindingEvidence(
            rule_id=finding.rule_id,
            category=(str(finding.metadata.get("category")) if finding.metadata.get("category") else None),
            severity=finding.severity.value,
            message=finding.message,
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
        ),
        relevant_code=RelevantCodeEvidence(
            scope_type="joern_cpg_projection",
            function_name=sanitized_context.enclosing_function,
            class_name=sanitized_context.enclosing_class,
            # The graph backend never exports code. This text is the existing
            # SafeContextService line window after credential redaction, kept
            # so prompt v9 can still evaluate guards and benign traps.
            code=sanitized_context.sanitized_snippet or "<SANITIZED_CONTEXT_UNAVAILABLE>",
            start_line=sanitized_context.context_start_line or finding.start_line,
            end_line=sanitized_context.context_end_line or finding.start_line,
        ),
        source=source,
        sink=sink,
        taint_path=TaintPathEvidence(
            path_type=(
                "cross_file"
                if len({step.file_path for step in selected_path}) > 1
                else "same_file" if selected_path else "intrinsic_usage" if intrinsic else "unknown"
            ),
            steps=steps,
            source_reaches_sink=graph.source_reaches_sink,
            complete=graph.path_complete or intrinsic,
        ),
        security_controls=controls,
        context_completeness=ContextCompleteness(
            status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.PARTIAL,
            source_resolved=source_resolved or intrinsic,
            sink_resolved=sink_resolved,
            taint_path_complete=graph.path_complete or intrinsic,
            call_chain_complete=graph.path_complete or intrinsic,
            reachability_resolved=graph.reachability_resolved or intrinsic,
            unresolved_symbols=(),
            missing_information=tuple(missing),
            limitations=graph.limitations,
        ),
        provenance=tuple(dict.fromkeys((*graph.provenance, "JOERN_SOURCE_FREE_PROJECTION"))),
    )


def _source_projection(evidence: EvidencePackage) -> dict[str, object] | None:
    source = evidence.source
    if source is None:
        return None
    return {
        "expression": source.expression,
        "source_type": source.source_type,
        "user_controlled": source.user_controlled,
        "file_path": source.file_path,
        "line": source.line,
        "confidence": source.confidence,
    }


def _security_control_projection(evidence: EvidencePackage) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = {
        "guards": [],
        "validations": [],
        "sanitizers": [],
        "safe_api_usage": [],
    }
    for control in evidence.security_controls:
        item = {
            "symbol": control.symbol,
            "control_type": control.control_type,
            "on_taint_path": control.on_taint_path,
            "protects_target": control.protects_target,
            "effective": control.effective,
            "confidence": control.confidence,
        }
        if "guard" in control.control_type:
            group = "guards"
        elif "validation" in control.control_type:
            group = "validations"
        elif "safe_api" in control.control_type or "parameterized" in control.control_type:
            group = "safe_api_usage"
        else:
            group = "sanitizers"
        groups[group].append(item)
    return groups


def project_evidence(evidence: EvidencePackage) -> dict[str, object]:
    """Trả về projection allowlist tường minh, an toàn cho provider."""
    sink = evidence.sink
    completeness = evidence.context_completeness
    effective_controls = [
        control.symbol
        for control in evidence.security_controls
        if control.effective is True and control.protects_target is not False
    ]
    rule_id = evidence.finding.rule_id.lower()
    rule_semantics = classify_rule_semantics(rule_id)
    intrinsic_usage = any(
        token in rule_id
        for token in ("insecure-hash", "weak-random", "secure-cookie")
    )
    taint_mechanism = any(
        token in rule_id
        for token in (
            "injection",
            "path-traversal",
            "deserialization",
            "xxe",
            "xpath",
            "raw-html",
        )
    )
    source_user_controlled = (
        evidence.source.user_controlled if evidence.source is not None else None
    )
    source_reaches_sink = evidence.taint_path.source_reaches_sink
    negative_taint_proven = (
        source_reaches_sink is False
        and evidence.taint_path.complete
        and completeness.reachability_resolved
        and "BOUNDED_LOCAL_NEGATIVE_PROOF" in evidence.provenance
    )
    return {
        "finding": {
            "rule_id": evidence.finding.rule_id,
            "category": evidence.finding.category,
            "severity": evidence.finding.severity,
            "message": evidence.finding.message,
            "file_path": evidence.finding.file_path,
            "start_line": evidence.finding.start_line,
            "end_line": evidence.finding.end_line,
        },
        "relevant_code": {
            "scope_type": evidence.relevant_code.scope_type,
            "function_name": evidence.relevant_code.function_name,
            "class_name": evidence.relevant_code.class_name,
            "start_line": evidence.relevant_code.start_line,
            "end_line": evidence.relevant_code.end_line,
            "code": evidence.relevant_code.code,
        },
        "source": _source_projection(evidence),
        "sink": None if sink is None else {
            "expression": sink.expression,
            "sink_type": sink.sink_type,
            "dangerous_argument": sink.dangerous_argument,
            "dangerous_conditions": list(sink.dangerous_conditions),
            "file_path": sink.file_path,
            "line": sink.line,
        },
        "taint_path": {
            "path_type": evidence.taint_path.path_type,
            "steps": [
                {
                    "order": step.order,
                    "kind": step.kind,
                    "expression": step.expression,
                    "function_id": step.function_id,
                    "file_path": step.file_path,
                    "line": step.line,
                }
                for step in evidence.taint_path.steps
            ],
            "source_reaches_sink": evidence.taint_path.source_reaches_sink,
            "complete": evidence.taint_path.complete,
        },
        "security_controls": _security_control_projection(evidence),
        "context_completeness": {
            "status": completeness.status.value,
            "source_resolved": completeness.source_resolved,
            "sink_resolved": completeness.sink_resolved,
            "taint_path_complete": completeness.taint_path_complete,
            "call_chain_complete": completeness.call_chain_complete,
            "reachability_resolved": completeness.reachability_resolved,
            "unresolved_symbols": list(completeness.unresolved_symbols),
            "missing_information": list(completeness.missing_information),
            "limitations": list(completeness.limitations),
        },
        "deterministic_verification": {
            "mechanism": (
                "intrinsic_usage"
                if intrinsic_usage
                else "taint_flow" if taint_mechanism else "rule_specific"
            ),
            "rule_semantics": rule_semantics.value,
            "attacker_control_required": False if intrinsic_usage else True if taint_mechanism else None,
            "evidence_complete": completeness.status == EvidenceStatus.COMPLETE,
            "source_user_controlled": (
                None
                if intrinsic_usage
                else True if source_user_controlled is True else None
            ),
            "source_reaches_sink": (
                None
                if intrinsic_usage
                else source_reaches_sink
                if source_reaches_sink is True or negative_taint_proven
                else None
            ),
            "negative_taint_conclusion_proven": negative_taint_proven,
            "unsafe_primitive_observed": bool(intrinsic_usage and sink is not None),
            "effective_controls": effective_controls,
            "has_evidence_conflict": (
                completeness.status == EvidenceStatus.COMPLETE
                and (
                    evidence.sink is None
                    if intrinsic_usage
                    else (
                        evidence.source is None
                        or evidence.sink is None
                        or not evidence.taint_path.complete
                    )
                )
            ),
        },
        "provenance": list(evidence.provenance),
    }


def build_evidence_context(
    finding: NormalizedFinding,
    source: SourceReadResult,
    sanitized_context: SanitizedContext,
    *,
    max_tool_calls: int = 5,
    max_depth: int = 5,
    repository_index: RepositoryEvidenceIndex | None = None,
    analysis_backend: AnalysisBackend | None = None,
) -> EvidenceContextResult:
    """Phân tích mã nguồn và thay snippet gửi provider bằng JSON bằng chứng an toàn."""
    if analysis_backend is not None and analysis_backend.identity.backend == "joern":
        initial = analysis_backend.initial_evidence(finding)
        if initial is None:
            initial = GraphEvidence(limitations=("JOERN_INITIAL_EVIDENCE_UNAVAILABLE",))
        try:
            local_evidence = CoreAnalysisEngine(
                finding,
                source,
                sanitized_context,
            ).build_evidence()
            initial = _merge_bounded_local_verification(
                finding,
                initial,
                local_evidence,
            )
        except (SyntaxError, ValueError):
            initial = replace(
                initial,
                limitations=tuple(
                    dict.fromkeys(
                        (*initial.limitations, "BOUNDED_LOCAL_VERIFIER_UNAVAILABLE")
                    )
                ),
            )
        graph_expansion = GraphEvidenceExpansionAgent(
            analysis_backend,
            finding,
            initial,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
        ).expand()
        evidence = _graph_evidence_package(
            finding,
            sanitized_context,
            graph_expansion.evidence,
        )
        expansion_tool_calls = graph_expansion.tool_calls
        expansion_tool_names = graph_expansion.tool_names
    else:
        engine = CoreAnalysisEngine(finding, source, sanitized_context)
        expansion = EvidenceExpansionAgent(
            engine,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
        ).expand()
        evidence = expansion.evidence
        expansion_tool_calls = expansion.tool_calls
        expansion_tool_names = expansion.tool_names

    if (
        repository_index is not None
        and evidence.context_completeness.status != EvidenceStatus.COMPLETE
    ):
        trace = repository_index.trace_for_finding(finding, max_depth=max_depth)
        if trace is not None:
            source = SourceEvidence(
                expression="<cross_file_user_controlled_input>",
                source_type=trace.source_type,
                user_controlled=True,
                file_path=trace.source_file,
                line=trace.source_line,
                confidence="high",
            )
            cross_steps = [
                TaintStep(
                    order=1,
                    kind="source",
                    expression="<cross_file_user_controlled_input>",
                    function_id=trace.function_path[0] if trace.function_path else None,
                    file_path=trace.source_file,
                    line=trace.source_line,
                )
            ]
            for function_id in trace.function_path:
                cross_steps.append(
                    TaintStep(
                        order=len(cross_steps) + 1,
                        kind="call_boundary",
                        expression="<cross_file_call_boundary>",
                        function_id=function_id,
                        file_path=(trace.sink_file if function_id == trace.function_path[-1] else trace.source_file),
                        line=None,
                    )
                )
            for step in evidence.taint_path.steps:
                cross_steps.append(
                    TaintStep(
                        order=len(cross_steps) + 1,
                        kind=step.kind,
                        expression=step.expression,
                        function_id=step.function_id,
                        file_path=step.file_path,
                        line=step.line,
                    )
                )
            evidence = replace(
                evidence,
                source=source,
                taint_path=TaintPathEvidence(
                    path_type="cross_file",
                    steps=tuple(cross_steps),
                    source_reaches_sink=True,
                    complete=True,
                ),
                context_completeness=ContextCompleteness(
                    status=EvidenceStatus.COMPLETE,
                    source_resolved=True,
                    sink_resolved=evidence.sink is not None,
                    taint_path_complete=True,
                    call_chain_complete=True,
                    reachability_resolved=True,
                    unresolved_symbols=(),
                    missing_information=(),
                    limitations=(),
                ),
                provenance=tuple(
                    dict.fromkeys(
                        (*evidence.provenance, f"module2_index:{trace.source_file}", f"module2_index:{trace.sink_file}")
                    )
                ),
            )

    if len(evidence.relevant_code.code) > MAX_EVIDENCE_CODE_CHARACTERS:
        relevant = replace(
            evidence.relevant_code,
            code=evidence.relevant_code.code[:MAX_EVIDENCE_CODE_CHARACTERS]
            + "\n<TRUNCATED_EVIDENCE_CODE>",
        )
        completeness = replace(
            evidence.context_completeness,
            status=EvidenceStatus.PARTIAL,
            missing_information=tuple(
                dict.fromkeys((*evidence.context_completeness.missing_information, "EVIDENCE_CODE_TRUNCATED"))
            ),
            limitations=tuple(
                dict.fromkeys((*evidence.context_completeness.limitations, "MAX_EVIDENCE_CODE_CHARACTERS"))
            ),
        )
        evidence = replace(evidence, relevant_code=relevant, context_completeness=completeness)

    rendered = json.dumps(
        project_evidence(evidence),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(rendered) > MAX_EVIDENCE_JSON_CHARACTERS:
        relevant = replace(evidence.relevant_code, code="<EVIDENCE_CODE_OMITTED_DUE_TO_LIMIT>")
        completeness = replace(
            evidence.context_completeness,
            status=EvidenceStatus.PARTIAL,
            missing_information=tuple(
                dict.fromkeys((*evidence.context_completeness.missing_information, "EVIDENCE_SIZE_LIMIT_REACHED"))
            ),
            limitations=tuple(
                dict.fromkeys((*evidence.context_completeness.limitations, "MAX_EVIDENCE_JSON_CHARACTERS"))
            ),
        )
        evidence = replace(evidence, relevant_code=relevant, context_completeness=completeness)
        rendered = json.dumps(
            project_evidence(evidence),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    context = sanitized_context.model_copy(
        update={
            "sanitized_snippet": rendered,
            "limited_imports": None,
            "limited_decorators": None,
            "truncated": sanitized_context.truncated
            or evidence.context_completeness.status != EvidenceStatus.COMPLETE,
        }
    )
    complete = evidence.context_completeness.status == EvidenceStatus.COMPLETE
    return EvidenceContextResult(
        context=context,
        evidence=evidence,
        complete=complete,
        tool_calls=expansion_tool_calls,
        tool_names=expansion_tool_names,
    )
