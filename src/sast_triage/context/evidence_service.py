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
from sast_triage.analysis.rule_semantics import (
    RuleMechanism,
    mechanism_for_rule_id,
    rule_mechanism,
    sink_only_evidence_is_sufficient,
)
from sast_triage.context.evidence_agent import GraphEvidenceExpansionAgent
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
from sast_triage.context.local_verifier import (
    verify_intrinsic_security_usage,
    verify_sanitized_python_flow,
)
from sast_triage.logic import LogicBugClass, LogicCandidate
from sast_triage.logic.index import LogicFindingIndex
from sast_triage.models import ContextStrategy, NormalizedFinding, SanitizedContext

MAX_EVIDENCE_CODE_CHARACTERS = 6_000
MAX_EVIDENCE_JSON_CHARACTERS = 12_000
_TEMPLATE_SUFFIXES = frozenset({".html", ".htm", ".jinja", ".jinja2", ".j2"})


@dataclass(frozen=True, slots=True)
class EvidenceContextResult:
    """Kết quả nội bộ được pipeline finding sử dụng."""

    context: SanitizedContext
    evidence: EvidencePackage
    complete: bool
    tool_calls: int
    tool_names: tuple[str, ...]
    report_evidence: dict[str, object]


def _report_evidence_projection(
    evidence: EvidencePackage,
    graph: GraphEvidence | None = None,
) -> dict[str, object]:
    """Build a source-free report projection with every bounded graph path."""
    if graph is not None and graph.paths:
        raw_paths = graph.paths
    elif evidence.taint_path.steps:
        raw_paths = (
            tuple(
                GraphStep(
                    kind=step.kind,
                    symbol=step.function_id or step.expression,
                    file_path=step.file_path,
                    line=step.line,
                )
                for step in evidence.taint_path.steps
            ),
        )
    else:
        raw_paths = ()

    paths: list[dict[str, object]] = []
    for path_index, path in enumerate(raw_paths, start=1):
        files = tuple(dict.fromkeys(step.file_path for step in path))
        paths.append(
            {
                "path_index": path_index,
                "path_type": "cross_file" if len(files) > 1 else "same_file",
                "files": list(files),
                "steps": [
                    {
                        "order": order,
                        "kind": step.kind,
                        "symbol": step.symbol,
                        "file_path": step.file_path,
                        "line": step.line,
                    }
                    for order, step in enumerate(path, start=1)
                ],
            }
        )

    callers = () if graph is None else graph.callers
    graph_controls = () if graph is None else graph.controls
    return {
        "backend": (
            "joern"
            if graph is not None and "JOERN_CPG" in graph.provenance
            else "scanner_projection"
            if graph is not None
            else "logic_projection"
        ),
        "source": _source_projection(evidence),
        "sink": (
            None
            if evidence.sink is None
            else {
                "symbol": evidence.sink.expression,
                "sink_type": evidence.sink.sink_type,
                "file_path": evidence.sink.file_path,
                "line": evidence.sink.line,
            }
        ),
        "source_reaches_sink": evidence.taint_path.source_reaches_sink,
        "complete": evidence.taint_path.complete,
        "paths": paths,
        "callers": [
            {
                "kind": caller.kind,
                "symbol": caller.symbol,
                "file_path": caller.file_path,
                "line": caller.line,
            }
            for caller in callers
        ],
        "controls": [
            {
                "symbol": control.symbol,
                "control_type": control.control_type,
                "on_path": control.on_path,
                "effective": control.effective,
                "file_path": control.file_path,
                "line": control.line,
            }
            for control in graph_controls
        ],
        "files": list(
            dict.fromkeys(step.file_path for path in raw_paths for step in path)
        ),
        "completeness": {
            "status": evidence.context_completeness.status.value,
            "source_resolved": evidence.context_completeness.source_resolved,
            "sink_resolved": evidence.context_completeness.sink_resolved,
            "taint_path_complete": evidence.context_completeness.taint_path_complete,
            "call_chain_complete": evidence.context_completeness.call_chain_complete,
            "reachability_resolved": evidence.context_completeness.reachability_resolved,
            "missing_information": list(
                evidence.context_completeness.missing_information
            ),
            "limitations": list(evidence.context_completeness.limitations),
        },
        "provenance": list(evidence.provenance),
    }


def _template_fallback_graph(finding: NormalizedFinding) -> GraphEvidence | None:
    """Represent a scanner-matched template sink when Python CPG cannot parse the file."""
    suffix = "." + finding.file_path.rsplit(".", 1)[-1].lower()
    rule = finding.rule_id.lower()
    if suffix not in _TEMPLATE_SUFFIXES or not any(
        token in rule for token in ("template", "xss", "raw-html")
    ):
        return None
    return GraphEvidence(
        sink_type="html_rendering",
        sink_symbol="scanner_reported_template_output",
        sink_file=finding.file_path,
        sink_line=finding.start_line,
        limitations=("NON_PYTHON_TEMPLATE_DATAFLOW_UNSUPPORTED",),
        provenance=("SCANNER_MATCH", "SANITIZED_TEMPLATE_CONTEXT"),
    )


def _scanner_structural_fallback_graph(
    finding: NormalizedFinding,
) -> GraphEvidence | None:
    """Represent scanner-proven non-call configuration assignments safely."""
    rule = finding.rule_id.lower()
    if "hardcoded-config" not in rule:
        return None
    return GraphEvidence(
        sink_type="hardcoded_configuration",
        sink_symbol="scanner_reported_configuration_assignment",
        sink_file=finding.file_path,
        sink_line=finding.start_line,
        path_complete=True,
        reachability_resolved=True,
        provenance=("SCANNER_MATCH", "SANITIZED_CONTEXT", "CONFIGURATION_ASSIGNMENT"),
    )


def _merge_local_verification(
    finding: NormalizedFinding,
    sanitized_context: SanitizedContext,
    graph: GraphEvidence,
) -> GraphEvidence:
    """Merge only source-free, fail-closed local verification facts."""
    snippet = sanitized_context.sanitized_snippet
    context_start = sanitized_context.context_start_line
    if not snippet or context_start is None or sanitized_context.truncated:
        return graph
    verification = verify_sanitized_python_flow(
        finding,
        snippet,
        context_start_line=context_start,
    )
    intrinsic = verify_intrinsic_security_usage(
        finding,
        snippet,
        context_start_line=context_start,
    )
    if intrinsic.security_sensitive_usage_proven:
        graph = graph.merge(GraphEvidence(provenance=intrinsic.provenance))
    if verification.negative_taint_proven:
        return graph.merge(
            GraphEvidence(
                controls=(
                    GraphControl(
                        symbol="bounded_local_final_value",
                        control_type="path_sensitive_negative_taint_proof",
                        on_path=True,
                        effective=True,
                        file_path=finding.file_path,
                        line=finding.start_line,
                    ),
                ),
                source_reaches_sink=False,
                path_complete=True,
                reachability_resolved=True,
                provenance=(
                    *verification.provenance,
                    "BOUNDED_LOCAL_NEGATIVE_PROOF",
                ),
            )
        )
    if verification.unresolved_guard_observed:
        return graph.merge(
            GraphEvidence(
                controls=(
                    GraphControl(
                        symbol="bounded_local_guard",
                        control_type="path_sensitive_guard_candidate",
                        on_path=True,
                        effective=None,
                        file_path=finding.file_path,
                        line=finding.start_line,
                    ),
                ),
                provenance=verification.provenance,
            )
        )
    return graph


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
    sink_only = sink_only_evidence_is_sufficient(finding)
    sink_resolved = sink is not None
    source_resolved = source is not None
    negative_proven = (
        graph.source_reaches_sink is False
        and graph.path_complete
        and graph.reachability_resolved
        and "BOUNDED_LOCAL_NEGATIVE_PROOF" in graph.provenance
    )
    complete = sink_resolved and (
        sink_only
        or negative_proven
        or (
            source_resolved
            and graph.source_reaches_sink is True
            and graph.path_complete
            and graph.reachability_resolved
            and "JOERN_CONTROL_FLOW" in graph.provenance
        )
    )
    missing: list[str] = []
    if not sink_resolved:
        missing.append("SINK_NOT_RESOLVED")
    if not sink_only and not source_resolved and not negative_proven:
        missing.append("SOURCE_NOT_RESOLVED")
    if not sink_only and not graph.path_complete:
        missing.append("TAINT_PATH_INCOMPLETE")
    if not sink_only and not graph.reachability_resolved:
        missing.append("REACHABILITY_NOT_RESOLVED")
    if (
        not sink_only
        and not negative_proven
        and "JOERN_CONTROL_FLOW" not in graph.provenance
    ):
        missing.append("SECURITY_CONTROL_NOT_ANALYZED")

    return EvidencePackage(
        finding_id=finding.finding_instance_id,
        finding=FindingEvidence(
            rule_id=finding.rule_id,
            category=(
                str(finding.metadata.get("category"))
                if finding.metadata.get("category")
                else None
            ),
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
            code=sanitized_context.sanitized_snippet
            or "<SANITIZED_CONTEXT_UNAVAILABLE>",
            start_line=sanitized_context.context_start_line or finding.start_line,
            end_line=sanitized_context.context_end_line or finding.start_line,
        ),
        source=source,
        sink=sink,
        taint_path=TaintPathEvidence(
            path_type=(
                "cross_file"
                if len({step.file_path for step in selected_path}) > 1
                else "same_file"
                if selected_path
                else rule_mechanism(finding).value
                if sink_only
                else "unknown"
            ),
            steps=steps,
            source_reaches_sink=graph.source_reaches_sink,
            complete=graph.path_complete or sink_only,
        ),
        security_controls=controls,
        context_completeness=ContextCompleteness(
            status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.PARTIAL,
            source_resolved=source_resolved or sink_only,
            sink_resolved=sink_resolved,
            taint_path_complete=graph.path_complete or sink_only,
            call_chain_complete=graph.path_complete or sink_only,
            reachability_resolved=graph.reachability_resolved or sink_only,
            unresolved_symbols=(),
            missing_information=tuple(missing),
            limitations=graph.limitations,
        ),
        provenance=tuple(
            dict.fromkeys((*graph.provenance, "JOERN_SOURCE_FREE_PROJECTION"))
        ),
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


def _security_control_projection(
    evidence: EvidencePackage,
) -> dict[str, list[dict[str, object]]]:
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
        elif (
            "safe_api" in control.control_type
            or "parameterized" in control.control_type
        ):
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
    mechanism = mechanism_for_rule_id(evidence.finding.rule_id)
    intrinsic_usage = mechanism == RuleMechanism.INTRINSIC_USAGE
    configuration = mechanism == RuleMechanism.CONFIGURATION
    taint_mechanism = mechanism == RuleMechanism.TAINT_FLOW
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
        "sink": None
        if sink is None
        else {
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
            "mechanism": mechanism.value,
            "attacker_control_required": (
                True if taint_mechanism else False if intrinsic_usage else None
            ),
            "evidence_complete": completeness.status == EvidenceStatus.COMPLETE,
            "source_user_controlled": (
                None
                if intrinsic_usage or configuration
                else True
                if source_user_controlled is True
                else None
            ),
            "source_reaches_sink": (
                None
                if intrinsic_usage or configuration
                else source_reaches_sink
                if source_reaches_sink is True or negative_taint_proven
                else None
            ),
            "negative_taint_conclusion_proven": negative_taint_proven,
            "unsafe_primitive_observed": bool(intrinsic_usage and sink is not None),
            "security_sensitive_usage_proven": (
                intrinsic_usage
                and "BOUNDED_INTRINSIC_SECURITY_USAGE" in evidence.provenance
            ),
            "unsafe_configuration_observed": bool(configuration and sink is not None),
            "effective_controls": effective_controls,
            "has_evidence_conflict": (
                completeness.status == EvidenceStatus.COMPLETE
                and (
                    evidence.sink is None
                    if intrinsic_usage or configuration
                    else (
                        not negative_taint_proven
                        and (
                            evidence.source is None
                            or evidence.sink is None
                            or not evidence.taint_path.complete
                        )
                    )
                )
            ),
        },
        "provenance": list(evidence.provenance),
    }


def _logic_relevant_code(
    sanitized_context: SanitizedContext,
    candidate: LogicCandidate,
) -> tuple[str, int | None, int | None, bool]:
    """Select the candidate's sanitized function body from a wider safe context."""
    snippet = sanitized_context.sanitized_snippet or "<SANITIZED_CONTEXT_UNAVAILABLE>"
    context_start = sanitized_context.context_start_line
    context_end = sanitized_context.context_end_line
    function_start = candidate.function_start_line
    function_end = candidate.function_end_line
    if (
        context_start is None
        or context_end is None
        or function_start is None
        or function_end is None
        or function_start < context_start
        or function_end > context_end
    ):
        return snippet, context_start, context_end, False

    lines = snippet.splitlines(keepends=True)
    start_offset = function_start - context_start
    end_offset = function_end - context_start + 1
    selected = "".join(lines[start_offset:end_offset])
    if not selected.strip():
        return snippet, context_start, context_end, False
    return selected, function_start, function_end, True


def _logic_evidence_package(
    finding: NormalizedFinding,
    sanitized_context: SanitizedContext,
    candidate: LogicCandidate,
) -> EvidencePackage:
    """Build a complete source-free trace for one bounded logic pattern."""
    relevant_code, code_start, code_end, function_scope_complete = _logic_relevant_code(
        sanitized_context,
        candidate,
    )
    complete = candidate.analysis_complete and function_scope_complete
    source_expression = candidate.source_symbol or candidate.source_kind
    sink_expression = candidate.sink_symbol or candidate.sink_kind
    source_line = candidate.source_line or candidate.line
    sink_line = candidate.sink_line or candidate.line
    trace_steps = [
        TaintStep(
            order=1,
            kind="source",
            expression=source_expression,
            function_id=candidate.function,
            file_path=candidate.file_path,
            line=source_line,
        )
    ]
    for guard in candidate.guards:
        trace_steps.append(
            TaintStep(
                order=len(trace_steps) + 1,
                kind="guard",
                expression=guard,
                function_id=candidate.function,
                file_path=candidate.file_path,
                line=sink_line,
            )
        )
    trace_steps.append(
        TaintStep(
            order=len(trace_steps) + 1,
            kind="sink",
            expression=sink_expression,
            function_id=candidate.function,
            file_path=candidate.file_path,
            line=sink_line,
        )
    )
    return EvidencePackage(
        finding_id=finding.finding_instance_id,
        finding=FindingEvidence(
            rule_id=finding.rule_id,
            category=f"logic_bug:{candidate.bug_class.value}",
            severity=finding.severity.value,
            message=finding.message,
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
        ),
        relevant_code=RelevantCodeEvidence(
            scope_type=(
                ContextStrategy.PYTHON_FUNCTION.value
                if function_scope_complete
                else sanitized_context.context_strategy.value
            ),
            function_name=candidate.function,
            class_name=sanitized_context.enclosing_class,
            start_line=code_start,
            end_line=code_end,
            code=relevant_code,
        ),
        source=SourceEvidence(
            expression=source_expression,
            source_type=candidate.source_kind,
            user_controlled=candidate.source_kind.startswith("http_"),
            file_path=candidate.file_path,
            line=source_line,
            confidence="high" if complete else "medium",
        ),
        sink=SinkEvidence(
            expression=sink_expression,
            sink_type=candidate.sink_kind,
            dangerous_argument=candidate.sink_argument or source_expression,
            dangerous_conditions=(candidate.bug_class.value,),
            file_path=candidate.file_path,
            line=sink_line,
        ),
        taint_path=TaintPathEvidence(
            path_type=(
                "authorization_boundary_logic_trace"
                if candidate.sink_kind == "privileged_endpoint_without_authorization"
                else "source_guard_sink_logic_trace"
            ),
            steps=tuple(trace_steps),
            source_reaches_sink=True,
            complete=complete,
        ),
        security_controls=tuple(
            SecurityControlEvidence(
                symbol=guard,
                control_type="observed_guard",
                on_taint_path=True,
                protects_target=False,
                effective=False,
                confidence="medium",
            )
            for guard in candidate.guards
        ),
        context_completeness=ContextCompleteness(
            status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.PARTIAL,
            source_resolved=True,
            sink_resolved=True,
            taint_path_complete=complete,
            call_chain_complete=complete,
            reachability_resolved=complete,
            unresolved_symbols=(),
            missing_information=() if complete else ("LOGIC_TRACE_INCOMPLETE",),
            limitations=() if complete else ("BOUNDED_LOGIC_ANALYSIS_PARTIAL",),
        ),
        provenance=("python_idor_business_logic_v2", "bounded_ast_pattern"),
    )


def _logic_proof_obligations(candidate: LogicCandidate) -> dict[str, object]:
    """Return class-specific proof and counter-evidence facts without raw source."""
    if candidate.sink_kind == "privileged_endpoint_without_authorization":
        hypothesis = (
            "An exposed HTTP or GraphQL endpoint reaches a privileged operation "
            "without an authorization gate in the containing function."
        )
        proof_obligations = (
            "privileged_endpoint_is_exposed",
            "sensitive_operation_is_reachable",
            "no_effective_endpoint_authorization_guard_observed",
        )
        reproduction = (
            "Call the endpoint as an authenticated low-privilege user in a test environment.",
            "The privileged operation must be denied before its sensitive side effect occurs.",
        )
        class_resolution = {
            "privileged_endpoint_exposed": candidate.entrypoint,
            "sensitive_operation_observed": True,
            "endpoint_authorization_guard_observed": False,
            "mechanism_is_object_idor": False,
        }
    elif candidate.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR:
        hypothesis = (
            "A caller-controlled object identifier reaches a lookup without "
            "object- or tenant-level authorization."
        )
        proof_obligations = (
            "caller_controlled_identifier_reaches_lookup",
            "lookup_is_not_subject_or_tenant_scoped",
            "no_effective_object_authorization_guard_observed",
        )
        reproduction = (
            "Request the same object as its owner and as a different authenticated user.",
            "The non-owner request must be denied before object data is returned or mutated.",
        )
        class_resolution = {
            "caller_identifier_reaches_object_lookup": True,
            "lookup_subject_or_tenant_scoped": False,
            "exact_object_authorization_guard_observed": False,
        }
    elif (
        "pagination" in candidate.sink_kind or "collection_query" in candidate.sink_kind
    ):
        hypothesis = "An endpoint can request or return an unbounded collection without enforced server-side pagination limits."
        proof_obligations = (
            "collection_query_or_pagination_input_observed",
            "resource_consuming_query_is_reachable",
            "no_effective_server_side_page_size_cap_observed",
        )
        reproduction = (
            "Request negative, zero, and excessive page or limit values in a bounded test environment.",
            "Verify that the server rejects invalid values and caps each response to the configured maximum.",
        )
        class_resolution = {
            "resource_consuming_collection_query_observed": True,
            "server_side_pagination_cap_observed": False,
            "resource_exhaustion_test_required": True,
        }
    elif candidate.sink_kind == "client_controlled_price_or_total":
        hypothesis = "A caller-controlled price, discount, subtotal, or total influences a cart operation instead of a server-trusted value."
        proof_obligations = (
            "caller_controlled_price_component_observed",
            "price_component_reaches_cart_result_or_state_change",
            "server_side_price_recomputation_not_observed",
        )
        reproduction = (
            "Submit negative, zero, and excessive quantities plus a modified client-side price in a test cart.",
            "Verify that the server ignores client prices, loads trusted prices, and rejects invalid quantities.",
        )
        class_resolution = {
            "caller_price_component_reaches_business_operation": True,
            "server_trusted_price_recomputation_observed": False,
            "boundary_tests_required": True,
        }
    else:
        hypothesis = "A caller-controlled domain value reaches a business operation without server-side bounds."
        proof_obligations = (
            "caller_controlled_domain_value_observed",
            "domain_value_reaches_business_operation",
            "no_numeric_or_domain_bound_guard_observed",
        )
        reproduction = (
            "Submit boundary, negative, zero, and excessive values in a non-production test environment.",
            "Every invalid value must be rejected before a result is returned or persistent state changes.",
        )
        class_resolution = {
            "caller_domain_value_reaches_business_operation": True,
            "numeric_or_domain_bound_guard_observed": False,
            "boundary_tests_required": True,
        }
    common_resolutions: dict[str, object] = {
        "caller_controlled_source": candidate.source_kind.startswith("http_"),
        "sensitive_sink_observed": True,
        "containing_function_search_complete": candidate.analysis_complete,
        "effective_control_for_exact_target_observed": False,
        "runtime_poc_executed": False,
        "source_symbol": candidate.source_symbol,
        "source_line": candidate.source_line,
        "sink_symbol": candidate.sink_symbol,
        "sink_line": candidate.sink_line,
        "sink_argument": candidate.sink_argument,
    }
    return {
        "attack_hypothesis": hypothesis,
        "proof_obligations": [
            {
                "fact": fact,
                "satisfied": candidate.analysis_complete,
                "provenance": "bounded_python_ast",
            }
            for fact in proof_obligations
        ],
        "counter_evidence_search": {
            "searched": candidate.analysis_complete,
            "observed_guard_symbols": list(candidate.guards),
            "effective_controls": [],
            "result": (
                "no_effective_class_specific_control_observed"
                if candidate.analysis_complete
                else "counter_evidence_search_incomplete"
            ),
        },
        "safe_reproduction_plan": list(reproduction),
        "retrieval_resolution": {
            "status": (
                "resolved_by_bounded_static_retrieval"
                if candidate.analysis_complete
                else "partially_resolved"
            ),
            "facts": {
                **common_resolutions,
                **class_resolution,
            },
            "remaining_limitation": "runtime_behavior_not_executed",
        },
    }


def _project_logic_evidence(
    evidence: EvidencePackage,
    candidate: LogicCandidate,
) -> dict[str, object]:
    """Project the reviewable source-guard-sink trace and plan risk factors."""
    projected = project_evidence(evidence)
    obligations = _logic_proof_obligations(candidate)
    projected["logic_analysis"] = {
        "logic_class": candidate.bug_class.value,
        "entrypoint": candidate.function,
        "entrypoint_exposed": candidate.entrypoint,
        "source_kind": candidate.source_kind,
        "sink_kind": candidate.sink_kind,
        "source_symbol": candidate.source_symbol,
        "source_line": candidate.source_line,
        "sink_symbol": candidate.sink_symbol,
        "sink_line": candidate.sink_line,
        "sink_argument": candidate.sink_argument,
        "guards": list(candidate.guards),
        "trace": list(candidate.trace),
        "cwe": candidate.cwe,
        "risk_score": candidate.risk_score,
        "risk_level": candidate.risk_level,
        "risk_factors": dict(candidate.risk_factors),
        "remediation": candidate.remediation,
        "validation_checklist": list(candidate.validation_checklist),
        "attack_hypothesis": obligations["attack_hypothesis"],
        "proof_obligations": obligations["proof_obligations"],
        "counter_evidence_search": obligations["counter_evidence_search"],
        "safe_reproduction_plan": obligations["safe_reproduction_plan"],
        "retrieval_resolution": obligations["retrieval_resolution"],
    }
    projected["retrieval_resolution"] = obligations["retrieval_resolution"]
    projected["deterministic_verification"] = {
        "mechanism": "logic_pattern",
        "evidence_complete": candidate.analysis_complete,
        "unsafe_pattern_observed": True,
        "logic_class": candidate.bug_class.value,
        "source_reaches_sink": True,
        "effective_controls": [],
        "has_evidence_conflict": False,
        "proof_obligations_satisfied": candidate.analysis_complete,
        "missing_proof_obligations": (
            [] if candidate.analysis_complete else ["bounded_analysis_incomplete"]
        ),
        "assessment": (
            "supported_by_bounded_static_analysis"
            if candidate.analysis_complete
            else "bounded_static_analysis_incomplete"
        ),
    }
    return projected


def build_evidence_context(
    finding: NormalizedFinding,
    sanitized_context: SanitizedContext,
    *,
    max_tool_calls: int = 5,
    max_depth: int = 5,
    logic_index: LogicFindingIndex | None = None,
    analysis_backend: AnalysisBackend | None = None,
) -> EvidenceContextResult:
    """Phân tích mã nguồn và thay snippet gửi provider bằng JSON bằng chứng an toàn."""
    logic_candidate = (
        logic_index.candidate_for(finding) if logic_index is not None else None
    )
    report_graph: GraphEvidence | None = None
    if logic_candidate is not None:
        evidence = _logic_evidence_package(
            finding,
            sanitized_context,
            logic_candidate,
        )
        expansion_tool_calls = 0
        expansion_tool_names = ("logic_candidate_projection",)
    elif (template_graph := _template_fallback_graph(finding)) is not None:
        report_graph = template_graph
        evidence = _graph_evidence_package(
            finding,
            sanitized_context,
            template_graph,
        )
        expansion_tool_calls = 0
        expansion_tool_names = ("template_context_projection",)
    elif (structural_graph := _scanner_structural_fallback_graph(finding)) is not None:
        report_graph = structural_graph
        evidence = _graph_evidence_package(
            finding,
            sanitized_context,
            structural_graph,
        )
        expansion_tool_calls = 0
        expansion_tool_names = ("scanner_structural_projection",)
    elif analysis_backend is not None:
        initial = analysis_backend.initial_evidence(finding)
        graph_expansion = GraphEvidenceExpansionAgent(
            analysis_backend,
            finding,
            initial,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
        ).expand()
        verified_graph = _merge_local_verification(
            finding,
            sanitized_context,
            graph_expansion.evidence,
        )
        evidence = _graph_evidence_package(
            finding,
            sanitized_context,
            verified_graph,
        )
        report_graph = verified_graph
        expansion_tool_calls = graph_expansion.tool_calls
        expansion_tool_names = graph_expansion.tool_names
    else:
        report_graph = GraphEvidence(
            sink_type="rule_specific_sink",
            sink_symbol=(
                "<scanner_reported_intrinsic>"
                if sink_only_evidence_is_sufficient(finding)
                else None
            ),
            sink_file=finding.file_path,
            sink_line=finding.start_line,
            limitations=("JOERN_BACKEND_UNAVAILABLE",),
            provenance=("JOERN_REQUIRED",),
        )
        evidence = _graph_evidence_package(
            finding,
            sanitized_context,
            report_graph,
        )
        expansion_tool_calls = 0
        expansion_tool_names = ()

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
                dict.fromkeys(
                    (
                        *evidence.context_completeness.missing_information,
                        "EVIDENCE_CODE_TRUNCATED",
                    )
                )
            ),
            limitations=tuple(
                dict.fromkeys(
                    (
                        *evidence.context_completeness.limitations,
                        "MAX_EVIDENCE_CODE_CHARACTERS",
                    )
                )
            ),
        )
        evidence = replace(
            evidence, relevant_code=relevant, context_completeness=completeness
        )

    projection = (
        _project_logic_evidence(evidence, logic_candidate)
        if logic_candidate is not None
        else project_evidence(evidence)
    )
    rendered = json.dumps(
        projection,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(rendered) > MAX_EVIDENCE_JSON_CHARACTERS:
        relevant = replace(
            evidence.relevant_code, code="<EVIDENCE_CODE_OMITTED_DUE_TO_LIMIT>"
        )
        completeness = replace(
            evidence.context_completeness,
            status=EvidenceStatus.PARTIAL,
            missing_information=tuple(
                dict.fromkeys(
                    (
                        *evidence.context_completeness.missing_information,
                        "EVIDENCE_SIZE_LIMIT_REACHED",
                    )
                )
            ),
            limitations=tuple(
                dict.fromkeys(
                    (
                        *evidence.context_completeness.limitations,
                        "MAX_EVIDENCE_JSON_CHARACTERS",
                    )
                )
            ),
        )
        evidence = replace(
            evidence, relevant_code=relevant, context_completeness=completeness
        )
        projection = (
            _project_logic_evidence(evidence, logic_candidate)
            if logic_candidate is not None
            else project_evidence(evidence)
        )
        rendered = json.dumps(
            projection,
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
        report_evidence=_report_evidence_projection(evidence, report_graph),
    )
