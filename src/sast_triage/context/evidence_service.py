"""Safe evidence projection service for the provider boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace

from sast_triage.context.evidence_agent import EvidenceExpansionAgent
from sast_triage.context.evidence_engine import CoreAnalysisEngine
from sast_triage.context.evidence_models import EvidencePackage, EvidenceStatus
from sast_triage.context.reader import SourceReadResult
from sast_triage.models import NormalizedFinding, SanitizedContext

MAX_EVIDENCE_CODE_CHARACTERS = 6_000
MAX_EVIDENCE_JSON_CHARACTERS = 12_000


@dataclass(frozen=True, slots=True)
class EvidenceContextResult:
    """Internal result used by the finding pipeline."""

    context: SanitizedContext
    evidence: EvidencePackage
    complete: bool
    tool_calls: int
    tool_names: tuple[str, ...]


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
    """Return an explicit provider-safe allowlisted projection."""
    sink = evidence.sink
    completeness = evidence.context_completeness
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
        "provenance": list(evidence.provenance),
    }


def build_evidence_context(
    finding: NormalizedFinding,
    source: SourceReadResult,
    sanitized_context: SanitizedContext,
    *,
    max_tool_calls: int = 5,
    max_depth: int = 5,
) -> EvidenceContextResult:
    """Analyze source and replace the provider snippet with safe evidence JSON."""
    engine = CoreAnalysisEngine(finding, source, sanitized_context)
    expansion = EvidenceExpansionAgent(
        engine,
        max_tool_calls=max_tool_calls,
        max_depth=max_depth,
    ).expand()
    evidence = expansion.evidence

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
        tool_calls=expansion.tool_calls,
        tool_names=expansion.tool_names,
    )
