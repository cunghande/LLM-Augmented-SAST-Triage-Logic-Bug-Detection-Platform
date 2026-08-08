"""Cổng kiểm tra mức độ đủ ngữ cảnh theo cách xác định."""

from sast_triage.context.evidence_models import EvidencePackage, EvidenceStatus


def requires_context_expansion(evidence: EvidencePackage) -> bool:
    """Trả về liệu các tool có giới hạn có phải thử hoàn thiện bằng chứng hay không."""
    completeness = evidence.context_completeness
    if completeness.status != EvidenceStatus.COMPLETE:
        return True
    if not completeness.source_resolved or not completeness.sink_resolved:
        return True
    if not completeness.taint_path_complete or not completeness.call_chain_complete:
        return True
    if not completeness.reachability_resolved:
        return True
    if completeness.unresolved_symbols or completeness.missing_information:
        return True
    if any(control.effective is None for control in evidence.security_controls):
        return True
    return any("MAX_DEPTH" in limitation for limitation in completeness.limitations)
