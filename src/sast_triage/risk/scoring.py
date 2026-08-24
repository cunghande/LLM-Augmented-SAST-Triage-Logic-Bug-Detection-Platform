"""Deterministic, source-free risk scoring and remediation guidance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    Severity,
)

RISK_SCORING_VERSION = "deterministic-risk-v1"

_SEVERITY_SCORE = {
    Severity.CRITICAL: 5.0,
    Severity.HIGH: 4.25,
    Severity.MEDIUM: 3.25,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
    Severity.UNKNOWN: 2.5,
}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Internal immutable projection written into ``TriageResult`` fields."""

    score: float
    level: str
    factors: dict[str, float]
    remediation: str
    validation_checklist: tuple[str, ...]
    scoring_version: str = RISK_SCORING_VERSION


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if 0.0 <= number <= 5.0:
            return number
    return None


def _existing_logic_assessment(finding: NormalizedFinding) -> RiskAssessment | None:
    """Reuse the already-reviewed logic-detector assessment when complete."""
    metadata = finding.metadata
    score = _number(metadata.get("risk_score"))
    level = metadata.get("risk_level")
    raw_factors = metadata.get("risk_factors")
    remediation = metadata.get("remediation")
    raw_checklist = metadata.get("validation_checklist")
    if (
        score is None
        or level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or not isinstance(raw_factors, dict)
        or not isinstance(remediation, str)
        or not remediation.strip()
        or not isinstance(raw_checklist, list)
    ):
        return None
    factors = {str(key): _number(value) for key, value in raw_factors.items()}
    required = {
        "severity",
        "reachability",
        "exposure",
        "data_sensitivity",
        "exploitability",
    }
    if set(factors) != required or any(value is None for value in factors.values()):
        return None
    checklist = tuple(
        item.strip()
        for item in raw_checklist
        if isinstance(item, str) and item.strip()
    )
    if not checklist:
        return None
    return RiskAssessment(
        score=score,
        level=level,
        factors={key: float(value) for key, value in factors.items() if value is not None},
        remediation=remediation.strip(),
        validation_checklist=checklist,
    )


def _evidence_values(evidence: dict[str, Any] | None) -> tuple[object, bool, bool]:
    if not isinstance(evidence, dict):
        return None, False, False
    reaches = evidence.get("source_reaches_sink")
    complete = evidence.get("complete") is True
    sink_resolved = isinstance(evidence.get("sink"), dict)
    return reaches, complete, sink_resolved


def _reachability(
    finding: NormalizedFinding,
    evidence: dict[str, Any] | None,
) -> float:
    reaches, complete, sink_resolved = _evidence_values(evidence)
    if reaches is True:
        return 5.0
    if reaches is False:
        return 1.5
    if complete and sink_resolved:
        return 3.75
    if finding.finding_type == FindingType.SECRET:
        return 3.0
    return 2.5


def _exposure(context: SanitizedContext) -> float:
    return {
        PathCategory.PRODUCTION: 4.0,
        PathCategory.UNKNOWN: 3.0,
        PathCategory.TEST: 1.5,
        PathCategory.FIXTURE: 1.25,
        PathCategory.EXAMPLE: 1.25,
        PathCategory.DOCUMENTATION: 1.0,
    }[context.path_category]


def _sensitivity(finding: NormalizedFinding) -> float:
    if finding.finding_type == FindingType.SECRET:
        return 5.0
    text = " ".join(
        (
            finding.rule_id,
            finding.rule_name or "",
            str(finding.metadata.get("cwe", "")),
        )
    ).lower()
    if any(token in text for token in ("auth", "jwt", "secret", "credential", "639")):
        return 4.75
    if any(token in text for token in ("sql", "injection", "command", "popen", "89")):
        return 4.5
    if any(token in text for token in ("cookie", "crypto", "path", "file")):
        return 4.0
    return 3.5


def _exploitability(
    finding: NormalizedFinding,
    context: SanitizedContext,
    evidence: dict[str, Any] | None,
) -> float:
    reaches, complete, sink_resolved = _evidence_values(evidence)
    if reaches is True:
        return 4.5
    if reaches is False:
        return 2.0
    if complete and sink_resolved:
        return 3.75
    if finding.finding_type == FindingType.SECRET:
        return 2.0 if context.path_category != PathCategory.PRODUCTION else 3.5
    return 2.75


def _level(score: float) -> str:
    if score >= 4.2:
        return "CRITICAL"
    if score >= 3.4:
        return "HIGH"
    if score >= 2.4:
        return "MEDIUM"
    return "LOW"


def _guidance(finding: NormalizedFinding) -> tuple[str, tuple[str, ...]]:
    text = " ".join((finding.rule_id, finding.rule_name or "")).lower()
    common = (
        "Xác nhận lại finding trên đúng commit và môi trường kiểm thử được phép.",
        "Thêm regression test cho hành vi dễ tổn thương và hành vi an toàn mong đợi.",
        "Chạy lại scanner, Joern và test suite sau khi sửa; bắt buộc developer review.",
    )
    if finding.finding_type == FindingType.SECRET:
        secret_remediation = (
            "Thu hồi hoặc xoay vòng credential, xóa giá trị khỏi mã nguồn và lịch sử "
            "phù hợp, sau đó lấy secret từ secret manager hoặc biến môi trường được "
            "kiểm soát."
        )
        return (
            secret_remediation,
            (
                "Xác minh credential chỉ là canary/test hay đã từng có hiệu lực mà không ghi giá trị vào ticket hoặc log.",
                "Xác minh credential cũ đã bị revoke và không còn truy cập được.",
                "Bổ sung secret-scanning regression và kiểm tra lịch sử repository an toàn.",
            ),
        )
    if "jwt" in text or "verify" in text:
        return (
            "Bật xác minh chữ ký JWT, khóa thuật toán cho phép và kiểm tra issuer, audience cùng thời hạn token.",
            common,
        )
    if "sql" in text or "injection" in text or "text" in text:
        return (
            "Thay SQL ghép chuỗi bằng truy vấn tham số hóa hoặc API ORM; không nội suy dữ liệu không tin cậy vào câu lệnh.",
            common,
        )
    if "cookie" in text:
        return (
            "Bật Secure, HttpOnly và SameSite phù hợp cho cookie nhạy cảm; xác minh ứng dụng chỉ phục vụ qua HTTPS.",
            common,
        )
    if "hardcoded" in text or "secret_key" in text:
        return (
            "Di chuyển khóa cấu hình khỏi mã nguồn sang secret manager hoặc biến môi trường và xoay vòng giá trị đã lộ.",
            common,
        )
    if "popen" in text or "subprocess" in text or "command" in text:
        return (
            "Tránh shell command ghép chuỗi; dùng API đối số tách rời và allowlist giá trị nghiệp vụ ở trust boundary.",
            common,
        )
    if "open" in text or "path" in text:
        return (
            "Chuẩn hóa đường dẫn, allowlist tài nguyên hợp lệ và kiểm tra containment sau khi resolve trước khi truy cập file.",
            common,
        )
    return (
        "Xác minh trust boundary và toàn bộ đường source–control–sink, sau đó áp dụng kiểm soát theo khuyến nghị của rule.",
        common,
    )


def assess_finding_risk(
    finding: NormalizedFinding,
    context: SanitizedContext,
    evidence: dict[str, Any] | None,
) -> RiskAssessment:
    """Return a deterministic assessment for any normalized finding."""
    existing = _existing_logic_assessment(finding)
    if existing is not None:
        return existing

    factors = {
        "severity": _SEVERITY_SCORE[finding.severity],
        "reachability": _reachability(finding, evidence),
        "exposure": _exposure(context),
        "data_sensitivity": _sensitivity(finding),
        "exploitability": _exploitability(finding, context, evidence),
    }
    score = round(
        0.25 * factors["severity"]
        + 0.25 * factors["reachability"]
        + 0.20 * factors["exposure"]
        + 0.20 * factors["data_sensitivity"]
        + 0.10 * factors["exploitability"],
        2,
    )
    remediation, checklist = _guidance(finding)
    return RiskAssessment(
        score=score,
        level=_level(score),
        factors=factors,
        remediation=remediation,
        validation_checklist=checklist,
    )
