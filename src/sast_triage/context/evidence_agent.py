"""Tầng 1: Bounded Evidence Collector (Thu thập bằng chứng tất định có giới hạn).

LƯU Ý THIẾT KẾ:
Đây là một quy trình tất định (deterministic workflow) điều khiển bằng logic if-elif
và ngân sách cố định (số bước, độ sâu, thời gian timeout), KHÔNG PHẢI là một LLM-driven agent
tự do chọn tool. Quy trình này thu thập dữ kiện từ code property graph (Joern) và AST
để chuyển cho Tầng 2 (LLM Triage Reasoner).
"""

from __future__ import annotations

from enum import Enum
import time
from dataclasses import dataclass, replace

from sast_triage.analysis.base import AnalysisBackend, GraphEvidence
from sast_triage.analysis.rule_semantics import (
    RuleMechanism,
    mechanism_for_rule_id,
    sink_only_evidence_is_sufficient,
)
from sast_triage.models import NormalizedFinding


class VulnerabilityCategory(str, Enum):
    """Phân loại nhóm lỗ hổng để áp dụng schema bằng chứng chuyên biệt."""

    INJECTION = "injection"  # SQLi, CMDi, Path Traversal, Deserialization, SSRF, XSS
    CRYPTO_SECRETS = "crypto_secrets"  # Weak hash, weak cipher, weak random, hardcoded secret
    IDOR = "idor"  # Broken object level authz, direct object reference
    MASS_ASSIGNMENT = "mass_assignment"  # Unrestricted parameter binding
    TOCTOU = "toctou"  # Race condition, check-then-use
    GENERAL_TAINT = "general_taint"  # Generic dataflow / taint
    CONFIGURATION = "configuration"  # Misconfigurations (debug mode, secure cookie, csrf)


def classify_vulnerability_category(finding: NormalizedFinding) -> VulnerabilityCategory:
    """Xác định nhóm lỗ hổng từ CWE và rule_id để áp dụng evidence schema tương ứng."""
    cwe_list = [str(c).upper() for c in finding.metadata.get("cwe", [])]
    rule_lower = finding.rule_id.lower()

    # 1. Injection & Taint (CWE-89, 78, 22, 502, 918, 79, 94, 95)
    injection_cwes = {"CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-918", "CWE-79", "CWE-94", "CWE-95"}
    if any(cwe in injection_cwes for cwe in cwe_list) or any(
        k in rule_lower for k in ("sql", "injection", "command", "travers", "deserial", "ssrf", "xss", "eval")
    ):
        return VulnerabilityCategory.INJECTION

    # 2. Crypto & Secrets (CWE-327, 328, 330, 798)
    crypto_cwes = {"CWE-327", "CWE-328", "CWE-330", "CWE-798"}
    if any(cwe in crypto_cwes for cwe in cwe_list) or any(
        k in rule_lower for k in ("hash", "crypto", "cipher", "secret", "jwt", "random")
    ):
        return VulnerabilityCategory.CRYPTO_SECRETS

    # 3. IDOR / Authorization (CWE-639, 284, 285)
    idor_cwes = {"CWE-639", "CWE-284", "CWE-285"}
    if any(cwe in idor_cwes for cwe in cwe_list) or any(
        k in rule_lower for k in ("idor", "authz", "ownership", "tenant", "object-level")
    ):
        return VulnerabilityCategory.IDOR

    # 4. Mass Assignment (CWE-915)
    if "CWE-915" in cwe_list or any(
        k in rule_lower for k in ("mass-assignment", "over-posting", "binding")
    ):
        return VulnerabilityCategory.MASS_ASSIGNMENT

    # 5. TOCTOU / Race Condition (CWE-362, 367)
    race_cwes = {"CWE-362", "CWE-367"}
    if any(cwe in race_cwes for cwe in cwe_list) or any(
        k in rule_lower for k in ("race", "toctou", "concurrency")
    ):
        return VulnerabilityCategory.TOCTOU

    # Fallback to RuleMechanism
    mech = mechanism_for_rule_id(finding.rule_id)
    if mech == RuleMechanism.CONFIGURATION:
        return VulnerabilityCategory.CONFIGURATION
    if mech == RuleMechanism.INTRINSIC_USAGE:
        return VulnerabilityCategory.CRYPTO_SECRETS
    return VulnerabilityCategory.GENERAL_TAINT


@dataclass(frozen=True, slots=True)
class BoundedEvidenceCollectionResult:
    """Kết quả thu thập bằng chứng đồ thị có giới hạn ngân sách."""

    evidence: GraphEvidence
    tool_calls: int
    tool_names: tuple[str, ...]
    category: VulnerabilityCategory = VulnerabilityCategory.GENERAL_TAINT


# Backward compatibility alias
GraphEvidenceExpansionResult = BoundedEvidenceCollectionResult


class BoundedEvidenceCollector:
    """Tầng 1: Thu thập bằng chứng Joern có giới hạn và xác định (Deterministic)."""

    def __init__(
        self,
        backend: AnalysisBackend,
        finding: NormalizedFinding,
        initial: GraphEvidence,
        *,
        max_iterations: int = 5,
        max_tool_calls: int = 5,
        max_depth: int = 5,
        max_paths: int = 50,
        max_nodes: int = 1_000,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not 1 <= max_iterations <= 5:
            raise ValueError("max_iterations must be between 1 and 5")
        if not 1 <= max_tool_calls <= 5:
            raise ValueError("max_tool_calls must be between 1 and 5")
        if not 1 <= max_depth <= 5:
            raise ValueError("max_depth must be between 1 and 5")
        if max_paths < 1 or max_nodes < 1 or timeout_seconds <= 0:
            raise ValueError("graph query budgets must be positive")
        self._backend = backend
        self._finding = finding
        self._initial = initial
        self._max_iterations = max_iterations
        self._max_tool_calls = max_tool_calls
        self._max_depth = max_depth
        self._max_paths = max_paths
        self._max_nodes = max_nodes
        self._timeout_seconds = timeout_seconds
        self._category = classify_vulnerability_category(finding)

    @property
    def category(self) -> VulnerabilityCategory:
        return self._category

    @staticmethod
    def _is_intrinsic(finding: NormalizedFinding) -> bool:
        return sink_only_evidence_is_sufficient(finding)

    def _sufficient_injection(self, evidence: GraphEvidence) -> bool:
        """Schema kiểm tra cho nhóm Injection / General Taint: source, sink, reachability và guard."""
        if evidence.sink_symbol is None:
            return False
        return (
            evidence.source_type is not None
            and evidence.source_reaches_sink is True
            and evidence.path_complete
            and evidence.reachability_resolved
            and "JOERN_CONTROL_FLOW" in evidence.provenance
        )

    def _sufficient_crypto(self, evidence: GraphEvidence) -> bool:
        """Schema kiểm tra cho nhóm Crypto / Secrets: định vị sink sử dụng hàm nhạy cảm."""
        return evidence.sink_symbol is not None

    def _sufficient_idor(self, evidence: GraphEvidence) -> bool:
        """Schema kiểm tra cho nhóm IDOR: sink query và security control / tenant scoping."""
        if evidence.sink_symbol is None:
            return False
        return evidence.reachability_resolved and "JOERN_CONTROL_FLOW" in evidence.provenance

    def _sufficient_mass_assignment(self, evidence: GraphEvidence) -> bool:
        """Schema kiểm tra cho nhóm Mass Assignment: model sink và allowlist guard."""
        if evidence.sink_symbol is None:
            return False
        return "JOERN_CONTROL_FLOW" in evidence.provenance

    def _sufficient_toctou(self, evidence: GraphEvidence) -> bool:
        """Schema kiểm tra cho nhóm TOCTOU: mutation sink, flow và lock/transaction check."""
        if evidence.sink_symbol is None:
            return False
        return evidence.reachability_resolved and "JOERN_CONTROL_FLOW" in evidence.provenance

    def _sufficient(self, evidence: GraphEvidence) -> bool:
        """Đánh giá điều kiện dừng thu thập dựa theo schema từng nhóm lỗ hổng."""
        if self._is_intrinsic(self._finding):
            return self._sufficient_crypto(evidence)

        if self._category == VulnerabilityCategory.INJECTION or self._category == VulnerabilityCategory.GENERAL_TAINT:
            return self._sufficient_injection(evidence)
        elif self._category == VulnerabilityCategory.CRYPTO_SECRETS:
            return self._sufficient_crypto(evidence)
        elif self._category == VulnerabilityCategory.IDOR:
            return self._sufficient_idor(evidence)
        elif self._category == VulnerabilityCategory.MASS_ASSIGNMENT:
            return self._sufficient_mass_assignment(evidence)
        elif self._category == VulnerabilityCategory.TOCTOU:
            return self._sufficient_toctou(evidence)
        elif self._category == VulnerabilityCategory.CONFIGURATION:
            return evidence.sink_symbol is not None

        return self._sufficient_injection(evidence)

    def _next_tool(self, evidence: GraphEvidence) -> str | None:
        """Lựa chọn tool tiếp theo theo quy tắc tất định tương ứng với nhóm lỗ hổng."""
        if self._category in (VulnerabilityCategory.INJECTION, VulnerabilityCategory.GENERAL_TAINT):
            if (
                evidence.source_type is None
                or evidence.source_reaches_sink is not True
                or not evidence.path_complete
            ):
                return "trace_dataflow"
            if not evidence.reachability_resolved:
                return "find_reachability"
            if "JOERN_CONTROL_FLOW" not in evidence.provenance:
                return "inspect_security_control"
            return None

        if self._category == VulnerabilityCategory.CRYPTO_SECRETS:
            if evidence.sink_symbol is None:
                return "trace_dataflow"
            return None

        if self._category in (VulnerabilityCategory.IDOR, VulnerabilityCategory.TOCTOU):
            if not evidence.reachability_resolved:
                return "find_reachability"
            if "JOERN_CONTROL_FLOW" not in evidence.provenance:
                return "inspect_security_control"
            return None

        if self._category == VulnerabilityCategory.MASS_ASSIGNMENT:
            if "JOERN_CONTROL_FLOW" not in evidence.provenance:
                return "inspect_security_control"
            return None

        # Fallback default sequence
        if (
            evidence.source_type is None
            or evidence.source_reaches_sink is not True
            or not evidence.path_complete
        ):
            return "trace_dataflow"
        if not evidence.reachability_resolved:
            return "find_reachability"
        if "JOERN_CONTROL_FLOW" not in evidence.provenance:
            return "inspect_security_control"
        return None

    def expand(self) -> BoundedEvidenceCollectionResult:
        """Thực hiện tối đa 5 bước thu thập tất định và dừng khi đủ bằng chứng hoặc không tiến triển."""
        evidence = self._initial
        tool_names: list[str] = []
        visited: set[tuple[str, tuple[object, ...]]] = set()
        started = time.monotonic()

        for _ in range(self._max_iterations):
            if self._sufficient(evidence) or len(tool_names) >= self._max_tool_calls:
                break
            if time.monotonic() - started >= self._timeout_seconds:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_FINDING_TIMEOUT"))
                    ),
                )
                break
            tool_name = self._next_tool(evidence)
            if tool_name is None:
                break
            signature = (tool_name, evidence.fingerprint())
            if signature in visited:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_QUERY_REPEATED"))
                    ),
                )
                break
            visited.add(signature)
            previous = evidence.fingerprint()
            result = self._backend.run_tool(
                tool_name,
                self._finding,
                evidence,
                max_depth=self._max_depth,
                max_paths=self._max_paths,
                max_nodes=self._max_nodes,
            )
            tool_names.append(tool_name)
            evidence = evidence.merge(result)
            if evidence.fingerprint() == previous:
                evidence = replace(
                    evidence,
                    limitations=tuple(
                        dict.fromkeys((*evidence.limitations, "AGENT_NO_PROGRESS"))
                    ),
                )
                break

        if not self._sufficient(evidence) and len(tool_names) >= self._max_tool_calls:
            evidence = replace(
                evidence,
                limitations=tuple(
                    dict.fromkeys((*evidence.limitations, "MAX_TOOL_CALLS_REACHED"))
                ),
            )
        return BoundedEvidenceCollectionResult(
            evidence=evidence,
            tool_calls=len(tool_names),
            tool_names=tuple(tool_names),
            category=self._category,
        )


# Backward compatibility alias
GraphEvidenceExpansionAgent = BoundedEvidenceCollector
