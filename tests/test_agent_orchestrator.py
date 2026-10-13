"""Unit tests for ControlledTriageAgent orchestration and safety fallback."""

from __future__ import annotations

from pathlib import Path
import pytest

from sast_triage.agent.models import AgentMode
from sast_triage.agent.orchestrator import ControlledTriageAgent
from sast_triage.analysis.base import GraphEvidence, QueryResultStatus
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PathCategory,
    PolicyAction,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
    TriageDecision,
)

SAMPLE_APP_CODE = """
from django.db import models, transaction
from django.contrib.auth.decorators import login_required

class Invoice(models.Model):
    user_id = models.IntegerField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)

@login_required
def view_invoice(request, invoice_id):
    return Invoice.objects.get(id=invoice_id)

def transfer_funds(src, dst, amount):
    with transaction.atomic():
        src.balance -= amount
        dst.balance += amount
"""


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "views.py").write_text(SAMPLE_APP_CODE, encoding="utf-8")
    return repo


@pytest.fixture
def finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="f-idor-test-1",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.django.idor",
        file_path="views.py",
        start_line=10,
        severity=Severity.HIGH,
        message="Potential IDOR",
        metadata={"cwe": ["CWE-639"]},
    )


@pytest.fixture
def context() -> SanitizedContext:
    return SanitizedContext(
        finding_id="f-idor-test-1",
        sanitized_snippet="def view_invoice(request, invoice_id):\n    return Invoice.objects.get(id=invoice_id)",
        context_strategy=ContextStrategy.PYTHON_FUNCTION,
        context_start_line=9,
        context_end_line=15,
        finding_start_line=10,
        enclosing_function="view_invoice",
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )


def test_agent_mode_off_bypasses_loop(repo_root: Path, finding: NormalizedFinding, context: SanitizedContext) -> None:
    agent = ControlledTriageAgent(repo_root, agent_mode=AgentMode.OFF)
    tier1 = TriageDecision(
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Tier-1 decision",
        model_version="v1",
        prompt_version="v1",
    )
    res = agent.triage(finding, context, tier1_decision=tier1)
    assert res.escalated_to_agent is False
    assert res.tool_calls_executed == 0
    assert len(res.trace) == 0


def test_agent_mode_escalate_triggers_on_unknown(
    repo_root: Path, finding: NormalizedFinding, context: SanitizedContext
) -> None:
    agent = ControlledTriageAgent(repo_root, agent_mode=AgentMode.ESCALATE)
    initial_ev = GraphEvidence(
        sink_symbol="Invoice.objects.get",
        query_status=QueryResultStatus.UNKNOWN,
        reachability_resolved=False,
    )
    res = agent.triage(finding, context, initial_evidence=initial_ev)
    assert res.escalated_to_agent is True
    assert res.tool_calls_executed >= 1
    assert len(res.trace) >= 1
    assert len(res.ledger.entries) >= 1


def test_agent_mode_always_executes_loop_and_caches_tools(
    repo_root: Path, finding: NormalizedFinding, context: SanitizedContext
) -> None:
    agent = ControlledTriageAgent(repo_root, agent_mode=AgentMode.ALWAYS)

    # First call: executes tools and populates cache
    res1 = agent.triage(finding, context)
    assert res1.escalated_to_agent is True
    assert res1.tool_calls_executed >= 1

    # Second call with same function: hits tool cache
    cached_tool_count = len(agent._tool_cache)
    assert cached_tool_count >= 1

    res2 = agent.triage(finding, context)
    assert res2.escalated_to_agent is True
    # Ensure cache is reused
    assert len(agent._tool_cache) == cached_tool_count


def test_agent_safe_fallback_on_error(
    repo_root: Path, finding: NormalizedFinding, context: SanitizedContext
) -> None:
    agent = ControlledTriageAgent(repo_root, agent_mode=AgentMode.ALWAYS)
    # Inject a broken planner to simulate crash
    agent._planner.plan_next_action = lambda *args, **kwargs: 1 / 0  # type: ignore

    res = agent.triage(finding, context)
    assert res.escalated_to_agent is True
    assert res.fallback_applied is True
    # Still produces safe fail-closed policy action!
    assert res.policy_decision.action in (PolicyAction.MANUAL_REVIEW, PolicyAction.LIKELY_TP)
