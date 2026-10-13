"""Unit tests for Controlled Agent Tools, ActionValidator, and EvidenceLedger."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from sast_triage.agent.models import AgentAction
from sast_triage.agent.ledger import EvidenceLedger
from sast_triage.agent.validator import ActionValidator
from sast_triage.agent.tools import AgentToolRegistry
from sast_triage.analysis.base import QueryResultStatus
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    ScannerType,
    Severity,
)

SAMPLE_APP_CODE = """
from django.db import models, transaction
from django.contrib.auth.decorators import login_required

class Invoice(models.Model):
    user_id = models.IntegerField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        fields = ["amount"]

@login_required
def view_invoice(request, invoice_id):
    calc_fee(10)
    return Invoice.objects.get(id=invoice_id)

def calc_fee(amount):
    return amount * 0.1

def transfer_funds(src, dst, amount):
    with transaction.atomic():
        src.balance -= amount
        dst.balance += amount
"""


@pytest.fixture
def test_repo_root(tmp_path: Path) -> Path:
    repo = tmp_path / "sample_repo"
    repo.mkdir()
    (repo / "views.py").write_text(SAMPLE_APP_CODE, encoding="utf-8")
    return repo


@pytest.fixture
def sample_finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="f-agent-test-1",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.django.idor",
        file_path="views.py",
        start_line=13,
        severity=Severity.HIGH,
        message="Potential IDOR",
        metadata={"cwe": ["CWE-639"]},
    )


# -------------------------------------------------------------
# ActionValidator Tests
# -------------------------------------------------------------


def test_validator_accepts_valid_read_function(test_repo_root: Path) -> None:
    validator = ActionValidator(test_repo_root)
    ledger = EvidenceLedger()

    action = AgentAction(
        tool="read_function",
        parameters={"symbol_name": "view_invoice", "file_path": "views.py"},
    )
    res = validator.validate_action(action, ledger)
    assert res.is_valid is True
    assert res.canonical_signature == "read_function:views.py:view_invoice"


def test_validator_blocks_non_allowlisted_tool(test_repo_root: Path) -> None:
    validator = ActionValidator(test_repo_root)
    ledger = EvidenceLedger()

    action = AgentAction(tool="execute_bash_command", parameters={"cmd": "ls"})
    res = validator.validate_action(action, ledger)
    assert res.is_valid is False
    assert res.error_code == "TOOL_NOT_ALLOWLISTED"


def test_validator_blocks_path_traversal(test_repo_root: Path) -> None:
    validator = ActionValidator(test_repo_root)
    ledger = EvidenceLedger()

    traversal_actions = [
        AgentAction(tool="read_function", parameters={"symbol_name": "f", "file_path": "../etc/passwd"}),
        AgentAction(tool="read_function", parameters={"symbol_name": "f", "file_path": "/views.py"}),
        AgentAction(tool="read_function", parameters={"symbol_name": "f", "file_path": "C:\\views.py"}),
    ]
    for act in traversal_actions:
        res = validator.validate_action(act, ledger)
        assert res.is_valid is False
        assert "PATH" in str(res.error_code)


def test_validator_blocks_duplicate_query(test_repo_root: Path) -> None:
    validator = ActionValidator(test_repo_root)
    ledger = EvidenceLedger()

    action = AgentAction(
        tool="read_function",
        parameters={"symbol_name": "view_invoice", "file_path": "views.py"},
    )
    # First time: valid
    res1 = validator.validate_action(action, ledger)
    assert res1.is_valid is True

    # Record into ledger
    ledger.add_entry(
        tool_name="read_function",
        parameters=action.parameters,
        canonical_signature=res1.canonical_signature,
        query_status=QueryResultStatus.FOUND,
        status_reason="OK",
        summary="Extracted function",
    )

    # Second time: blocked as duplicate
    res2 = validator.validate_action(action, ledger)
    assert res2.is_valid is False
    assert res2.error_code == "DUPLICATE_QUERY"


# -------------------------------------------------------------
# AgentToolRegistry Tests
# -------------------------------------------------------------


def test_tool_read_function(test_repo_root: Path, sample_finding: NormalizedFinding) -> None:
    tools = AgentToolRegistry(test_repo_root)
    status, reason, summary, facts = tools.execute_tool(
        "read_function",
        {"symbol_name": "view_invoice", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert "view_invoice" in facts["code_snippet"]
    assert facts["truncated"] is False


def test_tool_find_callers_and_callees(test_repo_root: Path, sample_finding: NormalizedFinding) -> None:
    tools = AgentToolRegistry(test_repo_root)

    # find_callees: view_invoice calls calc_fee
    status, _, _, facts = tools.execute_tool(
        "find_callees",
        {"symbol_name": "view_invoice", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert "calc_fee" in facts["callees"]

    # find_callers: calc_fee is called by view_invoice
    status, _, _, facts = tools.execute_tool(
        "find_callers",
        {"symbol_name": "calc_fee", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert any(c["caller_function"] == "view_invoice" for c in facts["callers"])


def test_tool_get_route_decorators(test_repo_root: Path, sample_finding: NormalizedFinding) -> None:
    tools = AgentToolRegistry(test_repo_root)
    status, _, _, facts = tools.execute_tool(
        "get_route_decorators",
        {"symbol_name": "view_invoice", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert "login_required" in facts["decorators"]
    assert facts["has_auth"] is True
    assert facts["has_csrf_exempt"] is False


def test_tool_get_model_schema(test_repo_root: Path, sample_finding: NormalizedFinding) -> None:
    tools = AgentToolRegistry(test_repo_root)
    status, _, _, facts = tools.execute_tool(
        "get_model_schema",
        {"model_name": "Invoice", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert facts["has_ownership_field"] is True
    assert "amount" in facts["allowlisted_fields"]


def test_tool_check_lock_or_transaction(test_repo_root: Path, sample_finding: NormalizedFinding) -> None:
    tools = AgentToolRegistry(test_repo_root)

    # transfer_funds has atomic transaction
    status, _, _, facts = tools.execute_tool(
        "check_lock_or_transaction",
        {"symbol_name": "transfer_funds", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert facts["has_atomic_transaction"] is True

    # view_invoice does NOT have atomic transaction
    status, _, _, facts = tools.execute_tool(
        "check_lock_or_transaction",
        {"symbol_name": "view_invoice", "file_path": "views.py"},
        sample_finding,
    )
    assert status == QueryResultStatus.FOUND
    assert facts["has_atomic_transaction"] is False


# -------------------------------------------------------------
# EvidenceLedger Tests
# -------------------------------------------------------------


def test_evidence_ledger_formatting() -> None:
    ledger = EvidenceLedger()
    assert "(Ledger is empty" in ledger.to_prompt_context()

    ledger.add_entry(
        tool_name="get_route_decorators",
        parameters={"symbol_name": "view_invoice", "file_path": "views.py"},
        canonical_signature="get_route_decorators:views.py:view_invoice",
        query_status=QueryResultStatus.FOUND,
        status_reason="DECORATORS_INSPECTED",
        summary="Found @login_required",
        facts={"has_auth": True},
    )

    ctx = ledger.to_prompt_context()
    assert "<UNTRUSTED_EVIDENCE_LEDGER>" in ctx
    assert "Tool: get_route_decorators" in ctx
    assert "Status: FOUND" in ctx
    assert "</UNTRUSTED_EVIDENCE_LEDGER>" in ctx
    assert ledger.has_unknowns() is False
