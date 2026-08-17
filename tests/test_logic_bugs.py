"""Tests for the bounded five-class Sprint 2 detector."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from sast_triage.analysis.native import NativeAnalysisBackend
from sast_triage.context.evidence_service import build_evidence_context
from sast_triage.context.python_scope import select_python_scope
from sast_triage.context.reader import read_repository_source
from sast_triage.context.repository_index import build_repository_index
from sast_triage.context.sanitizer import sanitize_context
from sast_triage.context.selection import select_raw_context
from sast_triage.logic import LogicBugClass, analyze_python_module
from sast_triage.triage.system_prompt import build_system_message

FIVE_CLASS_SOURCE = """
from flask import request

@app.get('/objects/<object_id>')
def object_detail(object_id, current_user, db):
    return db.query(Object).get(object_id)

@app.get('/safe/<object_id>')
def safe_object_detail(object_id, current_user, db):
    obj = db.query(Object).get(object_id)
    if obj.owner_id != current_user.id:
        raise PermissionError()
    return obj

@app.post('/profile')
def profile_update(request, user):
    payload = request.get_json()
    user.update(**payload)
    return user

@app.post('/transfer')
def transfer(amount, current_user, receiver, db):
    if current_user.balance < amount:
        raise ValueError()
    current_user.balance -= amount
    receiver.balance += amount
    db.commit()

@app.post('/purchase')
def purchase(quantity, db):
    order = db.create(quantity=quantity)
    db.commit()
    return order

@app.post('/password')
def change_password(request, user):
    payload = request.get_json()
    user.set_password(payload.get('new_password'))
    user.save()
"""


def test_analyzer_detects_all_five_plan_classes() -> None:
    candidates = analyze_python_module(
        ast.parse(FIVE_CLASS_SOURCE),
        file_path="app/routes.py",
        component=".",
    )

    assert {item.bug_class for item in candidates} == set(LogicBugClass)
    assert all(item.trace for item in candidates)
    assert all(item.risk_score >= 3.4 for item in candidates)
    assert all(item.remediation for item in candidates)


def test_analyzer_does_not_report_guarded_idor() -> None:
    candidates = analyze_python_module(
        ast.parse(FIVE_CLASS_SOURCE),
        file_path="app/routes.py",
        component=".",
    )

    assert not any(
        item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
        and item.function == "safe_object_detail"
        for item in candidates
    )


def test_analyzer_recognizes_local_and_authz_scoped_lookup_guards() -> None:
    source = """
@app.get('/applications/{application_id}')
def get_application(application_id, user, db):
    application = get_application_or_404(db, application_id)
    require_application_view(user, application)
    return application

@app.get('/jobs/{job_id}')
def get_job(job_id, user, db):
    return authz.load_job_for_view(db, user, job_id)
"""

    candidates = analyze_python_module(
        ast.parse(source),
        file_path="app/routes.py",
        component=".",
    )

    assert not any(
        item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
        for item in candidates
    )


def test_repository_index_projects_safe_logic_metadata(tmp_path: Path) -> None:
    source = tmp_path / "routes.py"
    source.write_text(FIVE_CLASS_SOURCE, encoding="utf-8")
    index = build_repository_index(tmp_path, "fixture")

    findings = index.discover_logic_findings()

    assert {item.metadata["logic_class"] for item in findings} == {
        item.value for item in LogicBugClass
    }
    assert all(item.scanner.value == "MODULE2" for item in findings)
    assert all("risk_score" in item.metadata for item in findings)
    assert all("remediation" in item.metadata for item in findings)


def test_repository_budget_prioritizes_high_risk_application_path(tmp_path: Path) -> None:
    ordinary = tmp_path / "aaa_misc.py"
    ordinary.write_text("def helper():\n    return 1\n", encoding="utf-8")
    sensitive = tmp_path / "payment_routes.py"
    sensitive.write_text(FIVE_CLASS_SOURCE, encoding="utf-8")

    index = build_repository_index(tmp_path, "fixture", max_python_files=1)

    assert index.skipped_files == 1
    assert index.logic_candidates
    assert {item.file_path for item in index.logic_candidates} == {"payment_routes.py"}


def test_logic_finding_gets_specialized_evidence_card(tmp_path: Path) -> None:
    source_path = tmp_path / "routes.py"
    source_path.write_text(FIVE_CLASS_SOURCE, encoding="utf-8")
    backend = NativeAnalysisBackend(tmp_path, "fixture", module2_enabled=True)
    finding = next(
        item
        for item in backend.discover_logic_findings("python-five-logic", ())
        if item.metadata["logic_class"] == LogicBugClass.MASS_ASSIGNMENT.value
    )
    source = read_repository_source(tmp_path, finding.file_path)
    scope = select_python_scope(source, finding.start_line, finding.end_line)
    raw = select_raw_context(finding, source, scope=scope)
    sanitized = sanitize_context(
        finding,
        raw,
        repository_index=backend.repository_index,
        analysis_backend=backend,
    )

    result = build_evidence_context(
        finding,
        source,
        sanitized,
        repository_index=backend.repository_index,
        analysis_backend=backend,
    )
    payload = json.loads(result.context.sanitized_snippet or "{}")

    assert result.complete is True
    assert payload["logic_analysis"]["logic_class"] == "mass_assignment"
    assert payload["logic_analysis"]["attack_hypothesis"]
    assert all(
        item["satisfied"]
        for item in payload["logic_analysis"]["proof_obligations"]
    )
    assert payload["logic_analysis"]["counter_evidence_search"]["searched"] is True
    assert payload["logic_analysis"]["safe_reproduction_plan"]
    assert payload["deterministic_verification"]["mechanism"] == "logic_pattern"
    assert payload["deterministic_verification"]["unsafe_pattern_observed"] is True
    assert payload["deterministic_verification"]["proof_obligations_satisfied"] is True


def test_prompt_v12_explains_bounded_proof_obligation_policy() -> None:
    prompt = build_system_message("model", "triage-prompt-v12")

    assert "proof_obligations_satisfied" in prompt
    assert "Do not abstain only because no runtime PoC was executed" in prompt
