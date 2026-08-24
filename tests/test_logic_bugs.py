"""Tests for the focused IDOR and business-rule Sprint 2 detector."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from sast_triage.context.evidence_service import build_evidence_context
from sast_triage.context.reader import read_repository_source
from sast_triage.context.sanitizer import sanitize_context
from sast_triage.context.selection import select_raw_context
from sast_triage.logic import LogicBugClass, LogicCandidate, analyze_python_module
from sast_triage.logic.index import build_logic_index
from sast_triage.triage.system_prompt import build_system_message

FOCUSED_USE_CASE_SOURCE = """
from flask import request

@app.get('/documents/<document_id>')
def document_detail(document_id, current_user, db):
    return db.query(Document).get(document_id)

@app.get('/safe/<document_id>')
def safe_document_detail(document_id, current_user, db):
    document = db.query(Document).get(document_id)
    if document.owner_id != current_user.id:
        raise PermissionError()
    return document

@app.post('/cart/total')
def calculate_cart_total(request, db):
    payload = request.get_json()
    quantity = payload.get('quantity')
    client_price = payload.get('price')
    total = quantity * client_price
    return db.create(total=total)

@app.get('/admin/users')
def list_users(request, db):
    limit = request.args.get('limit')
    return db.query(User).limit(limit).all()

@app.get('/admin/images')
def list_images(db):
    return db.query(Image).all()
"""


def _analyze(source: str = FOCUSED_USE_CASE_SOURCE) -> tuple[LogicCandidate, ...]:
    return analyze_python_module(
        ast.parse(source),
        file_path="app/routes.py",
        component=".",
    )


def test_analyzer_emits_only_the_two_focused_logic_classes() -> None:
    candidates = _analyze()

    assert {item.bug_class for item in candidates} == set(LogicBugClass)
    assert {item.bug_class for item in candidates} == {
        LogicBugClass.MISSING_AUTHZ_IDOR,
        LogicBugClass.BUSINESS_RULE_BYPASS,
    }
    assert all(item.trace for item in candidates)
    assert all(item.risk_score >= 3.4 for item in candidates)
    assert all(item.remediation for item in candidates)


def test_analyzer_detects_unshared_document_idor() -> None:
    candidates = _analyze()

    assert any(
        item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
        and item.function == "document_detail"
        and item.sink_kind == "object_lookup_without_subject_scope"
        for item in candidates
    )


def test_analyzer_does_not_report_guarded_or_subject_scoped_idor() -> None:
    source = FOCUSED_USE_CASE_SOURCE + """
@app.get('/shared/{document_id}')
def shared_document(document_id, current_user, db):
    return db.query(Document).filter(
        Document.id == document_id,
        DocumentShare.user_id == current_user.id,
    ).first()

@app.get('/applications/{application_id}')
def get_application(application_id, user, db):
    application = get_application_or_404(db, application_id)
    require_application_view(user, application)
    return application
"""
    candidates = _analyze(source)

    idor_functions = {
        item.function
        for item in candidates
        if item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
    }
    assert "document_detail" in idor_functions
    assert "safe_document_detail" not in idor_functions
    assert "shared_document" not in idor_functions
    assert "get_application" not in idor_functions


def test_analyzer_detects_route_reference_and_rejects_real_subject_scope() -> None:
    source = """
@app.get('/accounts/<account_ref>')
def account_card(account_ref):
    cards = {'a': {'owner': 'one'}}
    return cards.get(account_ref)

@app.get('/notes/<user_id>')
def personal_notes(user_id, current_user, db):
    return db.query(Note).filter(Note.user_id == user_id).all()

@app.get('/safe-notes/<user_id>')
def safe_personal_notes(user_id, current_user, db):
    return db.query(Note).filter(
        Note.user_id == user_id,
        Note.owner_id == current_user.id,
    ).all()
"""
    candidates = _analyze(source)
    functions = {
        item.function
        for item in candidates
        if item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
    }

    assert "account_card" in functions
    assert "personal_notes" in functions
    assert "safe_personal_notes" not in functions


def test_analyzer_handles_class_and_graphql_endpoints_and_effective_guards() -> None:
    source = """
class UserResource:
    def get(self, id):
        if not is_admin_or_owning_user(id):
            return {'error': 'forbidden'}
        return User.query.filter_by(id=id).first()

class EditPaste:
    def mutate(self, info, id, title=None):
        return Paste.query.filter_by(id=id).update({'title': title})

class Query:
    def resolve_delete_all_pastes(self, info):
        Paste.query.delete()
        return True
"""
    candidates = _analyze(source)
    functions = {
        item.function
        for item in candidates
        if item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
    }

    assert "get" not in functions
    assert "mutate" in functions
    assert "resolve_delete_all_pastes" in functions


def test_analyzer_does_not_treat_framework_hook_as_privileged_endpoint() -> None:
    source = """
@app.before_request
def set_difficulty():
    mode = request.headers.get('X-MODE')
    if mode:
        helpers.set_mode(mode)
"""

    assert not any(
        item.sink_kind == "privileged_endpoint_without_authorization"
        for item in _analyze(source)
    )


def test_non_blocking_actor_comparison_does_not_hide_idor() -> None:
    source = """
@app.get('/profiles/<user_id>')
def profile(user_id, current_user, db):
    profile = db.query(User).get(user_id)
    if user_id != current_user.id:
        audit('cross-account access')
    return profile
"""

    assert any(
        item.function == "profile"
        and item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
        for item in _analyze(source)
    )


def test_role_object_and_boolean_authorization_guards_suppress_idor() -> None:
    source = """
@app.get('/submissions/<pk>')
def submission_detail(request, pk, db):
    submission = db.query(Submission).get(pk)
    if submission.student_id != request.user.id:
        raise PermissionError()
    return submission

@app.get('/appointments/<pk>')
def appointment_detail(request, pk, db):
    appointment = db.query(Appointment).get(pk)
    if request.user.is_patient and appointment.patient != request.user.patient_profile:
        return forbidden()
    return appointment

@app.get('/documents/<pk>')
def document_download(request, pk, db):
    document = db.query(Document).get(pk)
    can_download = document.employee.user == request.user
    if not can_download:
        return forbidden()
    return document

@app.get('/organizations/<pk>')
def organization_detail(request, pk, db):
    organization = db.query(Organization).get(pk)
    if not organization_access(request, organization):
        return forbidden()
    return organization
"""

    idor_functions = {
        item.function
        for item in _analyze(source)
        if item.bug_class == LogicBugClass.MISSING_AUTHZ_IDOR
    }
    assert idor_functions.isdisjoint(
        {
            "submission_detail",
            "appointment_detail",
            "document_download",
            "organization_detail",
        }
    )


def test_analyzer_detects_request_map_overwriting_authenticated_actor() -> None:
    source = """
@app.post('/posts')
def create_post(request):
    data = {'username': authenticate(request)}
    data.update(request.get_json())
    return save_post(data['username'], data['text'])
"""

    assert any(
        item.function == "create_post"
        and item.sink_kind == "request_mapping_overwrites_actor_binding"
        for item in _analyze(source)
    )


def test_analyzer_detects_client_controlled_cart_price() -> None:
    candidates = _analyze()

    assert any(
        item.bug_class == LogicBugClass.BUSINESS_RULE_BYPASS
        and item.function == "calculate_cart_total"
        and item.sink_kind == "client_controlled_price_or_total"
        for item in candidates
    )


def test_analyzer_accepts_server_price_and_bounded_quantity() -> None:
    source = """
@app.post('/cart/total')
def calculate_cart_total(quantity, product_id, db):
    if quantity <= 0 or quantity > 100:
        raise ValueError()
    product = db.query(Product).get(product_id)
    total = quantity * product.price
    return {'total': total}
"""
    candidates = _analyze(source)

    assert not any(
        item.bug_class == LogicBugClass.BUSINESS_RULE_BYPASS
        for item in candidates
    )


def test_analyzer_detects_unbounded_request_delta_returned_to_business_result() -> None:
    source = """
@app.post('/credits')
def apply_credit_delta(request):
    payload = request.get_json()
    delta_value = float(payload.get('delta_value', 0))
    return {'approved_delta': delta_value, 'status': 'applied'}
"""

    assert any(
        item.function == "apply_credit_delta"
        and item.bug_class == LogicBugClass.BUSINESS_RULE_BYPASS
        for item in _analyze(source)
    )


def test_analyzer_detects_unbounded_pagination_and_collection_query() -> None:
    candidates = _analyze()
    sinks = {
        item.sink_kind
        for item in candidates
        if item.bug_class == LogicBugClass.BUSINESS_RULE_BYPASS
    }

    assert "unbounded_pagination_parameter" in sinks
    assert "unbounded_collection_query" in sinks


def test_pagination_parameter_uses_specific_sink_not_generic_domain_value() -> None:
    source = """
class Query:
    def resolve_items(self, info, limit=1000):
        return Item.query.order_by(Item.id).limit(limit)
"""
    candidates = _analyze(source)

    assert any(
        item.sink_kind == "unbounded_pagination_parameter" for item in candidates
    )
    assert not any(
        item.sink_kind == "unvalidated_domain_value_operation"
        for item in candidates
    )


def test_analyzer_accepts_bounded_pagination() -> None:
    source = """
@app.get('/admin/users')
def list_users(request, db):
    page = request.args.get('page')
    limit = request.args.get('limit')
    if page < 1:
        raise ValueError()
    if limit < 1 or limit > 100:
        raise ValueError()
    return db.query(User).limit(limit).offset((page - 1) * limit).all()
"""
    candidates = _analyze(source)

    assert not any(
        item.bug_class == LogicBugClass.BUSINESS_RULE_BYPASS
        for item in candidates
    )


def test_logic_index_projects_safe_metadata(tmp_path: Path) -> None:
    source = tmp_path / "routes.py"
    source.write_text(FOCUSED_USE_CASE_SOURCE, encoding="utf-8")
    index = build_logic_index(tmp_path)

    findings = index.discover_findings()

    assert {item.metadata["logic_class"] for item in findings} == {
        item.value for item in LogicBugClass
    }
    assert all(item.scanner.value == "MODULE2" for item in findings)
    assert all("risk_score" in item.metadata for item in findings)
    assert all("remediation" in item.metadata for item in findings)


def test_repository_budget_prioritizes_high_risk_application_path(
    tmp_path: Path,
) -> None:
    ordinary = tmp_path / "aaa_misc.py"
    ordinary.write_text("def helper():\n    return 1\n", encoding="utf-8")
    sensitive = tmp_path / "payment_routes.py"
    sensitive.write_text(FOCUSED_USE_CASE_SOURCE, encoding="utf-8")

    index = build_logic_index(tmp_path, max_python_files=1)

    assert index.skipped_files == 1
    assert index.candidates
    assert {item.file_path for item in index.candidates} == {
        "payment_routes.py"
    }


def test_business_rule_finding_gets_specialized_evidence_card(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "routes.py"
    source_path.write_text(FOCUSED_USE_CASE_SOURCE, encoding="utf-8")
    index = build_logic_index(tmp_path)
    finding = next(
        item
        for item in index.discover_findings(())
        if item.metadata.get("sink_kind") == "client_controlled_price_or_total"
    )
    source = read_repository_source(tmp_path, finding.file_path)
    raw = select_raw_context(finding, source)
    sanitized = sanitize_context(
        finding,
        raw,
    )

    result = build_evidence_context(
        finding,
        sanitized,
        logic_index=index,
    )
    payload = json.loads(result.context.sanitized_snippet or "{}")

    assert result.complete is True
    assert payload["logic_analysis"]["logic_class"] == "business_rule_bypass"
    assert "price" in payload["logic_analysis"]["attack_hypothesis"]
    assert all(
        item["satisfied"]
        for item in payload["logic_analysis"]["proof_obligations"]
    )
    resolution = payload["logic_analysis"]["retrieval_resolution"]
    assert resolution["status"] == "resolved_by_bounded_static_retrieval"
    assert resolution["facts"]["caller_price_component_reaches_business_operation"]
    assert payload["deterministic_verification"]["mechanism"] == "logic_pattern"
    assert payload["relevant_code"]["scope_type"] == "PYTHON_FUNCTION"
    assert payload["relevant_code"]["function_name"] == "calculate_cart_total"
    assert payload["source"]["expression"] != "<logic_candidate_source>"
    assert payload["sink"]["expression"] != "<logic_candidate_sink>"
    assert payload["sink"]["dangerous_argument"] != "<logic_sensitive_target>"
    assert payload["taint_path"]["steps"][0]["kind"] == "source"
    assert payload["taint_path"]["steps"][-1]["kind"] == "sink"
    assert payload["retrieval_resolution"] == resolution


def test_prompt_v14_is_specialized_for_exact_focused_evidence() -> None:
    prompt = build_system_message("model", "triage-prompt-v14")

    assert "owner/tenant-scoped" in prompt
    assert "client-controlled cart prices" in prompt
    assert "bounded pagination" in prompt
    assert "proof_obligations_satisfied" in prompt
    assert "source_symbol" in prompt
    assert "privileged_endpoint_without_authorization" in prompt
