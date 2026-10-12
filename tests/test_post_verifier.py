"""Unit tests for Structured Evidence (C2) and Post-LLM Verifier (C3, C1)."""

import json

from sast_triage.models import (
    EvidenceRole,
    FindingType,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PolicyAction,
    SanitizedContext,
    ScannerType,
    Severity,
    StructuredEvidence,
    TriageDecision,
)
from sast_triage.policy.engine import apply_policy
from sast_triage.triage.post_verifier import verify_post_triage_decision


def _make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id="f-test-12345678",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.flask.security.xss.template",
        file_path="src/views.py",
        start_line=15,
        end_line=15,
        severity=Severity.HIGH,
        message="XSS in template",
    )


def _make_context(finding_id: str = "f-test-12345678") -> SanitizedContext:
    snippet_dict = {
        "finding": {"file_path": "src/views.py"},
        "context_completeness": {"status": "complete"},
        "relevant_code": {
            "code": "def render(request):\n    name = request.args.get('name')\n    return render_template_string(name)\n"
        },
        "source": {"expression": "request.args.get('name')", "file_path": "src/views.py"},
        "sink": {"expression": "render_template_string", "file_path": "src/views.py"},
        "deterministic_verification": {
            "mechanism": "taint_flow",
            "evidence_complete": True,
            "has_evidence_conflict": False,
            "source_user_controlled": True,
            "source_reaches_sink": True,
            "effective_controls": [],
        },
    }
    from sast_triage.models import ContextStrategy, PathCategory, SourceKind

    return SanitizedContext(
        finding_id=finding_id,
        sanitized_snippet=json.dumps(snippet_dict),
        context_strategy=ContextStrategy.PYTHON_FUNCTION,
        context_start_line=1,
        context_end_line=20,
        finding_start_line=15,
        path_category=PathCategory.PRODUCTION,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )


def test_structured_evidence_model_validation() -> None:
    ev = StructuredEvidence(
        file="src/views.py",
        line=15,
        symbol="render_template_string",
        role=EvidenceRole.SINK,
        description="Sink call without escaping",
    )
    assert ev.file == "src/views.py"
    assert ev.role == EvidenceRole.SINK

    decision = TriageDecision(
        structured_evidence=[ev],
        missing_information=[],
        assumptions=[],
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Verified true positive with direct untrusted input into sink.",
        model_version="test-model",
        prompt_version="test-prompt",
    )
    assert len(decision.structured_evidence) == 1
    assert decision.structured_evidence[0].symbol == "render_template_string"


def test_post_verifier_accepts_valid_citations() -> None:
    finding = _make_finding()
    ctx = _make_context()
    decision = TriageDecision(
        structured_evidence=[
            StructuredEvidence(file="src/views.py", line=15, symbol="render_template_string", role=EvidenceRole.SINK),
            StructuredEvidence(file="src/views.py", line=14, symbol="name", role=EvidenceRole.SOURCE),
        ],
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Valid finding.",
        model_version="test-model",
        prompt_version="test-prompt",
    )
    res = verify_post_triage_decision(decision, ctx, finding)
    assert res.is_valid is True
    assert len(res.violations) == 0


def test_post_verifier_rejects_hallucinated_symbol() -> None:
    finding = _make_finding()
    ctx = _make_context()
    decision = TriageDecision(
        structured_evidence=[
            StructuredEvidence(file="src/views.py", line=15, symbol="hallucinated_variable_foo", role=EvidenceRole.SOURCE),
        ],
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Invalid finding with hallucinated symbol.",
        model_version="test-model",
        prompt_version="test-prompt",
    )
    res = verify_post_triage_decision(decision, ctx, finding)
    assert res.is_valid is False
    assert any("hallucinated_variable_foo" in v for v in res.violations)
    assert res.verified_decision.model_verdict == ModelVerdict.NEEDS_REVIEW


def test_post_verifier_rejects_unverified_sanitizer_claim() -> None:
    finding = _make_finding()
    ctx = _make_context()
    decision = TriageDecision(
        structured_evidence=[
            StructuredEvidence(file="src/views.py", line=15, symbol="fake_sanitizer", role=EvidenceRole.GUARD),
        ],
        model_verdict=ModelVerdict.LIKELY_FP,
        model_confidence=ModelConfidence.HIGH,
        summary="Claiming safe due to fake sanitizer.",
        model_version="test-model",
        prompt_version="test-prompt",
    )
    res = verify_post_triage_decision(decision, ctx, finding)
    assert res.is_valid is False
    assert any("fake_sanitizer" in v for v in res.violations)


def test_policy_engine_escalates_on_post_verifier_failure() -> None:
    finding = _make_finding()
    ctx = _make_context()
    decision = TriageDecision(
        structured_evidence=[
            StructuredEvidence(file="src/views.py", line=15, symbol="completely_made_up_token", role=EvidenceRole.SOURCE),
        ],
        model_verdict=ModelVerdict.LIKELY_TP,
        model_confidence=ModelConfidence.HIGH,
        summary="Finding claiming made up token.",
        model_version="test-model",
        prompt_version="test-prompt",
    )
    pol_dec = apply_policy(finding, ctx, decision)
    assert pol_dec.action == PolicyAction.MANUAL_REVIEW
    assert pol_dec.escalated is True
    assert "Post-LLM verifier rejection" in pol_dec.reasons[0]
