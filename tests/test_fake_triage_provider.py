"""Unit tests for FakeTriageProvider."""

import pytest

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ContextStrategy,
    FindingType,
    MissingContextReason,
    ModelConfidence,
    ModelVerdict,
    NormalizedFinding,
    PathCategory,
    SanitizedContext,
    ScannerType,
    Severity,
    SourceKind,
    TriageDecision,
    TriageInput,
)
from sast_triage.triage.fake_provider import (
    FakeTriageProvider,
    FakeTriageProviderMode,
)

CANARY = "TRIAGE_INPUT_CANARY_DO_NOT_COPY"


def make_finding(
    scanner: ScannerType = ScannerType.SEMGREP,
    file_path: str = "src/app.py",
    start_line: int = 1,
    rule_id: str = "rule-01",
    finding_id: str = "find123456789012",
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_instance_id=finding_id,
        scanner=scanner,
        finding_type=FindingType.SAST if scanner == ScannerType.SEMGREP else FindingType.SECRET,
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        severity=Severity.HIGH,
        message="Finding message",
        snippet="snippet",
    )


def make_context(
    finding_id: str = "find123456789012",
    context_available: bool = True,
    sanitized_snippet: str | None = "def fn():\n    pass\n",
) -> SanitizedContext:
    if context_available:
        return SanitizedContext(
            finding_id=finding_id,
            sanitized_snippet=sanitized_snippet,
            context_strategy=ContextStrategy.PYTHON_FUNCTION,
            context_start_line=1,
            context_end_line=5,
            finding_start_line=1,
            finding_end_line=1,
            path_category=PathCategory.UNKNOWN,
            source_kind=SourceKind.WORKTREE,
            context_available=True,
        )
    return SanitizedContext(
        finding_id=finding_id,
        sanitized_snippet=None,
        context_strategy=ContextStrategy.UNAVAILABLE,
        finding_start_line=1,
        finding_end_line=1,
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=False,
        missing_context_reasons=[MissingContextReason.PYTHON_AST_PARSE_FAILED],
    )


def make_triage_input(
    finding: NormalizedFinding | None = None,
    context: SanitizedContext | None = None,
    prompt_type: str = "fake.default",
    prompt_version: str = "v1.0",
) -> TriageInput:
    if finding is None:
        finding = make_finding()
    if context is None:
        context = make_context(finding_id=finding.finding_instance_id)

    return TriageInput(
        finding=finding,
        context=context,
        prompt_version=prompt_version,
        output_schema_version="v1.0",
        prompt_type=prompt_type,
    )


# --- 1. Packaging & Success Behavior ---


def test_triage_input_creation_valid() -> None:

    """Requirement Protected: TriageInput can be created with valid finding and context.

    Expected Result: triage_input is created successfully with matching finding IDs.
    Test Category: Happy Path Packaging
    """
    inp = make_triage_input()
    assert isinstance(inp, TriageInput)
    assert inp.finding.finding_instance_id == inp.context.finding_id


def test_triage_input_mismatched_id_rejected() -> None:

    """Requirement Protected: Mismatch between finding and context ID is rejected by Pydantic model.

    Expected Result: ValueError raised by Pydantic validator.
    Test Category: Contract Invariant
    """
    finding = make_finding(finding_id="id-1")
    context = make_context(finding_id="id-2")

    with pytest.raises(ValueError, match="must match"):
        TriageInput(
            finding=finding,
            context=context,
            prompt_version="v1",
            output_schema_version="v1",
            prompt_type="default",
        )


def test_fake_provider_prompt_type_tp_high() -> None:

    """Requirement Protected: prompt_type 'fake.tp.high' produces LIKELY_TP + HIGH confidence.

    Expected Result: ModelVerdict.LIKELY_TP, ModelConfidence.HIGH.
    Test Category: Happy Path Signal
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.tp.high")

    dec = provider.triage(inp)

    assert isinstance(dec, TriageDecision)
    assert dec.model_verdict == ModelVerdict.LIKELY_TP
    assert dec.model_confidence == ModelConfidence.HIGH
    assert dec.prompt_version == inp.prompt_version
    assert dec.model_version == "fake-triage-v1"


def test_fake_provider_prompt_type_fp_high() -> None:

    """Requirement Protected: prompt_type 'fake.fp.high' produces LIKELY_FP + HIGH confidence.

    Expected Result: ModelVerdict.LIKELY_FP, ModelConfidence.HIGH.
    Test Category: Happy Path Signal
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.fp.high")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.LIKELY_FP
    assert dec.model_confidence == ModelConfidence.HIGH


def test_fake_provider_prompt_type_review_low() -> None:

    """Requirement Protected: prompt_type 'fake.review.low' produces NEEDS_REVIEW + LOW confidence.

    Expected Result: ModelVerdict.NEEDS_REVIEW, ModelConfidence.LOW.
    Test Category: Happy Path Signal
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.review.low")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.NEEDS_REVIEW
    assert dec.model_confidence == ModelConfidence.LOW


def test_fake_provider_prompt_type_default() -> None:

    """Requirement Protected: Unknown/default prompt_type produces NEEDS_REVIEW + MEDIUM confidence.

    Expected Result: ModelVerdict.NEEDS_REVIEW, ModelConfidence.MEDIUM.
    Test Category: Fallback Signal
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="custom.unknown.type")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.NEEDS_REVIEW
    assert dec.model_confidence == ModelConfidence.MEDIUM


# --- 2. Precedence Rules ---


def test_precedence_context_unavailable_overrides_tp_signal() -> None:

    """Requirement Protected: Unavailable context MUST override prompt_type 'fake.tp.high' to NEEDS_REVIEW + LOW.

    Expected Result: ModelVerdict.NEEDS_REVIEW, ModelConfidence.LOW.
    Test Category: Precedence Constraint
    """
    provider = FakeTriageProvider()
    finding = make_finding()
    ctx = make_context(finding_id=finding.finding_instance_id, context_available=False)
    inp = make_triage_input(finding=finding, context=ctx, prompt_type="fake.tp.high")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.NEEDS_REVIEW
    assert dec.model_confidence == ModelConfidence.LOW
    assert "unavailable" in dec.evidence[0].lower()


def test_precedence_context_unavailable_overrides_fp_signal() -> None:

    """Requirement Protected: Unavailable context MUST override prompt_type 'fake.fp.high' to NEEDS_REVIEW + LOW.

    Expected Result: ModelVerdict.NEEDS_REVIEW, ModelConfidence.LOW.
    Test Category: Precedence Constraint
    """
    provider = FakeTriageProvider()
    finding = make_finding()
    ctx = make_context(finding_id=finding.finding_instance_id, context_available=False)
    inp = make_triage_input(finding=finding, context=ctx, prompt_type="fake.fp.high")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.NEEDS_REVIEW
    assert dec.model_confidence == ModelConfidence.LOW


def test_precedence_timeout_mode_overrides_unavailable_context() -> None:

    """Requirement Protected: Timeout mode takes precedence over unavailable context and raises error immediately.

    Expected Result: SastTriageError with TRIAGE_PROVIDER_TIMEOUT raised.
    Test Category: Precedence Constraint
    """
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_TIMEOUT)
    finding = make_finding()
    ctx = make_context(finding_id=finding.finding_instance_id, context_available=False)
    inp = make_triage_input(finding=finding, context=ctx, prompt_type="fake.tp.high")

    with pytest.raises(SastTriageError) as exc:
        provider.triage(inp)

    assert exc.value.error_code == "TRIAGE_PROVIDER_TIMEOUT"
    assert exc.value.retryable is True


# --- 3. Failure Simulation ---


def test_failure_simulation_raise_timeout() -> None:

    """Requirement Protected: Mode RAISE_TIMEOUT raises safe SastTriageError with retryable=True.

    Expected Result: SastTriageError raised, error_code == TRIAGE_PROVIDER_TIMEOUT.
    Test Category: Failure Simulation
    """
    provider = FakeTriageProvider(mode="raise_timeout")
    inp = make_triage_input()

    with pytest.raises(SastTriageError) as exc:
        provider.triage(inp)

    assert exc.value.error_code == "TRIAGE_PROVIDER_TIMEOUT"
    assert exc.value.retryable is True


def test_failure_simulation_raise_provider_error() -> None:

    """Requirement Protected: Mode RAISE_PROVIDER_ERROR raises safe SastTriageError with retryable=False.

    Expected Result: SastTriageError raised, error_code == TRIAGE_PROVIDER_ERROR.
    Test Category: Failure Simulation
    """
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_PROVIDER_ERROR)
    inp = make_triage_input()

    with pytest.raises(SastTriageError) as exc:
        provider.triage(inp)

    assert exc.value.error_code == "TRIAGE_PROVIDER_ERROR"
    assert exc.value.retryable is False


def test_reject_invalid_provider_mode() -> None:

    """Requirement Protected: Invalid mode parameter passed to FakeTriageProvider constructor is rejected.

    Expected Result: SastTriageError raised, error_code == TRIAGE_INVALID_PROVIDER_MODE.
    Test Category: Constructor Validation
    """
    with pytest.raises(SastTriageError) as exc:
        FakeTriageProvider(mode="invalid_mode")
    assert exc.value.error_code == "TRIAGE_INVALID_PROVIDER_MODE"


# --- 4. No Rule Heuristic Verification ---


def test_no_rule_heuristic_different_rules_same_prompt_type() -> None:

    """Requirement Protected: Different finding.rule_id values produce identical decision if prompt_type is the same.

    Expected Result: Identical verdict and confidence regardless of rule_id.
    Test Category: Anti-Heuristic Verification
    """
    provider = FakeTriageProvider()

    f1 = make_finding(rule_id="eval-use")
    f2 = make_finding(rule_id="sqli-injection")

    inp1 = make_triage_input(finding=f1, prompt_type="fake.tp.high")
    inp2 = make_triage_input(finding=f2, prompt_type="fake.tp.high")

    dec1 = provider.triage(inp1)
    dec2 = provider.triage(inp2)

    assert dec1.model_verdict == dec2.model_verdict == ModelVerdict.LIKELY_TP
    assert dec1.model_confidence == dec2.model_confidence == ModelConfidence.HIGH


def test_no_rule_heuristic_rule_id_fake_tp_ignored() -> None:

    """Requirement Protected: rule_id='fake.tp.high' is IGNORED if prompt_type is 'fake.default'.

    Expected Result: ModelVerdict.NEEDS_REVIEW (does NOT return LIKELY_TP).
    Test Category: Anti-Heuristic Verification
    """
    provider = FakeTriageProvider()

    finding = make_finding(rule_id="fake.tp.high")
    inp = make_triage_input(finding=finding, prompt_type="fake.default")

    dec = provider.triage(inp)

    assert dec.model_verdict == ModelVerdict.NEEDS_REVIEW
    assert dec.model_confidence == ModelConfidence.MEDIUM


# --- 5. Security & Canary Non-Leakage ---


def test_canary_in_snippet_not_copied_to_decision() -> None:

    """Requirement Protected: Secret canary in context.sanitized_snippet is NEVER copied into TriageDecision fields or JSON.

    Expected Result: CANARY absent from summary, evidence, missing_info, assumptions, repr, model_dump_json.
    Test Category: Security Boundary
    """
    provider = FakeTriageProvider()
    finding = make_finding()
    ctx = make_context(finding_id=finding.finding_instance_id, sanitized_snippet=f"password = '{CANARY}'\n")
    inp = make_triage_input(finding=finding, context=ctx, prompt_type="fake.tp.high")

    dec = provider.triage(inp)

    assert CANARY not in dec.summary
    assert not any(CANARY in e for e in dec.evidence)
    assert not any(CANARY in m for m in dec.missing_information)
    assert not any(CANARY in a for a in dec.assumptions)
    assert CANARY not in repr(dec)
    assert CANARY not in str(dec.model_dump())
    assert CANARY not in dec.model_dump_json()


def test_canary_in_imports_decorators_not_copied() -> None:

    """Requirement Protected: Secret canary in imports/decorators is NEVER copied into TriageDecision.

    Expected Result: CANARY absent from decision output.
    Test Category: Security Boundary
    """
    provider = FakeTriageProvider()
    finding = make_finding()
    ctx = SanitizedContext(
        finding_id=finding.finding_instance_id,
        sanitized_snippet="def fn(): pass\n",
        context_strategy=ContextStrategy.PYTHON_FUNCTION,
        context_start_line=1,
        context_end_line=5,
        finding_start_line=1,
        finding_end_line=1,
        limited_imports=[f"import os  # {CANARY}"],
        limited_decorators=[f"@{CANARY}"],
        path_category=PathCategory.UNKNOWN,
        source_kind=SourceKind.WORKTREE,
        context_available=True,
    )
    inp = make_triage_input(finding=finding, context=ctx, prompt_type="fake.fp.high")

    dec = provider.triage(inp)
    assert CANARY not in dec.model_dump_json()


def test_exception_safe_message_does_not_contain_canary() -> None:

    """Requirement Protected: Exception raised during failure mode does NOT leak input canary or payload.

    Expected Result: CANARY absent from safe_message, str(exc), and repr(exc).
    Test Category: Security Exception Safety
    """
    provider = FakeTriageProvider(mode=FakeTriageProviderMode.RAISE_TIMEOUT)
    finding = make_finding()
    ctx = make_context(finding_id=finding.finding_instance_id, sanitized_snippet=f"pass = '{CANARY}'\n")
    inp = make_triage_input(finding=finding, context=ctx)

    with pytest.raises(SastTriageError) as exc:
        provider.triage(inp)

    assert CANARY not in exc.value.safe_message
    assert CANARY not in str(exc.value)
    assert CANARY not in repr(exc.value)


def test_provider_accepts_only_triage_input() -> None:

    """Requirement Protected: FakeTriageProvider.triage() rejects inputs that are not TriageInput instances.

    Expected Result: SastTriageError raised with error_code TRIAGE_INVALID_INPUT.
    Test Category: API Input Validation
    """
    provider = FakeTriageProvider()

    with pytest.raises(SastTriageError) as exc:
        provider.triage("invalid_string_input")  # type: ignore[arg-type]

    assert exc.value.error_code == "TRIAGE_INVALID_INPUT"


# --- 6. Determinism & Immutability ---


def test_determinism_same_input_same_output() -> None:

    """Requirement Protected: Calling triage() twice with identical input produces equal TriageDecision models.

    Expected Result: dec1 == dec2.
    Test Category: Determinism
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.tp.high")

    dec1 = provider.triage(inp)
    dec2 = provider.triage(inp)

    assert dec1 == dec2
    assert dec1.model_dump() == dec2.model_dump()


def test_no_dynamic_values_in_decision() -> None:

    """Requirement Protected: TriageDecision output does not contain random IDs, timestamps, or dynamic environment values.

    Expected Result: Pure deterministic fields.
    Test Category: Determinism
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.fp.high")

    dec = provider.triage(inp)
    dump_json = dec.model_dump_json()

    assert "datetime" not in dump_json
    assert "timestamp" not in dump_json


def test_input_models_not_mutated() -> None:

    """Requirement Protected: FakeTriageProvider.triage() does NOT mutate input TriageInput, finding, or context.

    Expected Result: Fields of input models remain unchanged.
    Test Category: Immutability
    """
    provider = FakeTriageProvider()
    inp = make_triage_input(prompt_type="fake.tp.high")

    orig_rule = inp.finding.rule_id
    orig_prompt = inp.prompt_type

    provider.triage(inp)

    assert inp.finding.rule_id == orig_rule
    assert inp.prompt_type == orig_prompt
