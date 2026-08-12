"""Build safe provider prompts from the public ``TriageInput`` contract."""

from dataclasses import dataclass
from typing import Any

from sast_triage.models import TriageInput
from sast_triage.triage.system_prompt import build_system_message


@dataclass(frozen=True)
class ProviderPrompt:
    """Immutable system/user message pair sent to a triage provider."""

    system_message: str
    user_message: str
    prompt_version: str
    output_schema_version: str


def _display_value(value: Any) -> str:
    """Render metadata deterministically without exposing Python object reprs."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(_display_value(item) for item in value)
    return str(value)


def _build_user_message(triage_input: TriageInput) -> str:
    """Build the delimited untrusted-data payload for one finding."""
    finding = triage_input.finding
    context = triage_input.context
    metadata = ", ".join(
        f"{key}={_display_value(value)}"
        for key, value in sorted(finding.metadata.items())
    )
    context_text = (
        context.sanitized_snippet
        if context.context_available
        else "<CONTEXT_UNAVAILABLE>"
    )
    return "\n".join(
        [
            f"Prompt version: {triage_input.prompt_version}",
            f"Output schema version: {triage_input.output_schema_version}",
            "<ANALYSIS_TARGET>",
            "Chỉ đánh giá đúng scanner rule và cơ chế lỗ hổng được chỉ định dưới đây.",
            f"target_rule_id={finding.rule_id}",
            f"target_rule_message={finding.message}",
            f"target_metadata={metadata}",
            "</ANALYSIS_TARGET>",
            "<FINDING>",
            f"scanner={finding.scanner.value}",
            f"finding_type={finding.finding_type.value}",
            f"rule_id={finding.rule_id}",
            f"rule_name={_display_value(finding.rule_name)}",
            f"relative_file_path={finding.file_path}",
            f"line_range={finding.start_line}-{_display_value(finding.end_line)}",
            f"severity={finding.severity.value}",
            f"message={finding.message}",
            f"metadata={metadata}",
            "</FINDING>",
            "<SANITIZED_CONTEXT_UNTRUSTED>",
            f"strategy={context.context_strategy.value}",
            f"available={context.context_available}",
            f"truncated={context.truncated}",
            f"path_category={context.path_category.value}",
            f"context={context_text}",
            "</SANITIZED_CONTEXT_UNTRUSTED>",
        ]
    )


def build_triage_prompt(
    triage_input: TriageInput,
    *,
    model_version: str = "unknown",
) -> ProviderPrompt:
    """Build a deterministic prompt using sanitized context only."""
    if not isinstance(triage_input, TriageInput):
        raise TypeError("triage_input must be a TriageInput instance")
    if not model_version or not model_version.strip():
        raise ValueError("model_version must not be empty")

    return ProviderPrompt(
        system_message=build_system_message(
            model_version,
            triage_input.prompt_version,
        ),
        user_message=_build_user_message(triage_input),
        prompt_version=triage_input.prompt_version,
        output_schema_version=triage_input.output_schema_version,
    )


class SafePromptBuilder:
    """Stateless compatibility wrapper around :func:`build_triage_prompt`."""

    def build(
        self,
        triage_input: TriageInput,
        *,
        model_version: str = "unknown",
    ) -> ProviderPrompt:
        """Build the safe provider prompt for one triage input."""
        return build_triage_prompt(triage_input, model_version=model_version)
