"""LLM Triage package with lazy public exports.

Keeping package import lightweight is required because Modal imports the nested
Qwen app inside its minimal CPU and GPU images. Domain dependencies are loaded
only when a caller actually requests the corresponding CLI symbol.
"""

from importlib import import_module
from typing import Any

_EXPORT_MODULES = {
    "FakeTriageProvider": "sast_triage.triage.fake_provider",
    "FakeTriageProviderMode": "sast_triage.triage.fake_provider",
    "ProviderPrompt": "sast_triage.triage.prompt_builder",
    "RealTriageProvider": "sast_triage.triage.real_provider",
    "SafePromptBuilder": "sast_triage.triage.prompt_builder",
    "build_triage_prompt": "sast_triage.triage.prompt_builder",
    "parse_triage_decision": "sast_triage.triage.output_validator",
}

__all__ = [
    "FakeTriageProvider",
    "FakeTriageProviderMode",
    "ProviderPrompt",
    "RealTriageProvider",
    "SafePromptBuilder",
    "build_triage_prompt",
    "parse_triage_decision",
]


def __getattr__(name: str) -> Any:
    """Load a public triage symbol only when it is requested."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
