"""Deterministic, bounded evidence expansion orchestration."""

from sast_triage.context.evidence_engine import CoreAnalysisEngine
from sast_triage.context.evidence_models import EvidenceExpansionResult
from sast_triage.context.evidence_tools import EvidenceToolbox
from sast_triage.context.sufficiency import requires_context_expansion


class EvidenceExpansionAgent:
    """Call only tools needed to fill explicit evidence gaps."""

    def __init__(
        self,
        engine: CoreAnalysisEngine,
        *,
        max_tool_calls: int = 5,
        max_depth: int = 5,
    ) -> None:
        """Initialize the system-controlled expansion agent."""
        self._engine = engine
        self._max_depth = max_depth
        self._toolbox = EvidenceToolbox(
            engine,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
        )

    def expand(self) -> EvidenceExpansionResult:
        """Fill declared missing information within the configured budget."""
        evidence = self._engine.build_evidence()
        if not requires_context_expansion(evidence):
            return EvidenceExpansionResult(evidence=evidence, tool_calls=0, tool_names=())

        names: list[str] = []
        overrides: dict[str, bool | None] = {}
        completeness = evidence.context_completeness

        custom_controls = [
            control
            for control in evidence.security_controls
            if control.effective is None
        ]
        for control in custom_controls:
            if self._toolbox.calls_used >= 5:
                break
            self._toolbox.inspect_symbol(control.symbol)
            names.append("inspect_symbol")
            if self._toolbox.calls_used >= 5:
                break
            result = self._toolbox.analyze_security_control(
                control.symbol,
                evidence.sink.sink_type if evidence.sink else "unknown",
            )
            names.append("analyze_security_control")
            overrides[control.symbol] = result.evidence.get("effective")  # type: ignore[assignment]

        missing = set(completeness.missing_information)
        if {"SOURCE_NOT_RESOLVED", "TAINT_PATH_INCOMPLETE"} & missing:
            if self._toolbox.calls_used < 5:
                self._toolbox.trace_taint_path(
                    evidence.finding_id,
                    self._max_depth,
                )
                names.append("trace_taint_path")
            function_id = self._engine.target_function_id()
            if function_id and self._toolbox.calls_used < 5:
                self._toolbox.find_callers(function_id, self._max_depth)
                names.append("find_callers")
            if function_id and self._toolbox.calls_used < 5:
                self._toolbox.find_entrypoint_path(function_id, self._max_depth)
                names.append("find_entrypoint_path")

        expanded = self._engine.build_evidence(
            expand_callers=True,
            control_overrides=overrides,
        )
        return EvidenceExpansionResult(
            evidence=expanded,
            tool_calls=self._toolbox.calls_used,
            tool_names=tuple(names),
        )
