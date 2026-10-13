"""Domain models for Controlled Triage Agent subsystem."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from sast_triage.analysis.base import QueryResultStatus


class AgentMode(str, Enum):
    """Execution mode for Controlled Triage Agent."""

    OFF = "off"            # Only run Tier-1 Bounded Evidence Collector + single-turn LLM
    ESCALATE = "escalate"  # Escalate to agent loop only if incomplete, UNKNOWN, or NEEDS_EVIDENCE
    ALWAYS = "always"      # Always run agent loop


class AgentAction(BaseModel):
    """An action proposed by the LLM Planner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(description="Allowlisted tool name or 'DONE'")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")


class ActionValidationResult(BaseModel):
    """Outcome of validating an LLM-proposed action against security & schema boundaries."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_valid: bool
    error_code: str | None = None
    error_message: str | None = None
    canonical_signature: str | None = None


class LedgerEntry(BaseModel):
    """Immutable factual entry in the agent evidence ledger."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: int
    tool_name: str
    parameters: dict[str, Any]
    canonical_signature: str
    query_status: QueryResultStatus
    status_reason: str
    summary: str
    facts: dict[str, Any] = Field(default_factory=dict)


class AgentTraceEntry(BaseModel):
    """Trace record for auditing and reproducing agent execution steps."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int
    action: AgentAction
    is_valid: bool
    status: str
    summary: str
    stop_reason: str | None = None


class PlannerOutput(BaseModel):
    """Structured response from the LLM Planner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    thought: str = Field(description="Concise rationale for the chosen action or decision to conclude")
    action: AgentAction = Field(description="Next tool call or tool='DONE'")
