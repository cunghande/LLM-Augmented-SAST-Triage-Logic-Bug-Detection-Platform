"""EvidenceLedger: Append-only, verified record of facts gathered by tools."""

from __future__ import annotations

import json
from typing import Any
from sast_triage.analysis.base import QueryResultStatus
from sast_triage.agent.models import LedgerEntry


class EvidenceLedger:
    """Tamper-evident, verified ledger separating factual findings from model reasoning."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._signatures: set[str] = set()

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    @property
    def visited_signatures(self) -> frozenset[str]:
        return frozenset(self._signatures)

    def has_signature(self, signature: str) -> bool:
        return signature in self._signatures

    def add_entry(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        canonical_signature: str,
        query_status: QueryResultStatus,
        status_reason: str,
        summary: str,
        facts: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """Append a new verified entry to the ledger."""
        entry = LedgerEntry(
            entry_id=len(self._entries) + 1,
            tool_name=tool_name,
            parameters=parameters,
            canonical_signature=canonical_signature,
            query_status=query_status,
            status_reason=status_reason,
            summary=summary,
            facts=facts or {},
        )
        self._entries.append(entry)
        self._signatures.add(canonical_signature)
        return entry

    def has_unknowns(self) -> bool:
        """Check if any query returned UNKNOWN."""
        return any(e.query_status == QueryResultStatus.UNKNOWN for e in self._entries)

    def to_prompt_context(self) -> str:
        """Format the evidence ledger into an untrusted data envelope for LLM prompts."""
        if not self._entries:
            return "<UNTRUSTED_EVIDENCE_LEDGER>\n(Ledger is empty - no tool calls executed yet)\n</UNTRUSTED_EVIDENCE_LEDGER>"

        lines = ["<UNTRUSTED_EVIDENCE_LEDGER>"]
        for entry in self._entries:
            lines.append(f"Entry #{entry.entry_id}:")
            lines.append(f"  Tool: {entry.tool_name}")
            lines.append(f"  Parameters: {json.dumps(entry.parameters, sort_keys=True)}")
            lines.append(f"  Status: {entry.query_status.value} ({entry.status_reason})")
            lines.append(f"  Summary: {entry.summary}")
            if entry.facts:
                lines.append(f"  Structured Facts: {json.dumps(entry.facts, sort_keys=True)}")
            lines.append("")
        lines.append("</UNTRUSTED_EVIDENCE_LEDGER>")
        return "\n".join(lines)

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Serialize for reporting."""
        return [entry.model_dump() for entry in self._entries]
