"""Canonicalize phase.

Applies the byte-deterministic canonical form generator
(`orchesis.canonical`) to the current request. The bytes + section offsets
are parked on `ctx.processed.params` so the upstream phase + its provider
adapter can use them as a cache-key surface.
"""

from __future__ import annotations

from typing import Any

from orchesis.canonical import CanonicalError, canonicalize_with_offsets
from orchesis.pipeline import Phase, PhaseResult, RequestContext


class CanonicalizePhase(Phase):
    """Build the canonical-form bytes for the current request body.

    Reads:    `ctx.input.original_messages`, `ctx.input.original_tools`,
              `ctx.input.raw_body` (size hint only).
    Writes:   `ctx.processed.params["canonical_bytes"]`,
              `ctx.processed.params["section_offsets"]`,
              `ctx.processed.messages_canonicalized = True`.
    Sets metric `bytes_out`.
    """

    name = "canonicalize"
    version = "0.1.0"
    appends_tracking = frozenset({"metrics"})
    timeout_seconds = 0.5

    async def execute(self, ctx: RequestContext) -> PhaseResult:
        if ctx.processed.messages_canonicalized:
            return PhaseResult(status="skip", reason="already canonicalized")
        messages = ctx.processed.messages or list(ctx.input.original_messages)
        tools = ctx.processed.tools or list(ctx.input.original_tools)
        system_text = self._extract_system(messages)
        non_system_messages = [m for m in messages if m.get("role") != "system"]
        size_hint = max(1, len(ctx.input.raw_body) or 1)
        try:
            out, offsets = canonicalize_with_offsets(
                system=system_text,
                tools=tools,
                documents=None,
                messages=non_system_messages,
                input_size_hint=size_hint,
            )
        except CanonicalError as e:
            return PhaseResult(
                status="block",
                reason=f"canonicalization failed: {e}",
            )
        ctx.processed.params["canonical_bytes"] = out
        ctx.processed.params["section_offsets"] = offsets
        ctx.processed.messages_canonicalized = True
        return PhaseResult(
            status="pass",
            details={"bytes_out": len(out), "sections": list(offsets.keys())},
        )

    @staticmethod
    def _extract_system(messages: list[Any]) -> str | None:
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for piece in content:
                        if isinstance(piece, dict) and piece.get("type") == "text":
                            parts.append(str(piece.get("text", "")))
        if not parts:
            return None
        return "\n".join(parts)
