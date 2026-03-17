"""Session replay utilities for debugging policy behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from orchesis.engine import evaluate
from orchesis.replay import read_events_from_jsonl
from orchesis.state import RateLimitTracker


@dataclass
class ReplayResult:
    session_id: str
    original_decisions: list[dict[str, Any]]
    replayed_decisions: list[dict[str, Any]]
    differences: list[dict[str, Any]]
    summary: dict[str, int]


class SessionReplay:
    """Replays recorded sessions for debugging and testing."""

    def __init__(self, decisions_log_path: str):
        self.log_path = decisions_log_path

    def load_session(self, session_id: str) -> list[dict]:
        """Load all decisions for a session."""
        sid = str(session_id or "")
        out: list[dict[str, Any]] = []
        for event in read_events_from_jsonl(self.log_path):
            state_snapshot = event.state_snapshot if isinstance(event.state_snapshot, dict) else {}
            if str(state_snapshot.get("session_id", "")) != sid:
                continue
            out.append(
                {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "agent_id": event.agent_id,
                    "tool": event.tool,
                    "cost": float(event.cost),
                    "decision": event.decision,
                    "reasons": list(event.reasons),
                    "state_snapshot": dict(state_snapshot),
                }
            )
        return out

    def diff(self, original: list, replayed: list) -> list[dict]:
        """Return list of decision differences."""
        diffs: list[dict[str, Any]] = []
        max_len = max(len(original), len(replayed))
        for index in range(max_len):
            o = original[index] if index < len(original) else {}
            r = replayed[index] if index < len(replayed) else {}
            o_dec = str(o.get("decision", ""))
            r_dec = str(r.get("decision", ""))
            if o_dec != r_dec or list(o.get("reasons", [])) != list(r.get("reasons", [])):
                diffs.append(
                    {
                        "index": index,
                        "event_id": o.get("event_id") or r.get("event_id"),
                        "original_decision": o_dec,
                        "replayed_decision": r_dec,
                        "original_reasons": list(o.get("reasons", [])),
                        "replayed_reasons": list(r.get("reasons", [])),
                    }
                )
        return diffs

    def replay(self, session_id: str, policy: dict | None = None) -> ReplayResult:
        """Re-evaluate session against current (or provided) policy."""
        sid = str(session_id or "")
        selected_policy = policy if isinstance(policy, dict) else {"rules": []}
        original = self.load_session(sid)
        replayed: list[dict[str, Any]] = []
        for item in original:
            req = {
                "tool": item.get("tool", ""),
                "cost": float(item.get("cost", 0.0) or 0.0),
                "params": {},
                "context": {
                    "agent": item.get("agent_id", "__global__"),
                    "session_id": sid,
                },
            }
            decision = evaluate(req, selected_policy, state=RateLimitTracker(persist_path=None))
            replayed.append(
                {
                    "event_id": item.get("event_id"),
                    "decision": "ALLOW" if decision.allowed else "DENY",
                    "reasons": list(decision.reasons),
                }
            )
        differences = self.diff(original, replayed)
        newly_blocked = sum(
            1
            for row in differences
            if row.get("original_decision") == "ALLOW" and row.get("replayed_decision") == "DENY"
        )
        newly_allowed = sum(
            1
            for row in differences
            if row.get("original_decision") == "DENY" and row.get("replayed_decision") == "ALLOW"
        )
        return ReplayResult(
            session_id=sid,
            original_decisions=original,
            replayed_decisions=replayed,
            differences=differences,
            summary={
                "total": len(original),
                "changed": len(differences),
                "newly_blocked": newly_blocked,
                "newly_allowed": newly_allowed,
            },
        )

