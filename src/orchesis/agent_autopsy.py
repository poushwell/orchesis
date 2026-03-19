"""Agent Autopsy - post-mortem analysis of failed agent sessions.

Viral MVP: "What killed your AI agent?"
One command -> full diagnosis of what went wrong.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone


class AgentAutopsy:
    """Post-mortem analysis of agent session failures."""

    FAILURE_MODES = {
        "context_collapse": "Token growth exceeded 3x baseline",
        "loop_detected": "Repeated identical requests",
        "budget_exhausted": "Daily budget exceeded",
        "security_block": "Request blocked by security pipeline",
        "context_poison": "Harmful context detected by apoptosis",
        "crystal_stale": "Context crystallized with outdated information",
        "coherence_loss": "IACS score dropped below threshold",
        "latency_spike": "Response latency anomaly detected",
    }

    def __init__(self):
        self._autopsies: dict[str, dict] = {}
        self._lock = threading.Lock()

    def perform(self, session_id: str, decisions_log: list[dict]) -> dict:
        """Perform full autopsy on session."""
        session_events = [row for row in decisions_log if str(row.get("session_id", "")) == session_id]
        if not session_events:
            return {"error": f"No events found for session: {session_id}"}

        cause_of_death = self._determine_cause(session_events)
        autopsy = {
            "autopsy_id": f"autopsy-{session_id[:8]}",
            "session_id": session_id,
            "performed_at": datetime.now(timezone.utc).isoformat(),
            "cause_of_death": cause_of_death,
            "contributing_factors": self._find_contributing_factors(session_events),
            "timeline": self._build_timeline(session_events),
            "vital_signs": self._extract_vital_signs(session_events),
            "recommendations": self._generate_recommendations(cause_of_death),
            "severity": self._score_severity(cause_of_death),
            "preventable": cause_of_death in {"loop_detected", "budget_exhausted"},
        }
        with self._lock:
            self._autopsies[session_id] = autopsy
        return autopsy

    def _determine_cause(self, events: list[dict]) -> str:
        """Determine primary cause of session failure."""
        for event in reversed(events):
            reasons = event.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            decision = str(event.get("decision", "") or "")
            if decision == "DENY":
                lower = [str(item).lower() for item in reasons]
                if any("loop" in item for item in lower):
                    return "loop_detected"
                if any("budget" in item for item in lower):
                    return "budget_exhausted"
                if any("inject" in item or "prompt" in item for item in lower):
                    return "security_block"

            state = event.get("state_snapshot", {})
            if not isinstance(state, dict):
                state = {}
            if bool(state.get("context_collapse")):
                return "context_collapse"
            if bool(state.get("stale_crystal")):
                return "crystal_stale"
        return "unknown"

    def _find_contributing_factors(self, events: list[dict]) -> list[str]:
        factors: list[str] = []
        for event in events:
            state = event.get("state_snapshot", {})
            if not isinstance(state, dict):
                state = {}
            if float(state.get("psi", 0.0) or 0.0) > 0.85:
                factors.append("high_crystallinity")
            if bool(state.get("slope_alert")):
                factors.append("cqs_declining")
            if int(event.get("tokens", 0) or 0) > 10000:
                factors.append("high_token_usage")
        return sorted(set(factors))

    def _build_timeline(self, events: list[dict]) -> list[dict]:
        return [
            {
                "timestamp": event.get("timestamp", ""),
                "decision": event.get("decision", ""),
                "tokens": int(event.get("tokens", 0) or 0),
                "phase": (
                    event.get("state_snapshot", {}).get("phase", "unknown")
                    if isinstance(event.get("state_snapshot"), dict)
                    else "unknown"
                ),
            }
            for event in events[-10:]
        ]

    def _extract_vital_signs(self, events: list[dict]) -> dict:
        if not events:
            return {}
        tokens = [int(event.get("tokens", 0) or 0) for event in events]
        return {
            "total_requests": len(events),
            "peak_tokens": max(tokens) if tokens else 0,
            "final_tokens": tokens[-1] if tokens else 0,
            "deny_count": sum(1 for event in events if str(event.get("decision", "")) == "DENY"),
        }

    def _generate_recommendations(self, cause: str) -> list[str]:
        recommendations = {
            "context_collapse": [
                "Enable context_budget with L0/L1/L2 thresholds",
                "Use UCI compression to prevent token growth",
            ],
            "loop_detected": [
                "Lower loop_detection.block_threshold",
                "Add task diversity to agent prompts",
            ],
            "budget_exhausted": [
                "Increase daily budget or add per-agent limits",
                "Enable semantic cache to reduce token usage",
            ],
            "security_block": [
                "Review agent prompt for injection patterns",
                "Check tool permissions and scope",
            ],
        }
        return recommendations.get(cause, ["Review session logs for anomalies"])

    def _score_severity(self, cause: str) -> str:
        critical = {"security_block", "context_poison"}
        high = {"context_collapse", "loop_detected"}
        if cause in critical:
            return "critical"
        if cause in high:
            return "high"
        return "medium"

    def get_stats(self) -> dict:
        with self._lock:
            causes: dict[str, int] = {}
            for row in self._autopsies.values():
                cause = str(row.get("cause_of_death", "unknown") or "unknown")
                causes[cause] = causes.get(cause, 0) + 1
            return {
                "autopsies_performed": len(self._autopsies),
                "causes": causes,
            }

    def list_recent(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = list(self._autopsies.values())
        rows.sort(key=lambda item: str(item.get("performed_at", "")), reverse=True)
        return rows[: max(1, int(limit))]

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._autopsies.get(session_id)
            return dict(row) if isinstance(row, dict) else None
