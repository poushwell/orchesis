"""Session Forensics - deep dive into session behavior."""

from __future__ import annotations

import threading


class SessionForensics:
    """Deep forensic analysis of session patterns."""

    def __init__(self):
        self._analyses: dict[str, dict] = {}
        self._lock = threading.Lock()

    def analyze(self, session_id: str, events: list[dict]) -> dict:
        """Full forensic analysis of session."""
        if not events:
            return {"error": "No events"}

        token_growth = self._analyze_token_growth(events)
        decision_pattern = self._analyze_decisions(events)
        phase_transitions = self._analyze_phases(events)
        anomalies = self._detect_anomalies(events)
        result = {
            "session_id": session_id,
            "duration_requests": len(events),
            "token_growth": token_growth,
            "decision_pattern": decision_pattern,
            "phase_transitions": phase_transitions,
            "anomalies": anomalies,
            "health_score": self._compute_health(decision_pattern, anomalies),
        }
        with self._lock:
            self._analyses[session_id] = result
        return result

    def _analyze_token_growth(self, events: list[dict]) -> dict:
        tokens = [int(event.get("tokens", 0) or 0) for event in events]
        if not tokens or tokens[0] == 0:
            return {"growth_factor": 1.0, "collapse": False}
        growth = tokens[-1] / max(1, tokens[0])
        return {
            "initial": tokens[0],
            "final": tokens[-1],
            "growth_factor": round(growth, 2),
            "collapse": growth > 3.0,
        }

    def _analyze_decisions(self, events: list[dict]) -> dict:
        decisions = [str(event.get("decision", "ALLOW") or "ALLOW") for event in events]
        total = len(decisions)
        denies = decisions.count("DENY")
        return {
            "total": total,
            "allow": total - denies,
            "deny": denies,
            "deny_rate": round(denies / max(1, total), 4),
        }

    def _analyze_phases(self, events: list[dict]) -> list[str]:
        phases: list[str] = []
        for event in events:
            snapshot = event.get("state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            phase = str(snapshot.get("phase", "LIQUID") or "LIQUID")
            if not phases or phases[-1] != phase:
                phases.append(phase)
        return phases

    def _detect_anomalies(self, events: list[dict]) -> list[str]:
        anomalies: list[str] = []
        tokens = [int(event.get("tokens", 0) or 0) for event in events]
        if tokens and len(tokens) > 1 and tokens[-1] > 3 * max(1, tokens[0]):
            anomalies.append("context_collapse")
        deny_count = sum(1 for event in events if str(event.get("decision", "")) == "DENY")
        if deny_count > len(events) * 0.3:
            anomalies.append("high_deny_rate")
        return anomalies

    def _compute_health(self, decisions: dict, anomalies: list) -> float:
        score = 1.0
        score -= float(decisions.get("deny_rate", 0.0) or 0.0) * 0.5
        score -= len(anomalies) * 0.2
        return round(max(0.0, min(1.0, score)), 4)

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._analyses.get(session_id)
            return dict(row) if isinstance(row, dict) else None

    def get_stats(self) -> dict:
        with self._lock:
            return {"analyses": len(self._analyses)}
