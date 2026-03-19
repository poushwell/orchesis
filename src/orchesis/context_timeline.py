"""Context Timeline - chronological context evolution tracker."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any


class ContextTimeline:
    """Tracks context evolution over session lifetime."""

    def __init__(self):
        self._timelines: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def record(self, session_id: str, snapshot: dict[str, Any]) -> None:
        sid = str(session_id or "").strip() or "__default__"
        payload = dict(snapshot) if isinstance(snapshot, dict) else {}
        with self._lock:
            if sid not in self._timelines:
                self._timelines[sid] = []
            self._timelines[sid].append(
                {
                    **payload,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "seq": len(self._timelines[sid]),
                }
            )
            if len(self._timelines[sid]) > 1000:
                self._timelines[sid] = self._timelines[sid][-1000:]

    def get_timeline(self, session_id: str) -> list[dict[str, Any]]:
        sid = str(session_id or "").strip() or "__default__"
        with self._lock:
            return list(self._timelines.get(sid, []))

    def get_phase_transitions(self, session_id: str) -> list[dict[str, Any]]:
        timeline = self.get_timeline(session_id)
        transitions: list[dict[str, Any]] = []
        prev_phase: str | None = None
        for point in timeline:
            phase = str(point.get("phase", "LIQUID") or "LIQUID")
            if phase != prev_phase:
                transitions.append(
                    {
                        "seq": int(point.get("seq", 0)),
                        "timestamp": point.get("timestamp"),
                        "from": prev_phase,
                        "to": phase,
                        "psi": point.get("psi", 0.5),
                    }
                )
                prev_phase = phase
        return transitions

    def get_collapse_events(self, session_id: str) -> list[dict[str, Any]]:
        timeline = self.get_timeline(session_id)
        return [point for point in timeline if point.get("slope_alert") or point.get("context_collapse")]

    def summarize(self, session_id: str) -> dict[str, Any]:
        sid = str(session_id or "").strip() or "__default__"
        timeline = self.get_timeline(sid)
        if not timeline:
            return {"session_id": sid, "points": 0}
        phases = [str(point.get("phase", "LIQUID") or "LIQUID") for point in timeline]
        psi_values = [float(point.get("psi", 0.5) or 0.5) for point in timeline]
        return {
            "session_id": sid,
            "points": len(timeline),
            "duration_requests": len(timeline),
            "phase_distribution": {phase: phases.count(phase) for phase in set(phases)},
            "avg_psi": round(sum(psi_values) / float(len(psi_values)), 4),
            "collapse_events": len(self.get_collapse_events(sid)),
            "phase_transitions": len(self.get_phase_transitions(sid)),
        }

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {"sessions_tracked": len(self._timelines)}
