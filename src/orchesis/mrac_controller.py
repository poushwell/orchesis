"""MRAC - Model Reference Adaptive Control for context management.

H37: Adaptive gain scheduling per agent.
Reference model: ideal context quality trajectory.
"""

from __future__ import annotations

import math
import threading
from typing import Any


class MRACController:
    """Model Reference Adaptive Control."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.gamma = float(cfg.get("gamma", 0.1))
        self.ref_decay = float(cfg.get("ref_decay", 0.95))
        self._agents: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register_agent(self, agent_id: str) -> dict:
        """Initialize MRAC state for agent."""
        aid = str(agent_id or "").strip()
        if not aid:
            aid = "unknown"
        with self._lock:
            self._agents[aid] = {
                "gain_compression": 1.0,
                "gain_injection": 1.0,
                "ref_state": 1.0,
                "tracking_error": 0.0,
                "adaptations": 0,
            }
            return dict(self._agents[aid])

    def update(self, agent_id: str, actual_cqs: float) -> dict:
        """MRAC update step. Returns new gains."""
        aid = str(agent_id or "").strip()
        if not aid:
            aid = "unknown"
        with self._lock:
            if aid not in self._agents:
                self._agents[aid] = {
                    "gain_compression": 1.0,
                    "gain_injection": 1.0,
                    "ref_state": 1.0,
                    "tracking_error": 0.0,
                    "adaptations": 0,
                }
            state = self._agents[aid]
            ref = float(state["ref_state"])
            cqs = float(actual_cqs)
            error = cqs - ref

            delta = self.gamma * error * ref
            state["gain_compression"] = max(0.1, min(3.0, float(state["gain_compression"]) + delta))
            state["gain_injection"] = max(0.1, min(3.0, float(state["gain_injection"]) - delta))

            state["ref_state"] = float(state["ref_state"]) * self.ref_decay + (1.0 - self.ref_decay)
            state["tracking_error"] = math.fabs(error)
            state["adaptations"] = int(state.get("adaptations", 0)) + 1

            return {
                "agent_id": aid,
                "gain_compression": round(float(state["gain_compression"]), 4),
                "gain_injection": round(float(state["gain_injection"]), 4),
                "tracking_error": round(float(error), 4),
                "ref_state": round(float(state["ref_state"]), 4),
            }

    def get_gains(self, agent_id: str) -> dict:
        aid = str(agent_id or "").strip()
        with self._lock:
            if aid not in self._agents:
                return {"gain_compression": 1.0, "gain_injection": 1.0}
            return {
                key: value
                for key, value in self._agents[aid].items()
                if key.startswith("gain_")
            }

    def get_all_agents(self) -> list[dict]:
        with self._lock:
            return [{"agent_id": aid, **dict(state)} for aid, state in self._agents.items()]

    def get_stats(self) -> dict:
        with self._lock:
            if not self._agents:
                return {"agents": 0}
            errors = [float(item.get("tracking_error", 0.0)) for item in self._agents.values()]
            return {
                "agents": len(self._agents),
                "avg_tracking_error": round(sum(errors) / len(errors), 4),
                "gamma": self.gamma,
            }
