"""Agent lifecycle state management."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


class AgentLifecycleManager:
    """Manages agent lifecycle: spawn, monitor, retire."""

    STATES = ["initializing", "active", "idle", "degraded", "retired", "banned"]

    TRANSITIONS = {
        "initializing": ["active"],
        "active": ["idle", "degraded", "retired"],
        "idle": ["active", "retired"],
        "degraded": ["active", "retired", "banned"],
        "retired": [],
        "banned": [],
    }

    def __init__(self):
        self._agents: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _snapshot(self, agent_id: str, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_id": str(agent_id),
            "state": str(row.get("state", "initializing")),
            "since": str(row.get("since", "")),
            "transitions_history": deepcopy(row.get("transitions_history", [])),
            "metadata": deepcopy(row.get("metadata", {})),
        }

    def register(self, agent_id: str, metadata: dict | None = None) -> dict:
        """Register new agent in initializing state."""
        key = str(agent_id or "").strip()
        if not key:
            raise ValueError("agent_id is required")
        if key in self._agents:
            return self.get_state(key)
        now = self._now_iso()
        self._agents[key] = {
            "state": "initializing",
            "since": now,
            "transitions_history": [{"from": None, "to": "initializing", "reason": "register", "at": now}],
            "metadata": deepcopy(metadata) if isinstance(metadata, dict) else {},
        }
        return self.get_state(key)

    def transition(self, agent_id: str, new_state: str, reason: str = "") -> bool:
        """Transition agent to new state. Validates allowed transitions."""
        key = str(agent_id or "").strip()
        target = str(new_state or "").strip()
        if key not in self._agents or target not in self.STATES:
            return False
        current = str(self._agents[key].get("state", "initializing"))
        if target == current:
            return True
        allowed = self.TRANSITIONS.get(current, [])
        if target not in allowed:
            return False
        now = self._now_iso()
        self._agents[key]["state"] = target
        self._agents[key]["since"] = now
        history = self._agents[key].setdefault("transitions_history", [])
        if isinstance(history, list):
            history.append({"from": current, "to": target, "reason": str(reason or ""), "at": now})
        return True

    def auto_transition(self, agent_id: str, metrics: dict) -> str | None:
        """Auto-transition based on metrics (e.g. high error rate -> degraded)."""
        key = str(agent_id or "").strip()
        if key not in self._agents or not isinstance(metrics, dict):
            return None
        current = str(self._agents[key].get("state", "initializing"))
        error_rate = float(metrics.get("error_rate", 0.0) or 0.0)
        request_rate = float(metrics.get("request_rate", metrics.get("rps", 0.0)) or 0.0)
        if current in {"active", "idle"} and error_rate >= 0.2 and self.transition(key, "degraded", "auto:error_rate"):
            return "degraded"
        if current == "degraded" and error_rate <= 0.05 and self.transition(key, "active", "auto:recovered"):
            return "active"
        if current == "active" and request_rate <= 0.0 and self.transition(key, "idle", "auto:idle"):
            return "idle"
        if current == "idle" and request_rate > 0.0 and self.transition(key, "active", "auto:resume"):
            return "active"
        return None

    def get_state(self, agent_id: str) -> dict:
        key = str(agent_id or "").strip()
        row = self._agents.get(key)
        if not isinstance(row, dict):
            raise KeyError("agent not found")
        return self._snapshot(key, row)

    def list_by_state(self, state: str) -> list[dict]:
        target = str(state or "").strip()
        rows: list[dict] = []
        for agent_id, row in self._agents.items():
            if str(row.get("state", "")) != target:
                continue
            rows.append(self._snapshot(agent_id, row))
        rows.sort(key=lambda item: str(item.get("agent_id", "")))
        return rows

    def retire(self, agent_id: str, reason: str = "") -> bool:
        return self.transition(agent_id, "retired", reason or "retire")

    def ban(self, agent_id: str, reason: str = "") -> bool:
        return self.transition(agent_id, "banned", reason or "ban")
