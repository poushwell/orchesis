"""Fleet coordination for multi-agent routing and sharing."""

from __future__ import annotations

from typing import Any


class FleetCoordinator:
    """Coordinates multiple agents - shared context, load balancing."""

    MAX_ENTRIES = 10_000

    def __init__(self, config: dict | None = None):
        self._config = config if isinstance(config, dict) else {}
        self._agents: dict[str, dict[str, Any]] = {}
        self._shared_context: dict[str, str] = {}
        self._shared_context_order: list[str] = []
        self._tasks_routed = 0

    def register_agent(self, agent_id: str, capabilities: list[str]) -> dict:
        aid = str(agent_id or "").strip()
        caps = sorted({str(item).strip() for item in capabilities if str(item).strip()})
        if not aid:
            return {"agent_id": "", "registered": False}
        row = self._agents.get(aid, {"tasks": 0, "status": "idle", "context": {}})
        row["agent_id"] = aid
        row["capabilities"] = caps
        row["tasks"] = int(row.get("tasks", 0) or 0)
        row["status"] = str(row.get("status", "idle") or "idle")
        row["context"] = row.get("context") if isinstance(row.get("context"), dict) else {}
        self._agents[aid] = row
        return {"agent_id": aid, "registered": True, "capabilities": caps}

    def _matches_capabilities(self, agent: dict[str, Any], required: list[str]) -> bool:
        if not required:
            return True
        caps = {
            str(item).strip().lower()
            for item in agent.get("capabilities", [])
            if str(item).strip()
        }
        return all(item.lower() in caps for item in required)

    def assign_task(self, task: dict) -> str:
        """Route task to best available agent based on capabilities."""
        if not self._agents:
            return ""
        payload = task if isinstance(task, dict) else {}
        required_raw = payload.get("required_capabilities", payload.get("capabilities", []))
        required = [str(item).strip() for item in required_raw] if isinstance(required_raw, list) else []
        candidates = [
            agent
            for agent in self._agents.values()
            if str(agent.get("status", "idle")) != "degraded" and self._matches_capabilities(agent, required)
        ]
        if not candidates:
            return ""
        candidates.sort(key=lambda row: (int(row.get("tasks", 0) or 0), str(row.get("agent_id", ""))))
        chosen = candidates[0]
        chosen["tasks"] = int(chosen.get("tasks", 0) or 0) + 1
        chosen["status"] = "active"
        self._tasks_routed += 1

        context_key = payload.get("context_key")
        context_value = payload.get("context_value")
        if isinstance(context_key, str) and context_key.strip() and isinstance(context_value, str):
            key = context_key.strip()
            context = chosen.get("context")
            if not isinstance(context, dict):
                context = {}
            context[key] = context_value
            chosen["context"] = context
            context_id = f"{chosen['agent_id']}:{key}"
            self._shared_context[context_id] = context_value
            self._shared_context_order.append(context_id)
            self._trim_shared_context()
        return str(chosen.get("agent_id", ""))

    def share_context(self, from_agent: str, to_agent: str, context_key: str) -> bool:
        """Share context between agents."""
        src = str(from_agent or "").strip()
        dst = str(to_agent or "").strip()
        key = str(context_key or "").strip()
        if src not in self._agents or dst not in self._agents or not key:
            return False
        src_context = self._agents[src].get("context")
        value = None
        if isinstance(src_context, dict):
            value = src_context.get(key)
        if value is None:
            value = self._shared_context.get(f"{src}:{key}")
        if not isinstance(value, str):
            return False
        dst_context = self._agents[dst].get("context")
        if not isinstance(dst_context, dict):
            dst_context = {}
        dst_context[key] = value
        self._agents[dst]["context"] = dst_context
        context_id = f"{dst}:{key}"
        self._shared_context[context_id] = value
        self._shared_context_order.append(context_id)
        self._trim_shared_context()
        return True

    def _trim_shared_context(self) -> None:
        cap = max(1, int(self.MAX_ENTRIES))
        while len(self._shared_context_order) > cap:
            oldest = self._shared_context_order.pop(0)
            if oldest not in self._shared_context_order:
                self._shared_context.pop(oldest, None)

    def get_fleet_status(self) -> dict:
        statuses = {"active": 0, "idle": 0, "degraded": 0}
        for row in self._agents.values():
            status = str(row.get("status", "idle") or "idle")
            if status not in statuses:
                status = "idle"
            statuses[status] += 1
        return {
            "total_agents": len(self._agents),
            "active": statuses["active"],
            "idle": statuses["idle"],
            "degraded": statuses["degraded"],
            "shared_contexts": len(self._shared_context),
            "tasks_routed": int(self._tasks_routed),
        }

    def get_load_distribution(self) -> dict:
        """Request distribution across agents."""
        distribution = {agent_id: int(row.get("tasks", 0) or 0) for agent_id, row in self._agents.items()}
        total_tasks = sum(distribution.values())
        max_load = max(distribution.values()) if distribution else 0
        min_load = min(distribution.values()) if distribution else 0
        return {
            "distribution": distribution,
            "total_tasks": total_tasks,
            "max_load": max_load,
            "min_load": min_load,
        }

    def rebalance(self) -> dict:
        """Rebalance load across agents."""
        if len(self._agents) < 2:
            return {"rebalanced": False, "moved_tasks": 0, "from_agent": None, "to_agent": None}
        ordered = sorted(
            self._agents.values(),
            key=lambda row: (int(row.get("tasks", 0) or 0), str(row.get("agent_id", ""))),
        )
        low = ordered[0]
        high = ordered[-1]
        low_tasks = int(low.get("tasks", 0) or 0)
        high_tasks = int(high.get("tasks", 0) or 0)
        if high_tasks - low_tasks <= 1:
            return {"rebalanced": False, "moved_tasks": 0, "from_agent": None, "to_agent": None}
        low["tasks"] = low_tasks + 1
        high["tasks"] = high_tasks - 1
        low["status"] = "active" if low["tasks"] > 0 else "idle"
        high["status"] = "active" if high["tasks"] > 0 else "idle"
        return {
            "rebalanced": True,
            "moved_tasks": 1,
            "from_agent": str(high.get("agent_id", "")),
            "to_agent": str(low.get("agent_id", "")),
        }
