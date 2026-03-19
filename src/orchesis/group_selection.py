"""Group Selection - multi-level evolutionary dynamics.

Individual selection: each agent optimizes own performance.
Group selection: agent groups that cooperate outperform defectors.

Applied: agents that share context (quorum) outperform isolates.
Tier 3 research - requires fleet data.
"""

from __future__ import annotations

import threading
from typing import Any


class GroupSelectionModel:
    """Multi-level selection for agent fleet dynamics."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.cooperation_bonus = float(cfg.get("cooperation_bonus", 0.2))
        self.defection_penalty = float(cfg.get("defection_penalty", 0.1))
        self._agents: dict[str, dict[str, Any]] = {}
        self._groups: dict[str, list[str]] = {}
        self._fitness_history: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def register_agent(self, agent_id: str, group_id: str) -> None:
        with self._lock:
            self._agents[agent_id] = {
                "group": group_id,
                "fitness": 0.5,
                "cooperative": True,
                "interactions": 0,
            }
            if group_id not in self._groups:
                self._groups[group_id] = []
            if agent_id not in self._groups[group_id]:
                self._groups[group_id].append(agent_id)

    def record_interaction(self, agent_id: str, cooperative: bool, outcome: float) -> dict[str, Any]:
        """Record agent interaction outcome."""
        with self._lock:
            if agent_id not in self._agents:
                return {"error": "Agent not registered"}
            agent = self._agents[agent_id]
            agent["cooperative"] = bool(cooperative)
            agent["interactions"] = int(agent.get("interactions", 0)) + 1

            individual_fitness = float(outcome)
            group_id = str(agent.get("group", ""))
            group_members = self._groups.get(group_id, [])
            group_cooperators = sum(
                1 for member in group_members if self._agents.get(member, {}).get("cooperative", False)
            )
            cooperation_rate = group_cooperators / max(1, len(group_members))

            group_effect = self.cooperation_bonus * cooperation_rate if cooperative else -self.defection_penalty
            total_fitness = min(1.0, max(0.0, individual_fitness + group_effect))
            agent["fitness"] = total_fitness

            row = {
                "agent_id": agent_id,
                "individual_fitness": round(individual_fitness, 4),
                "group_effect": round(group_effect, 4),
                "total_fitness": round(total_fitness, 4),
                "cooperation_rate": round(cooperation_rate, 4),
            }
            self._fitness_history.append(row)
            if len(self._fitness_history) > 10_000:
                self._fitness_history = self._fitness_history[-10_000:]
            return row

    def get_group_fitness(self, group_id: str) -> dict[str, Any]:
        with self._lock:
            members = self._groups.get(group_id, [])
            if not members:
                return {"group_id": group_id, "fitness": 0.0, "size": 0}
            fitnesses = [float(self._agents[m]["fitness"]) for m in members if m in self._agents]
            return {
                "group_id": group_id,
                "fitness": round(sum(fitnesses) / max(1, len(fitnesses)), 4),
                "size": len(members),
                "cooperators": sum(1 for m in members if self._agents.get(m, {}).get("cooperative")),
            }

    def get_fittest_group(self) -> dict[str, Any] | None:
        with self._lock:
            group_ids = list(self._groups.keys())
        if not group_ids:
            return None
        groups = [self.get_group_fitness(group_id) for group_id in group_ids]
        return max(groups, key=lambda row: float(row.get("fitness", 0.0)))

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "agents": len(self._agents),
                "groups": len(self._groups),
                "cooperation_bonus": self.cooperation_bonus,
            }
