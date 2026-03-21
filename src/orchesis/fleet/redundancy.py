"""Fleet Redundancy Score - measures fleet diversity and resilience."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class AgentSpec:
    agent_id: str
    model: str
    provider: str
    tools: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RedundancyScore:
    overall: float = 0.0
    model_diversity: float = 0.0
    provider_diversity: float = 0.0
    tool_coverage: float = 0.0
    capability_overlap: float = 0.0
    single_points_of_failure: list[str] = field(default_factory=list)
    fleet_size: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"Fleet Redundancy Score: {self.overall:.2f}/1.00\n"
            f"  Model diversity:    {self.model_diversity:.2f}\n"
            f"  Provider diversity:  {self.provider_diversity:.2f}\n"
            f"  Tool coverage:      {self.tool_coverage:.2f}\n"
            f"  Capability overlap: {self.capability_overlap:.2f}\n"
            f"  Fleet size: {self.fleet_size}\n"
            f"  Single points of failure: {len(self.single_points_of_failure)}"
        )


class FleetRedundancyScorer:
    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or {
            "model_diversity": 0.25,
            "provider_diversity": 0.30,
            "tool_coverage": 0.25,
            "capability_overlap": 0.20,
        }
        self._agents: dict[str, AgentSpec] = {}

    def register_agent(
        self,
        agent_id: str,
        model: str = "",
        provider: str = "",
        tools: list[str] | None = None,
        capabilities: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register an agent in the fleet."""
        aid = str(agent_id or "").strip()
        self._agents[aid] = AgentSpec(
            agent_id=aid,
            model=str(model or ""),
            provider=str(provider or ""),
            tools=list(tools or []),
            capabilities=list(capabilities or []),
            metadata=dict(metadata or {}),
        )
        logger.info(
            "Registered fleet agent",
            extra={"component": "fleet_redundancy", "agent_id": aid},
        )

    def remove_agent(self, agent_id: str) -> None:
        self._agents.pop(str(agent_id or ""), None)

    def _shannon_entropy_normalized(self, items: list[str]) -> float:
        """Compute normalized Shannon entropy (0-1) of item distribution."""
        if not items or len(set(items)) <= 1:
            return 0.0
        counts = Counter(items)
        total = len(items)
        n_unique = len(counts)
        if n_unique <= 1:
            return 0.0
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        max_entropy = math.log2(n_unique)
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def _compute_model_diversity(self) -> float:
        models = [agent.model for agent in self._agents.values() if agent.model]
        return self._shannon_entropy_normalized(models)

    def _compute_provider_diversity(self) -> float:
        providers = [agent.provider for agent in self._agents.values() if agent.provider]
        return self._shannon_entropy_normalized(providers)

    def _compute_tool_coverage(self) -> tuple[float, list[str], dict[str, list[str]]]:
        """Return (score, single_points, details)."""
        tool_agents: dict[str, set[str]] = {}
        for agent in self._agents.values():
            for tool in agent.tools:
                tool_agents.setdefault(tool, set()).add(agent.agent_id)
        if not tool_agents:
            return 0.0, [], {}
        covered = sum(1 for agents in tool_agents.values() if len(agents) >= 2)
        single = sorted(tool for tool, agents in tool_agents.items() if len(agents) == 1)
        details = {tool: sorted(agents) for tool, agents in tool_agents.items()}
        return covered / len(tool_agents), single, details

    def _compute_capability_overlap(self) -> tuple[float, dict[str, list[str]], list[str]]:
        cap_agents: dict[str, set[str]] = {}
        for agent in self._agents.values():
            for capability in agent.capabilities:
                cap_agents.setdefault(capability, set()).add(agent.agent_id)
        if not cap_agents:
            return 0.0, {}, []
        covered = sum(1 for agents in cap_agents.values() if len(agents) >= 2)
        details = {cap: sorted(agents) for cap, agents in cap_agents.items()}
        single = sorted(cap for cap, agents in cap_agents.items() if len(agents) == 1)
        return covered / len(cap_agents), details, single

    def compute(self) -> RedundancyScore:
        """Compute fleet redundancy score."""
        if not self._agents:
            return RedundancyScore(fleet_size=0)

        model_div = self._compute_model_diversity()
        provider_div = self._compute_provider_diversity()
        tool_cov, single_tools, tool_details = self._compute_tool_coverage()
        cap_overlap, cap_details, single_caps = self._compute_capability_overlap()

        overall = (
            self.weights["model_diversity"] * model_div
            + self.weights["provider_diversity"] * provider_div
            + self.weights["tool_coverage"] * tool_cov
            + self.weights["capability_overlap"] * cap_overlap
        )

        result = RedundancyScore(
            overall=round(overall, 4),
            model_diversity=round(model_div, 4),
            provider_diversity=round(provider_div, 4),
            tool_coverage=round(tool_cov, 4),
            capability_overlap=round(cap_overlap, 4),
            single_points_of_failure=single_tools,
            fleet_size=len(self._agents),
            details={
                "tool_agents": tool_details,
                "capability_agents": cap_details,
                "single_capabilities": single_caps,
                "models": Counter(agent.model for agent in self._agents.values() if agent.model),
                "providers": Counter(agent.provider for agent in self._agents.values() if agent.provider),
            },
        )
        logger.info(
            "Computed fleet redundancy score",
            extra={"component": "fleet_redundancy"},
        )
        return result

    def get_agents(self) -> list[AgentSpec]:
        return list(self._agents.values())

    def clear(self) -> None:
        self._agents.clear()
