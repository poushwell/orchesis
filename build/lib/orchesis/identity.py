"""Agent identity models and trust-tier capability checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class TrustTier(IntEnum):
    """Agent trust levels where higher tier grants more autonomy."""

    BLOCKED = 0
    INTERN = 1
    ASSISTANT = 2
    OPERATOR = 3
    PRINCIPAL = 4


@dataclass
class AgentIdentity:
    """Formal identity used for scoped policy enforcement."""

    agent_id: str
    name: str
    trust_tier: TrustTier = TrustTier.INTERN
    allowed_tools: list[str] | None = None
    denied_tools: list[str] | None = None
    max_cost_per_call: float | None = None
    daily_budget: float | None = None
    rate_limit_per_minute: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentRegistry:
    """Registry of known agents with their identities."""

    agents: dict[str, AgentIdentity]
    default_tier: TrustTier = TrustTier.INTERN

    def get(self, agent_id: str) -> AgentIdentity:
        """Get identity; unknown agents resolve to default tier."""
        identity = self.agents.get(agent_id)
        if identity is not None:
            return identity
        return AgentIdentity(
            agent_id=agent_id,
            name=agent_id,
            trust_tier=self.default_tier,
        )

    def register(self, identity: AgentIdentity) -> None:
        """Add or update an agent identity."""
        self.agents[identity.agent_id] = identity

    def is_known(self, agent_id: str) -> bool:
        """Check whether an agent is explicitly registered."""
        return agent_id in self.agents


TIER_DEFAULT_CAPABILITIES = {
    TrustTier.BLOCKED: set(),
    TrustTier.INTERN: {"read"},
    TrustTier.ASSISTANT: {"read", "write"},
    TrustTier.OPERATOR: {"read", "write", "delete", "execute"},
    TrustTier.PRINCIPAL: {"read", "write", "delete", "execute", "admin"},
}

TOOL_CAPABILITY_MAP = {
    "read_file": "read",
    "write_file": "write",
    "delete_file": "delete",
    "run_sql": "execute",
    "api_call": "execute",
}


def check_capability(identity: AgentIdentity, tool: str) -> bool:
    """Check if agent trust tier allows the tool capability."""
    required = TOOL_CAPABILITY_MAP.get(tool, "execute")
    allowed = TIER_DEFAULT_CAPABILITIES[identity.trust_tier]
    return required in allowed
