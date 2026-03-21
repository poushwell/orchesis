"""Fast Path - lightweight request evaluation for known-safe agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    BASIC = "basic"
    TRUSTED = "trusted"
    INTERNAL = "internal"


SKIPPABLE_PHASES = {
    TrustLevel.UNTRUSTED: [],
    TrustLevel.BASIC: [
        "experiment",
        "flow_xray",
        "cascade",
        "adaptive_detection",
    ],
    TrustLevel.TRUSTED: [
        "experiment",
        "flow_xray",
        "cascade",
        "adaptive_detection",
        "mast_request",
        "model_router",
        "auto_healing",
    ],
    TrustLevel.INTERNAL: [
        "experiment",
        "flow_xray",
        "cascade",
        "adaptive_detection",
        "mast_request",
        "model_router",
        "auto_healing",
        "behavioral",
    ],
}


MANDATORY_PHASES = {
    "parse",
    "policy",
    "secrets",
    "budget",
    "upstream",
    "post_upstream",
    "send",
}


FRAMEWORK_TRUST = {
    "openclaw": TrustLevel.BASIC,
    "paperclip": TrustLevel.BASIC,
    "langchain": TrustLevel.BASIC,
    "crewai": TrustLevel.BASIC,
    "autogen": TrustLevel.BASIC,
}


@dataclass
class FastPathDecision:
    fast_path: bool = False
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    skip_phases: list[str] = field(default_factory=list)
    framework: str = ""
    reason: str = ""


class FastPathEvaluator:
    """Evaluate whether a request qualifies for fast path processing."""

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        registered_agents: set[str] | None = None,
    ):
        self.policy = dict(policy or {})
        self.registered_agents = set(registered_agents or set())
        self._request_count: dict[str, int] = {}
        self._trust_overrides: dict[str, TrustLevel] = {}

    def set_trust(self, agent_id: str, level: TrustLevel) -> None:
        """Manually set trust level for an agent."""
        self._trust_overrides[str(agent_id or "")] = level

    def _determine_trust(self, agent_id: str, framework: str) -> TrustLevel:
        """Determine trust level for a request."""
        if agent_id in self._trust_overrides:
            return self._trust_overrides[agent_id]
        if agent_id in self.registered_agents:
            return TrustLevel.TRUSTED
        if framework in FRAMEWORK_TRUST:
            return FRAMEWORK_TRUST[framework]
        return TrustLevel.UNTRUSTED

    def _detect_framework(self, headers: dict[str, Any]) -> str:
        """Detect framework from headers."""
        ua = str(headers.get("user-agent") or "").lower()
        if "openclaw" in ua or "openhands" in ua:
            return "openclaw"
        fw = str(headers.get("x-orchesis-framework") or "").lower()
        if fw:
            return fw
        if headers.get("x-openclaw-session-id"):
            return "openclaw"
        return ""

    def evaluate(
        self,
        headers: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> FastPathDecision:
        """Evaluate request for fast path eligibility."""
        _ = body
        headers = dict(headers or {})
        framework = self._detect_framework(headers)
        agent_id = str(
            headers.get("x-orchesis-agent-id")
            or headers.get("x-openclaw-session-id")
            or ""
        )
        self._request_count[agent_id] = self._request_count.get(agent_id, 0) + 1

        trust = self._determine_trust(agent_id, framework)
        if trust == TrustLevel.UNTRUSTED:
            return FastPathDecision(
                fast_path=False,
                trust_level=trust,
                framework=framework,
                reason="Unknown agent, full pipeline required",
            )

        skip = [
            phase
            for phase in SKIPPABLE_PHASES.get(trust, [])
            if phase not in MANDATORY_PHASES
        ]
        decision = FastPathDecision(
            fast_path=len(skip) > 0,
            trust_level=trust,
            skip_phases=skip,
            framework=framework,
            reason=f"Trust level {trust.value}: skipping {len(skip)} phases",
        )
        logger.debug(
            "Fast path evaluation complete",
            extra={
                "component": "fast_path",
                "agent_id": agent_id,
                "framework": framework,
            },
        )
        return decision

    def get_mandatory_phases(self) -> set[str]:
        """Return set of phases that are always mandatory."""
        return set(MANDATORY_PHASES)
