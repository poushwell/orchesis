"""
Budget Bridge - independent cost tracking for AI agent fleets.

Does NOT trust agent-reported costs. Calculates real cost
from token counts x model pricing. Enforces budgets server-side.

Usage:
    bridge = BudgetBridge(pricing=MODEL_PRICING)
    bridge.record_usage(agent_id, model, input_tokens, output_tokens)
    cost = bridge.get_agent_cost(agent_id)
    if bridge.check_budget(agent_id, daily_limit=10.0):
        # allow request
    else:
        # budget exceeded, block
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


MODEL_PRICING = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "claude-3-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3.5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-4-sonnet": {"input": 3.00, "output": 15.00},
    "claude-4-opus": {"input": 15.00, "output": 75.00},
}


@dataclass
class UsageRecord:
    agent_id: str
    model: str
    input_tokens: int
    output_tokens: int
    computed_cost_usd: float
    reported_cost_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    discrepancy: float = 0.0


@dataclass
class BudgetStatus:
    agent_id: str
    total_cost_usd: float = 0.0
    daily_cost_usd: float = 0.0
    daily_limit_usd: float = 0.0
    budget_remaining_usd: float = 0.0
    is_over_budget: bool = False
    request_count: int = 0
    total_tokens: int = 0
    cost_discrepancy_total: float = 0.0
    spoofing_suspected: bool = False


class BudgetBridge:
    def __init__(
        self,
        pricing: dict[str, dict[str, float]] | None = None,
        daily_limit_default: float | None = None,
        spoof_threshold: float = 0.5,
    ) -> None:
        self.pricing = pricing or dict(MODEL_PRICING)
        self.daily_limit_default = daily_limit_default
        self.spoof_threshold = float(spoof_threshold)
        self._records: dict[str, list[UsageRecord]] = {}
        self._daily_limits: dict[str, float] = {}

    def set_daily_limit(self, agent_id: str, limit_usd: float) -> None:
        """Set daily budget limit for an agent."""
        self._daily_limits[str(agent_id)] = float(limit_usd)

    def compute_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Compute cost from token counts and model pricing."""
        pricing = self.pricing.get(model)
        if not isinstance(pricing, dict):
            pricing = {"input": 3.00, "output": 15.00}
        in_tokens = max(0, int(input_tokens))
        out_tokens = max(0, int(output_tokens))
        input_cost = (in_tokens / 1_000_000) * float(pricing["input"])
        output_cost = (out_tokens / 1_000_000) * float(pricing["output"])
        return round(input_cost + output_cost, 6)

    def record_usage(
        self,
        agent_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        reported_cost_usd: float = 0.0,
        request_id: str = "",
    ) -> UsageRecord:
        """Record token usage and compute real cost."""
        computed = self.compute_cost(model, input_tokens, output_tokens)
        reported = float(reported_cost_usd)
        discrepancy = round(computed - reported, 6)
        record = UsageRecord(
            agent_id=str(agent_id),
            model=str(model),
            input_tokens=max(0, int(input_tokens)),
            output_tokens=max(0, int(output_tokens)),
            computed_cost_usd=computed,
            reported_cost_usd=reported,
            request_id=str(request_id),
            discrepancy=discrepancy,
        )
        self._records.setdefault(record.agent_id, []).append(record)
        logger.debug(
            "Recorded budget usage",
            extra={
                "component": "budget_bridge",
                "agent_id": record.agent_id,
                "model": record.model,
                "computed_cost_usd": record.computed_cost_usd,
                "reported_cost_usd": record.reported_cost_usd,
            },
        )
        return record

    def get_agent_cost(self, agent_id: str) -> float:
        """Get total computed cost for an agent."""
        rows = self._records.get(str(agent_id), [])
        return round(sum(item.computed_cost_usd for item in rows), 6)

    def get_daily_cost(self, agent_id: str) -> float:
        """Get today's computed cost for an agent."""
        rows = self._records.get(str(agent_id), [])
        today = datetime.now().date()
        total = 0.0
        for item in rows:
            if datetime.fromtimestamp(item.timestamp).date() == today:
                total += item.computed_cost_usd
        return round(total, 6)

    def check_budget(self, agent_id: str, daily_limit: float | None = None) -> bool:
        """Return True when agent is within budget."""
        limit = daily_limit
        if limit is None:
            limit = self._daily_limits.get(str(agent_id))
        if limit is None:
            limit = self.daily_limit_default
        if limit is None:
            return True
        return self.get_daily_cost(agent_id) < float(limit)

    def get_status(self, agent_id: str) -> BudgetStatus:
        """Get full budget status for an agent."""
        agent_key = str(agent_id)
        rows = self._records.get(agent_key, [])
        total_cost = round(sum(item.computed_cost_usd for item in rows), 6)
        daily_cost = self.get_daily_cost(agent_key)
        request_count = len(rows)
        total_tokens = sum(item.input_tokens + item.output_tokens for item in rows)
        discrepancy_total = round(sum(item.discrepancy for item in rows), 6)
        discrepancy_ratio = (discrepancy_total / total_cost) if total_cost > 0 else 0.0

        limit = self._daily_limits.get(agent_key)
        if limit is None:
            limit = self.daily_limit_default
        daily_limit = float(limit) if limit is not None else 0.0
        is_over = (daily_cost >= daily_limit) if limit is not None else False
        remaining = max(daily_limit - daily_cost, 0.0) if limit is not None else 0.0

        return BudgetStatus(
            agent_id=agent_key,
            total_cost_usd=total_cost,
            daily_cost_usd=daily_cost,
            daily_limit_usd=round(daily_limit, 6),
            budget_remaining_usd=round(remaining, 6),
            is_over_budget=is_over,
            request_count=request_count,
            total_tokens=total_tokens,
            cost_discrepancy_total=discrepancy_total,
            spoofing_suspected=(discrepancy_ratio > self.spoof_threshold),
        )

    def get_fleet_summary(self) -> dict[str, Any]:
        """Get cost summary across all agents."""
        agents = sorted(self._records.keys())
        statuses = [self.get_status(agent_id) for agent_id in agents]
        return {
            "agents": [status.agent_id for status in statuses],
            "agent_count": len(statuses),
            "total_cost_usd": round(sum(status.total_cost_usd for status in statuses), 6),
            "daily_cost_usd": round(sum(status.daily_cost_usd for status in statuses), 6),
            "total_requests": sum(status.request_count for status in statuses),
            "suspected_spoofing_agents": [
                status.agent_id for status in statuses if status.spoofing_suspected
            ],
            "by_agent": {status.agent_id: status for status in statuses},
        }

    def detect_cost_spoofing(self, agent_id: str) -> dict[str, Any]:
        """Detect potential cost underreporting for an agent."""
        rows = self._records.get(str(agent_id), [])
        computed = round(sum(item.computed_cost_usd for item in rows), 6)
        reported = round(sum(item.reported_cost_usd for item in rows), 6)
        discrepancy = round(computed - reported, 6)
        if computed <= 0:
            reported_ratio = 1.0
        else:
            reported_ratio = reported / computed
        suspected = reported_ratio < (1.0 - self.spoof_threshold)
        return {
            "agent_id": str(agent_id),
            "computed_cost_usd": computed,
            "reported_cost_usd": reported,
            "discrepancy_usd": discrepancy,
            "reported_ratio": round(reported_ratio, 6),
            "spoofing_suspected": suspected,
        }

    def clear(self, agent_id: str | None = None) -> None:
        """Clear records for one agent or whole fleet."""
        if agent_id is None:
            self._records.clear()
            self._daily_limits.clear()
            return
        key = str(agent_id)
        self._records.pop(key, None)
        self._daily_limits.pop(key, None)
