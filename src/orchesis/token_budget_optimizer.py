"""Token Budget Optimizer - optimal allocation of token budget.

Given total token budget, allocate optimally across:
- System prompt (fixed)
- History (compressible)
- Current message (fixed)
- Response buffer (reserved)
"""

from __future__ import annotations

from typing import Any


class TokenBudgetOptimizer:
    """Optimal token budget allocation across context components."""

    DEFAULT_ALLOCATION = {
        "system": 0.15,
        "history": 0.50,
        "current": 0.20,
        "response": 0.15,
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.total_budget = int(cfg.get("total_budget", 128000))
        self.allocation = dict(self.DEFAULT_ALLOCATION)

    def allocate(self, total: int, components: dict[str, int]) -> dict[str, int]:
        """Allocate tokens given component sizes and priority constraints."""
        total_budget = max(0, int(total))
        payload = {
            str(key): max(0, int(value))
            for key, value in components.items()
            if isinstance(value, int | float)
        }
        used = sum(payload.values())
        if used <= total_budget:
            return dict(payload)

        priority = ["system", "current", "response", "history"]
        allocated: dict[str, int] = {}
        remaining = total_budget

        for comp in priority:
            if comp not in payload:
                continue
            if remaining <= 0:
                allocated[comp] = 0
                continue
            take = min(payload[comp], remaining)
            allocated[comp] = int(take)
            remaining -= int(take)

        for comp, value in payload.items():
            if comp in allocated:
                continue
            if remaining <= 0:
                allocated[comp] = 0
                continue
            take = min(value, remaining)
            allocated[comp] = int(take)
            remaining -= int(take)

        return allocated

    def compute_savings(self, before: dict[str, int], after: dict[str, int]) -> dict[str, Any]:
        """Compute token savings from optimization."""
        before_total = sum(max(0, int(value)) for value in before.values())
        after_total = sum(max(0, int(value)) for value in after.values())
        saved = max(0, before_total - after_total)
        return {
            "before_tokens": before_total,
            "after_tokens": after_total,
            "saved": saved,
            "savings_rate": round(saved / max(1, before_total), 4),
        }

    def recommend_model(self, required_tokens: int) -> dict[str, Any]:
        """Recommend cheapest model that fits token budget."""
        models = {
            "gpt-4o-mini": 128000,
            "gpt-4o": 128000,
            "claude-3-haiku": 200000,
            "claude-3-5-sonnet": 200000,
        }
        required = max(0, int(required_tokens))
        cheapest = [name for name, cap in models.items() if cap >= required]
        return {
            "required": required,
            "recommended": cheapest[0] if cheapest else "claude-3-5-sonnet",
            "fits": bool(cheapest),
        }

    def get_utilization(self, used: int) -> dict[str, Any]:
        spent = max(0, int(used))
        total = max(1, int(self.total_budget))
        return {
            "used": spent,
            "total": total,
            "utilization": round(spent / total, 4),
            "remaining": int(self.total_budget) - spent,
        }
