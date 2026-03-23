"""Per-tool and per-task cost tracking for AI agent tool calls."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, defaultdict
from dataclasses import asdict, dataclass
from datetime import date, datetime
from typing import Any

DEFAULT_TOOL_COSTS = {
    "web_search": 0.005,
    "code_interpreter": 0.02,
    "shell_execute": 0.001,
    "read_file": 0.0001,
    "write_file": 0.0001,
    "send_email": 0.001,
    "default": 0.001,
}

MODEL_COSTS = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4.1": {"input": 0.002, "output": 0.008},
    "gpt-4.1-mini": {"input": 0.0004, "output": 0.0016},
    "gpt-4.1-nano": {"input": 0.0001, "output": 0.0004},
    "claude-opus-4": {"input": 0.015, "output": 0.075},
    "claude-sonnet-4": {"input": 0.003, "output": 0.015},
    "claude-haiku-4": {"input": 0.0008, "output": 0.004},
    "default": {"input": 0.001, "output": 0.004},
}


@dataclass
class ToolCallCost:
    tool_name: str
    cost_usd: float
    timestamp: float
    task_id: str | None = None
    model_used: str | None = None
    tokens_input: int = 0
    tokens_output: int = 0


class CostTracker:
    """Tracks costs per tool, per task, and per day with thread safety."""

    def __init__(
        self,
        tool_costs: dict[str, float] | None = None,
        model_costs: dict[str, dict[str, float]] | None = None,
        *,
        max_call_history: int = 10_000,
        max_tasks: int = 5000,
        max_days: int = 365,
    ):
        self._lock = threading.Lock()
        self._tool_costs = {**DEFAULT_TOOL_COSTS, **(tool_costs or {})}
        self._model_costs = {**MODEL_COSTS, **(model_costs or {})}
        self._max_call_history = max(1, int(max_call_history))
        self._max_tasks = max(1, int(max_tasks))
        self._max_days = max(1, int(max_days))
        self._calls: list[ToolCallCost] = []
        self._daily_total: dict[str, float] = defaultdict(float)
        self._tool_daily: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._task_total: OrderedDict[str, float] = OrderedDict()
        self._cascade_savings_daily: dict[str, float] = defaultdict(float)
        self._loop_savings_daily: dict[str, float] = defaultdict(float)

    def record_call(
        self,
        tool_name: str,
        task_id: str | None = None,
        model: str | None = None,
        tokens_input: int = 0,
        tokens_output: int = 0,
        cost_override: float | None = None,
    ) -> ToolCallCost:
        if isinstance(cost_override, int | float):
            cost = float(cost_override)
        elif model and (tokens_input or tokens_output):
            rates = self._model_costs.get(model, self._model_costs["default"])
            cost = (tokens_input / 1000.0 * rates["input"]) + (tokens_output / 1000.0 * rates["output"])
        else:
            cost = float(self._tool_costs.get(tool_name, self._tool_costs["default"]))

        call = ToolCallCost(
            tool_name=tool_name,
            cost_usd=cost,
            timestamp=time.time(),
            task_id=task_id,
            model_used=model,
            tokens_input=int(tokens_input) if isinstance(tokens_input, int | float) else 0,
            tokens_output=int(tokens_output) if isinstance(tokens_output, int | float) else 0,
        )
        today = date.today().isoformat()
        with self._lock:
            self._calls.append(call)
            if len(self._calls) > self._max_call_history:
                drop = max(1, int(len(self._calls) * 0.2))
                self._calls = self._calls[drop:]
            self._daily_total[today] += cost
            self._tool_daily[today][tool_name] += cost
            if len(self._daily_total) > self._max_days:
                sorted_days = sorted(self._daily_total.keys())
                for old_day in sorted_days[: len(sorted_days) - self._max_days]:
                    self._daily_total.pop(old_day, None)
                    self._tool_daily.pop(old_day, None)
                    self._cascade_savings_daily.pop(old_day, None)
                    self._loop_savings_daily.pop(old_day, None)
            if task_id:
                prev = float(self._task_total.pop(task_id, 0.0))
                self._task_total[task_id] = prev + cost
                self._task_total.move_to_end(task_id)
                while len(self._task_total) > self._max_tasks:
                    drop_tasks = max(1, int(len(self._task_total) * 0.2))
                    for _ in range(drop_tasks):
                        if not self._task_total:
                            break
                        self._task_total.popitem(last=False)
        return call

    def get_daily_total(self, day: str | None = None) -> float:
        safe_day = day or date.today().isoformat()
        with self._lock:
            return float(self._daily_total.get(safe_day, 0.0))

    def get_tool_costs(self, day: str | None = None) -> dict[str, float]:
        safe_day = day or date.today().isoformat()
        with self._lock:
            return dict(self._tool_daily.get(safe_day, {}))

    def get_task_cost(self, task_id: str) -> float:
        with self._lock:
            return float(self._task_total.get(task_id, 0.0))

    def get_hourly_costs(self, day: str | None = None) -> dict[int, float]:
        safe_day = day or date.today().isoformat()
        hourly: dict[int, float] = defaultdict(float)
        with self._lock:
            for call in self._calls:
                call_day = date.fromtimestamp(call.timestamp).isoformat()
                if call_day != safe_day:
                    continue
                hour = datetime.fromtimestamp(call.timestamp).hour
                hourly[hour] += call.cost_usd
        return dict(hourly)

    def check_budget(self, budget_config: dict[str, Any]) -> dict[str, Any]:
        today = date.today().isoformat()
        daily_budget = float(budget_config.get("daily", float("inf")))
        daily_spent = self.get_daily_total(today)
        soft_pct = float(budget_config.get("soft_limit_percent", 80))

        result: dict[str, Any] = {
            "daily_budget": daily_budget,
            "daily_spent": round(daily_spent, 4),
            "daily_remaining": round(max(0.0, daily_budget - daily_spent), 4),
            "daily_percent": round((daily_spent / daily_budget * 100.0) if daily_budget and daily_budget != float("inf") else 0.0, 1),
            "over_budget": bool(daily_budget != float("inf") and daily_spent >= daily_budget),
            "soft_limit_reached": bool(
                daily_budget not in (0.0, float("inf"))
                and (daily_spent / daily_budget * 100.0) >= soft_pct
            ),
        }

        per_tool = budget_config.get("per_tool", {})
        result["per_tool_status"] = {}
        if isinstance(per_tool, dict):
            tool_costs = self.get_tool_costs(today)
            for tool, limit_raw in per_tool.items():
                if not isinstance(tool, str) or not isinstance(limit_raw, int | float):
                    continue
                limit = float(limit_raw)
                spent = float(tool_costs.get(tool, 0.0))
                result["per_tool_status"][tool] = {
                    "limit": limit,
                    "spent": round(spent, 4),
                    "percent": round((spent / limit * 100.0) if limit else 0.0, 1),
                    "over": bool(limit and spent >= limit),
                }
        return result

    def reset_daily(self) -> None:
        today = date.today().isoformat()
        with self._lock:
            self._daily_total.pop(today, None)
            self._tool_daily.pop(today, None)
            self._cascade_savings_daily.pop(today, None)
            self._loop_savings_daily.pop(today, None)

    def record_cascade_savings(self, original_model: str, actual_model: str, tokens: int) -> float:
        safe_tokens = max(0, int(tokens))
        if safe_tokens <= 0:
            return 0.0
        original_rates = self._model_costs.get(original_model, self._model_costs["default"])
        actual_rates = self._model_costs.get(actual_model, self._model_costs["default"])
        # Approximate mixed input/output token cost using average rate.
        original_cost = (safe_tokens / 1000.0) * ((original_rates["input"] + original_rates["output"]) / 2.0)
        actual_cost = (safe_tokens / 1000.0) * ((actual_rates["input"] + actual_rates["output"]) / 2.0)
        savings = max(0.0, original_cost - actual_cost)
        today = date.today().isoformat()
        with self._lock:
            self._cascade_savings_daily[today] += savings
        return round(savings, 8)

    def get_cascade_savings_today(self, day: str | None = None) -> float:
        safe_day = day or date.today().isoformat()
        with self._lock:
            return float(self._cascade_savings_daily.get(safe_day, 0.0))

    def record_loop_prevented_savings(self, amount_usd: float) -> float:
        safe = max(0.0, float(amount_usd))
        if safe <= 0.0:
            return 0.0
        today = date.today().isoformat()
        with self._lock:
            self._loop_savings_daily[today] += safe
        return round(safe, 8)

    def get_loop_prevented_savings_today(self, day: str | None = None) -> float:
        safe_day = day or date.today().isoformat()
        with self._lock:
            return float(self._loop_savings_daily.get(safe_day, 0.0))

    def estimate_llm_cost(self, model: str, tokens_input: int = 0, tokens_output: int = 0) -> float:
        rates = self._model_costs.get(model, self._model_costs["default"])
        in_tokens = max(0, int(tokens_input))
        out_tokens = max(0, int(tokens_output))
        return float((in_tokens / 1000.0 * rates["input"]) + (out_tokens / 1000.0 * rates["output"]))

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "calls": [asdict(item) for item in self._calls[-1000:]],
                "daily_totals": dict(self._daily_total),
                "tool_daily": {day: dict(values) for day, values in self._tool_daily.items()},
                "task_totals": dict(self._task_total),
                "cascade_savings_daily": dict(self._cascade_savings_daily),
                "loop_savings_daily": dict(self._loop_savings_daily),
            }

