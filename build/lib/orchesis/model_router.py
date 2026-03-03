"""Route LLM requests to optimal model based on task complexity."""

from __future__ import annotations

import re
from typing import Any


LOW_COMPLEXITY_KEYWORDS = [
    "rename",
    "format",
    "list",
    "count",
    "simple",
    "copy",
    "move",
    "delete",
    "send",
    "notify",
    "ping",
    "check",
    "status",
    "hello",
    "hi",
    "thanks",
    "yes",
    "no",
    "ok",
    "confirm",
    "cancel",
    "translate",
]

HIGH_COMPLEXITY_KEYWORDS = [
    "analyze",
    "architect",
    "design",
    "debug",
    "complex",
    "optimize",
    "refactor",
    "research",
    "compare",
    "evaluate",
    "synthesize",
    "strategy",
    "plan",
    "security",
    "audit",
    "review",
    "investigate",
    "diagnose",
    "explain why",
]


class ModelRouter:
    """Routes LLM requests to an optimal model based on complexity."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}
        self._default_model = str(self._config.get("default", "gpt-4o"))
        self._rules = self._config.get(
            "rules",
            [
                {"complexity": "low", "model": "gpt-4o-mini"},
                {"complexity": "high", "model": self._default_model},
            ],
        )
        self._low_keywords = set(self._config.get("low_keywords", LOW_COMPLEXITY_KEYWORDS))
        self._high_keywords = set(self._config.get("high_keywords", HIGH_COMPLEXITY_KEYWORDS))
        self._routing_log: list[dict[str, Any]] = []
        self._last_reason = "Default complexity"

    def _classify(self, prompt: str, tool_name: str | None = None) -> str:
        prompt_lower = prompt.lower() if isinstance(prompt, str) else ""
        tool_hint = tool_name.lower() if isinstance(tool_name, str) else ""

        for keyword in self._high_keywords:
            candidate = keyword.lower().strip()
            if not candidate:
                continue
            if (" " in candidate and candidate in prompt_lower) or re.search(
                rf"\b{re.escape(candidate)}\b", prompt_lower
            ):
                self._last_reason = f"Complex task detected (keyword: '{keyword}')"
                return "high"
        for keyword in self._low_keywords:
            candidate = keyword.lower().strip()
            if not candidate or len(candidate) <= 2:
                continue
            if (" " in candidate and candidate in prompt_lower) or re.search(
                rf"\b{re.escape(candidate)}\b", prompt_lower
            ):
                self._last_reason = f"Simple task detected (keyword: '{keyword}')"
                return "low"

        if any(token in tool_hint for token in ("search", "read", "write", "notify")) and len(prompt_lower) < 150:
            self._last_reason = f"Tool hint suggests simple operation ('{tool_hint}')"
            return "low"

        if len(prompt_lower) > 2000:
            self._last_reason = f"Long prompt ({len(prompt_lower)} chars) suggests complex task"
            return "high"
        if len(prompt_lower) < 40:
            self._last_reason = "Short prompt suggests simple task"
            return "low"
        self._last_reason = "Default complexity"
        return "medium"

    def route(self, prompt: str | None, tool_name: str | None = None) -> dict[str, Any]:
        from orchesis.cost_tracker import MODEL_COSTS

        complexity = self._classify(prompt or "", tool_name=tool_name)
        model = self._default_model
        for rule in self._rules:
            if isinstance(rule, dict) and str(rule.get("complexity")) == complexity:
                model = str(rule.get("model", model))
                break

        default_rates = MODEL_COSTS.get(self._default_model, MODEL_COSTS["default"])
        selected_rates = MODEL_COSTS.get(model, MODEL_COSTS["default"])
        avg_default = (default_rates["input"] + default_rates["output"]) / 2.0
        avg_selected = (selected_rates["input"] + selected_rates["output"]) / 2.0
        ratio = (avg_selected / avg_default) if avg_default > 0 else 1.0

        result = {
            "model": model,
            "complexity": complexity,
            "reason": self._last_reason,
            "cost_ratio": round(ratio, 4),
        }
        self._routing_log.append(dict(result))
        return result

    def get_savings_estimate(self) -> dict[str, Any]:
        total_calls = len(self._routing_log)
        calls_downgraded = sum(
            1 for item in self._routing_log if item.get("complexity") == "low"
        )
        avg_saving_per_low = 0.95
        savings = (
            round(calls_downgraded / total_calls * avg_saving_per_low * 100, 1)
            if total_calls
            else 0.0
        )
        return {
            "total_calls_routed": total_calls,
            "calls_downgraded": calls_downgraded,
            "estimated_savings_percent": savings,
        }

