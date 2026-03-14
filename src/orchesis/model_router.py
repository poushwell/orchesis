"""Route LLM requests to optimal model based on task complexity."""

from __future__ import annotations

import random
import re
import threading
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


class ThompsonSampler:
    """Beta-distribution bandit for adaptive model selection."""

    def __init__(self) -> None:
        self._state: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def register_model(self, model: str) -> None:
        name = str(model or "").strip()
        if not name:
            return
        with self._lock:
            self._state.setdefault(name, {"alpha": 1.0, "beta": 1.0})

    def sample(self, models: list[str]) -> str:
        cleaned = [str(item).strip() for item in models if str(item).strip()]
        if not cleaned:
            return ""
        best_model = cleaned[0]
        best_score = -1.0
        with self._lock:
            for name in cleaned:
                self._state.setdefault(name, {"alpha": 1.0, "beta": 1.0})
            for name in cleaned:
                priors = self._state[name]
                score = random.betavariate(float(priors["alpha"]), float(priors["beta"]))
                if score > best_score:
                    best_score = score
                    best_model = name
        return best_model

    def update(self, model: str, success: bool) -> None:
        name = str(model or "").strip()
        if not name:
            return
        with self._lock:
            bucket = self._state.setdefault(name, {"alpha": 1.0, "beta": 1.0})
            if bool(success):
                bucket["alpha"] = float(bucket["alpha"]) + 1.0
            else:
                bucket["beta"] = float(bucket["beta"]) + 1.0

    def get_stats(self) -> dict[str, dict[str, float]]:
        with self._lock:
            out: dict[str, dict[str, float]] = {}
            for name, values in self._state.items():
                alpha = float(values.get("alpha", 1.0))
                beta = float(values.get("beta", 1.0))
                denom = alpha + beta
                out[name] = {
                    "alpha": alpha,
                    "beta": beta,
                    "estimated_success_rate": (alpha / denom) if denom > 0 else 0.5,
                }
            return out


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
        self._sampler = ThompsonSampler()
        self._sampler.register_model(self._default_model)
        for item in self._rules:
            if not isinstance(item, dict):
                continue
            self._sampler.register_model(str(item.get("model", "")).strip())

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
        candidates: list[str] = []
        for rule in self._rules:
            if isinstance(rule, dict) and str(rule.get("complexity")) == complexity:
                candidate = str(rule.get("model", "")).strip()
                if candidate:
                    candidates.append(candidate)
        # Preserve existing behavior when only one model matches this tier.
        unique_candidates = list(dict.fromkeys(candidates))
        sampler_used = False
        if len(unique_candidates) == 1:
            model = unique_candidates[0]
        elif len(unique_candidates) >= 2:
            sampled = self._sampler.sample(unique_candidates)
            model = sampled if sampled else unique_candidates[0]
            sampler_used = True
        elif complexity in {"low", "medium", "high"}:
            # No explicit tier rule -> keep default model.
            model = self._default_model

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
            "sampler_used": sampler_used,
        }
        self._routing_log.append(dict(result))
        return result

    def record_outcome(self, model: str, success: bool) -> None:
        self._sampler.update(model, bool(success))

    def get_sampler_stats(self) -> dict[str, dict[str, float]]:
        return self._sampler.get_stats()

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

