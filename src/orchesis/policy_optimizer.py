"""Policy optimization suggestions from observed traffic."""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any


class PolicyOptimizer:
    """Suggests policy optimizations based on traffic patterns."""

    def analyze(self, decisions_log: list, current_policy: dict) -> dict:
        suggestions = []
        rate = self.suggest_rate_limits(decisions_log)
        cache = self.suggest_cache_settings(decisions_log)
        budget = self.suggest_budget_limits(decisions_log)
        if rate:
            suggestions.append(rate)
        if cache:
            suggestions.append(cache)
        if budget:
            suggestions.append(budget)

        expected_improvements = {
            "cost_reduction_percent": round(sum(max(0.0, float(self.estimate_impact(item, decisions_log)["cost_change"])) for item in suggestions), 3),
            "performance_delta": round(sum(float(self.estimate_impact(item, decisions_log)["performance_change"]) for item in suggestions), 3),
            "security_delta": round(sum(float(self.estimate_impact(item, decisions_log)["security_change"]) for item in suggestions), 3),
        }
        risk_assessment = {
            "overall_risk": "low" if len(suggestions) <= 2 else "medium",
            "requires_review": any(item.get("type") in {"rate_limit", "budget"} for item in suggestions),
        }
        return {
            "current_policy": current_policy if isinstance(current_policy, dict) else {},
            "suggested_changes": suggestions,
            "expected_improvements": expected_improvements,
            "risk_assessment": risk_assessment,
        }

    def suggest_rate_limits(self, decisions_log: list) -> dict:
        """Suggest optimal rate limits based on traffic."""
        counts: dict[str, int] = defaultdict(int)
        for row in decisions_log if isinstance(decisions_log, list) else []:
            agent = self._agent_id(row)
            if not agent:
                continue
            counts[agent] += 1
        if not counts:
            return {}
        max_agent = max(counts, key=lambda key: counts[key])
        suggested = max(30, min(600, int(counts[max_agent] * 1.5)))
        return {
            "type": "rate_limit",
            "target": max_agent,
            "path": f"agents.{max_agent}.rate_limit_per_minute",
            "value": suggested,
            "reason": "Observed sustained request volume",
        }

    def suggest_cache_settings(self, decisions_log: list) -> dict:
        """Suggest cache similarity threshold based on query patterns."""
        values: list[float] = []
        for row in decisions_log if isinstance(decisions_log, list) else []:
            snapshot = self._snapshot(row)
            if not isinstance(snapshot, dict):
                continue
            raw = snapshot.get("cache_hit_rate")
            if isinstance(raw, int | float):
                values.append(float(raw))
        if not values:
            return {
                "type": "cache",
                "path": "semantic_cache.similarity_threshold",
                "value": 0.85,
                "reason": "Default recommendation",
            }
        avg = sum(values) / float(len(values))
        suggested = 0.75 if avg < 0.4 else (0.9 if avg > 0.8 else 0.85)
        return {
            "type": "cache",
            "path": "semantic_cache.similarity_threshold",
            "value": round(suggested, 2),
            "reason": "Aligned to observed cache hit patterns",
        }

    def suggest_budget_limits(self, decisions_log: list) -> dict:
        """Suggest daily budgets based on spending history."""
        per_agent: dict[str, float] = defaultdict(float)
        for row in decisions_log if isinstance(decisions_log, list) else []:
            agent = self._agent_id(row)
            if not agent:
                continue
            per_agent[agent] += self._cost(row)
        if not per_agent:
            return {}
        target = max(per_agent, key=lambda key: per_agent[key])
        observed = per_agent[target]
        suggested = max(1.0, round(observed * 1.3, 2))
        return {
            "type": "budget",
            "target": target,
            "path": f"agents.{target}.daily_budget",
            "value": suggested,
            "reason": "Budget aligned with observed spend",
        }

    def apply_suggestions(self, policy: dict, suggestions: list[dict]) -> dict:
        """Apply selected suggestions to policy dict."""
        out = deepcopy(policy if isinstance(policy, dict) else {})
        for suggestion in suggestions if isinstance(suggestions, list) else []:
            if not isinstance(suggestion, dict):
                continue
            path = suggestion.get("path")
            if not isinstance(path, str) or not path:
                continue
            self._set_path(out, path, suggestion.get("value"))
        return out

    def estimate_impact(self, suggestion: dict, decisions_log: list) -> dict:
        impact = {"cost_change": 0.0, "security_change": 0.0, "performance_change": 0.0}
        if not isinstance(suggestion, dict):
            return impact
        typ = suggestion.get("type")
        if typ == "cache":
            impact["cost_change"] = 5.0
            impact["performance_change"] = 7.5
        elif typ == "rate_limit":
            impact["security_change"] = 6.0
            impact["performance_change"] = -2.0
        elif typ == "budget":
            total = sum(self._cost(item) for item in decisions_log if isinstance(decisions_log, list))
            impact["cost_change"] = round(min(15.0, total * 2.0), 3)
            impact["security_change"] = 1.5
        return impact

    @staticmethod
    def _set_path(obj: dict[str, Any], path: str, value: Any) -> None:
        parts = [part for part in path.split(".") if part]
        if not parts:
            return
        current = obj
        for key in parts[:-1]:
            next_obj = current.get(key)
            if not isinstance(next_obj, dict):
                current[key] = {}
            current = current[key]
        current[parts[-1]] = value

    @staticmethod
    def _agent_id(row: Any) -> str:
        if isinstance(row, dict):
            value = row.get("agent_id", "")
        else:
            value = getattr(row, "agent_id", "")
        return str(value or "")

    @staticmethod
    def _snapshot(row: Any) -> dict[str, Any]:
        if isinstance(row, dict):
            value = row.get("state_snapshot", {})
        else:
            value = getattr(row, "state_snapshot", {})
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _cost(row: Any) -> float:
        raw = row.get("cost", 0.0) if isinstance(row, dict) else getattr(row, "cost", 0.0)
        try:
            return float(raw)
        except (TypeError, ValueError):
            return 0.0
