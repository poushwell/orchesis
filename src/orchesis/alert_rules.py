"""Configurable smart alerting rules."""

from __future__ import annotations

import time
from typing import Any


class AlertRule:
    """Single alerting rule with condition and action."""

    OPERATORS = ["gt", "lt", "eq", "gte", "lte", "contains"]
    METRICS = [
        "cost_today",
        "blocked_count",
        "cache_hit_rate",
        "error_rate",
        "active_agents",
        "loop_count",
    ]
    ACTIONS = ["log", "webhook", "email", "slack"]

    def __init__(self, config: dict):
        if not isinstance(config, dict):
            raise ValueError("rule config must be object")
        self.name = str(config.get("name", "")).strip()
        self.metric = str(config.get("metric", "")).strip()
        self.operator = str(config.get("operator", "")).strip()
        self.threshold = config.get("threshold")
        self.action = str(config.get("action", "log")).strip() or "log"
        self.cooldown_minutes = int(config.get("cooldown_minutes", 60))
        self.enabled = bool(config.get("enabled", True))
        self._validate()

    def _validate(self) -> None:
        if not self.name:
            raise ValueError("name is required")
        if self.metric not in self.METRICS:
            raise ValueError("invalid metric")
        if self.operator not in self.OPERATORS:
            raise ValueError("invalid operator")
        if self.action not in self.ACTIONS:
            raise ValueError("invalid action")
        if self.cooldown_minutes < 0:
            raise ValueError("cooldown_minutes must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "metric": self.metric,
            "operator": self.operator,
            "threshold": self.threshold,
            "action": self.action,
            "cooldown_minutes": self.cooldown_minutes,
            "enabled": self.enabled,
        }


class AlertRulesEngine:
    """Evaluates alert rules against current metrics."""

    def __init__(self, rules: list[AlertRule]):
        self._rules = list(rules)
        self._fired: dict[str, float] = {}

    @staticmethod
    def _as_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _match(self, rule: AlertRule, value: Any) -> bool:
        if rule.operator == "contains":
            if isinstance(value, str):
                return str(rule.threshold) in value
            if isinstance(value, (list, tuple, set)):
                return rule.threshold in value
            return False

        left = self._as_float(value)
        right = self._as_float(rule.threshold)
        if left is None or right is None:
            return False
        if rule.operator == "gt":
            return left > right
        if rule.operator == "lt":
            return left < right
        if rule.operator == "eq":
            return left == right
        if rule.operator == "gte":
            return left >= right
        if rule.operator == "lte":
            return left <= right
        return False

    def evaluate(self, metrics: dict) -> list[dict]:
        """Evaluate all rules. Returns list of fired alerts."""
        now = time.time()
        source = metrics if isinstance(metrics, dict) else {}
        fired: list[dict[str, Any]] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            value = source.get(rule.metric)
            if not self._match(rule, value):
                continue
            cooldown_s = max(0, int(rule.cooldown_minutes)) * 60
            last_ts = float(self._fired.get(rule.name, 0.0) or 0.0)
            if cooldown_s > 0 and last_ts > 0.0 and (now - last_ts) < cooldown_s:
                continue
            self._fired[rule.name] = now
            fired.append(
                {
                    "rule": rule.name,
                    "metric": rule.metric,
                    "operator": rule.operator,
                    "threshold": rule.threshold,
                    "value": value,
                    "action": rule.action,
                    "timestamp": now,
                }
            )
        return fired

    def add_rule(self, config: dict) -> AlertRule:
        """Add new rule at runtime."""
        rule = AlertRule(config)
        for current in self._rules:
            if current.name == rule.name:
                raise ValueError("rule already exists")
        self._rules.append(rule)
        return rule

    def remove_rule(self, name: str) -> bool:
        """Remove rule by name."""
        target = str(name)
        before = len(self._rules)
        self._rules = [item for item in self._rules if item.name != target]
        self._fired.pop(target, None)
        return len(self._rules) < before

    def list_rules(self) -> list[dict]:
        """List all rules with status."""
        rows: list[dict[str, Any]] = []
        for rule in self._rules:
            row = rule.to_dict()
            row["last_fired_ts"] = self._fired.get(rule.name)
            rows.append(row)
        rows.sort(key=lambda item: str(item.get("name", "")))
        return rows
