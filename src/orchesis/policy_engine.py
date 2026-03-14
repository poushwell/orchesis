"""Declarative YAML policy evaluator (policy-as-code)."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PolicyRule:
    id: str
    description: str
    when: dict
    action: str
    priority: int = 0


@dataclass
class PolicyEvalResult:
    action: str
    rule_id: str
    rule_description: str
    reason: str
    matched: bool


class PolicyEngine:
    """Declarative policy engine for YAML/dict policies."""

    def __init__(self, policy_dict: dict):
        payload = policy_dict if isinstance(policy_dict, dict) else {}
        default_action = str(payload.get("default_action", "deny")).strip().lower()
        if default_action == "deny":
            default_action = "block"
        if default_action not in {"allow", "block", "warn", "approve"}:
            default_action = "block"
        self._default_action = default_action

        raw_vars = payload.get("variables")
        self._variables = raw_vars if isinstance(raw_vars, dict) else {}

        self._rules: list[PolicyRule] = []
        raw_rules = payload.get("rules")
        if isinstance(raw_rules, list):
            for item in raw_rules:
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get("id", "")).strip()
                if not rule_id:
                    continue
                description = str(item.get("description", "")).strip()
                when = item.get("when")
                if not isinstance(when, dict):
                    when = {}
                action = str(item.get("action", self._default_action)).strip().lower()
                if action == "deny":
                    action = "block"
                if action not in {"allow", "block", "warn", "approve"}:
                    action = self._default_action
                priority = item.get("priority", 0)
                try:
                    parsed_priority = int(priority)
                except Exception:
                    parsed_priority = 0
                self._rules.append(
                    PolicyRule(
                        id=rule_id,
                        description=description,
                        when=when,
                        action=action,
                        priority=parsed_priority,
                    )
                )
        self._rules.sort(key=lambda r: int(r.priority), reverse=True)

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        content = Path(path).expanduser().read_text(encoding="utf-8")
        loaded = yaml.safe_load(content)
        return cls.from_dict(loaded if isinstance(loaded, dict) else {})

    @classmethod
    def from_dict(cls, policy_dict: dict) -> "PolicyEngine":
        return cls(policy_dict)

    def evaluate(
        self,
        tool_name: str,
        agent_id: str = "",
        session_calls: int = 0,
        agent_calls: int = 0,
        token_count: int = 0,
        extra: dict | None = None,
    ) -> PolicyEvalResult:
        context: dict[str, Any] = {
            "tool": str(tool_name or ""),
            "agent_id": str(agent_id or ""),
            "session_calls": int(session_calls),
            "agent_calls": int(agent_calls),
            "token_count": int(token_count),
        }
        if isinstance(extra, dict):
            context.update(extra)

        for rule in self._rules:
            if self._eval_condition(rule.when, context):
                return PolicyEvalResult(
                    action=rule.action,
                    rule_id=rule.id,
                    rule_description=rule.description,
                    reason=f"matched rule '{rule.id}'",
                    matched=True,
                )

        return PolicyEvalResult(
            action=self._default_action,
            rule_id="",
            rule_description="",
            reason="no rule matched; default_action applied",
            matched=False,
        )

    def get_rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def get_variables(self) -> dict:
        return dict(self._variables)

    def _eval_condition(self, when: dict, context: dict[str, Any]) -> bool:
        if not when:
            return False
        for field, predicate in when.items():
            key = str(field or "")
            actual = context.get(key)
            if isinstance(predicate, dict):
                if not self._eval_ops(actual, predicate):
                    return False
            else:
                if not self._op_eq(actual, predicate):
                    return False
        return True

    def _resolve_value(self, value: Any) -> Any:
        if isinstance(value, str) and value.startswith("$"):
            return self._variables.get(value[1:], [])
        return value

    def _eval_ops(self, actual: Any, ops: dict[str, Any]) -> bool:
        for op, raw_expected in ops.items():
            expected = self._resolve_value(raw_expected)
            name = str(op or "").strip().lower()
            if name == "eq":
                if not self._op_eq(actual, expected):
                    return False
            elif name == "in":
                if not self._op_in(actual, expected):
                    return False
            elif name == "not_in":
                if self._op_in(actual, expected):
                    return False
            elif name == "matches":
                if not fnmatch.fnmatch(str(actual or ""), str(expected or "")):
                    return False
            elif name == "startswith":
                if not str(actual or "").startswith(str(expected or "")):
                    return False
            elif name == "contains":
                if str(expected or "") not in str(actual or ""):
                    return False
            elif name in {"gt", "gte", "lt", "lte"}:
                if not self._op_numeric(name, actual, expected):
                    return False
            else:
                return False
        return True

    @staticmethod
    def _to_number(value: Any) -> float | None:
        try:
            return float(value)
        except Exception:
            return None

    def _op_numeric(self, op: str, actual: Any, expected: Any) -> bool:
        a = self._to_number(actual)
        b = self._to_number(expected)
        if a is None or b is None:
            return False
        if op == "gt":
            return a > b
        if op == "gte":
            return a >= b
        if op == "lt":
            return a < b
        if op == "lte":
            return a <= b
        return False

    @staticmethod
    def _op_eq(actual: Any, expected: Any) -> bool:
        if isinstance(actual, int | float) or isinstance(expected, int | float):
            try:
                return float(actual) == float(expected)
            except Exception:
                return False
        return str(actual) == str(expected)

    @staticmethod
    def _op_in(actual: Any, expected: Any) -> bool:
        if isinstance(expected, list):
            return str(actual) in [str(item) for item in expected]
        return False

