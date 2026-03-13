"""Per-tool policy engine for granular tool controls."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fnmatch
import json
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass
class ToolDecision:
    """Result of evaluating a tool call."""

    tool_name: str
    action: str
    reason: str
    rule_source: str


class ToolPolicyEngine:
    """Per-tool policy evaluation engine."""

    def __init__(self, config: dict):
        cfg = config if isinstance(config, dict) else {}
        self.default_action = str(cfg.get("default_action", "deny") or "deny").strip().lower()
        if self.default_action not in {"allow", "block", "deny", "approve", "warn"}:
            self.default_action = "deny"
        raw_rules = cfg.get("rules")
        self._rules = raw_rules if isinstance(raw_rules, dict) else {}
        allowed = cfg.get("allowed")
        self._allowed_legacy = set(str(x) for x in allowed) if isinstance(allowed, list) else set()
        self._lock = threading.Lock()
        self._usage_by_session: dict[str, dict[str, int]] = {}
        self._usage_by_agent: dict[str, dict[str, int]] = {}
        self._tool_stats: dict[str, dict[str, Any]] = {}
        self._blocked_attempts: list[dict[str, Any]] = []

    @staticmethod
    def _normalize_action(value: str) -> str:
        action = str(value or "").strip().lower()
        if action == "deny":
            return "block"
        if action not in {"allow", "block", "approve", "warn"}:
            return "block"
        return action

    @staticmethod
    def _parse_args(tool_args: Any) -> dict[str, Any]:
        if isinstance(tool_args, dict):
            return tool_args
        if isinstance(tool_args, str):
            try:
                data = json.loads(tool_args)
                if isinstance(data, dict):
                    return data
            except Exception:
                return {}
        return {}

    @staticmethod
    def _extract_domain(args: dict[str, Any]) -> str:
        for key in ("url", "domain", "host", "endpoint"):
            value = args.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname.lower()
            return value.strip().lower()
        return ""

    @staticmethod
    def _blocked_domain(host: str, patterns: list[str]) -> bool:
        safe_host = str(host or "").lower().strip()
        if not safe_host:
            return False
        for pattern in patterns:
            p = str(pattern or "").lower().strip()
            if not p:
                continue
            if fnmatch.fnmatch(safe_host, p):
                return True
        return False

    def _record_blocked(self, tool_name: str, agent_id: str, session_id: str, reason: str) -> None:
        with self._lock:
            self._blocked_attempts.append(
                {
                    "timestamp": time.time(),
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "reason": reason,
                }
            )
            if len(self._blocked_attempts) > 500:
                self._blocked_attempts = self._blocked_attempts[-500:]

    def evaluate(
        self,
        tool_name: str,
        agent_id: str,
        tool_args: dict | str | None = None,
        session_id: str | None = None,
    ) -> ToolDecision:
        tool = str(tool_name or "").strip()
        agent = str(agent_id or "unknown")
        session = str(session_id or "default")
        args = self._parse_args(tool_args)
        with self._lock:
            self._tool_stats.setdefault(
                tool,
                {"usage_count": 0, "block_count": 0, "approve_count": 0, "warn_count": 0, "allow_count": 0, "top_users": {}},
            )
        rule = self._rules.get(tool)
        if isinstance(rule, str):
            action = self._normalize_action(rule)
            if action == "block":
                with self._lock:
                    self._tool_stats[tool]["block_count"] += 1
                self._record_blocked(tool, agent, session, "explicit block rule")
            return ToolDecision(
                tool_name=tool,
                action=action,
                reason=f"explicit action '{action}'",
                rule_source="explicit_rule",
            )
        if isinstance(rule, dict):
            action = self._normalize_action(str(rule.get("action", self.default_action)))
            max_per_session = rule.get("max_per_session")
            if isinstance(max_per_session, int | float) and int(max_per_session) > 0:
                with self._lock:
                    session_usage = self._usage_by_session.setdefault(session, {})
                    current = int(session_usage.get(tool, 0))
                if current >= int(max_per_session):
                    with self._lock:
                        self._tool_stats[tool]["block_count"] += 1
                    self._record_blocked(tool, agent, session, "max_per_session exceeded")
                    return ToolDecision(
                        tool_name=tool,
                        action="block",
                        reason=f"max_per_session exceeded ({current}/{int(max_per_session)})",
                        rule_source="rate_limit",
                    )
            blocked_domains = rule.get("blocked_domains")
            if isinstance(blocked_domains, list):
                host = self._extract_domain(args)
                if host and self._blocked_domain(host, [str(x) for x in blocked_domains]):
                    with self._lock:
                        self._tool_stats[tool]["block_count"] += 1
                    self._record_blocked(tool, agent, session, f"blocked domain '{host}'")
                    return ToolDecision(
                        tool_name=tool,
                        action="block",
                        reason=f"blocked domain '{host}'",
                        rule_source="domain_block",
                    )
            if action == "block":
                with self._lock:
                    self._tool_stats[tool]["block_count"] += 1
                self._record_blocked(tool, agent, session, "explicit block rule")
            elif action == "approve":
                with self._lock:
                    self._tool_stats[tool]["approve_count"] += 1
            elif action == "warn":
                with self._lock:
                    self._tool_stats[tool]["warn_count"] += 1
            else:
                with self._lock:
                    self._tool_stats[tool]["allow_count"] += 1
            return ToolDecision(
                tool_name=tool,
                action=action,
                reason=f"rule action '{action}'",
                rule_source="explicit_rule",
            )
        if self._allowed_legacy:
            if tool in self._allowed_legacy:
                with self._lock:
                    self._tool_stats[tool]["allow_count"] += 1
                return ToolDecision(tool_name=tool, action="allow", reason="legacy allowed list", rule_source="legacy_allowed")
            with self._lock:
                self._tool_stats[tool]["block_count"] += 1
            self._record_blocked(tool, agent, session, "not in legacy allowed list")
            return ToolDecision(
                tool_name=tool,
                action="block",
                reason="tool not in allowed list",
                rule_source="default_action",
            )
        action = self._normalize_action(self.default_action)
        if action == "block":
            with self._lock:
                self._tool_stats[tool]["block_count"] += 1
            self._record_blocked(tool, agent, session, "default action block")
        else:
            with self._lock:
                self._tool_stats[tool]["allow_count"] += 1
        return ToolDecision(
            tool_name=tool,
            action=action,
            reason=f"default_action '{self.default_action}'",
            rule_source="default_action",
        )

    def record_usage(self, tool_name: str, agent_id: str, session_id: str) -> None:
        tool = str(tool_name or "").strip()
        agent = str(agent_id or "unknown")
        session = str(session_id or "default")
        with self._lock:
            session_usage = self._usage_by_session.setdefault(session, {})
            session_usage[tool] = int(session_usage.get(tool, 0)) + 1
            agent_usage = self._usage_by_agent.setdefault(agent, {})
            agent_usage[tool] = int(agent_usage.get(tool, 0)) + 1
            stats = self._tool_stats.setdefault(
                tool,
                {"usage_count": 0, "block_count": 0, "approve_count": 0, "warn_count": 0, "allow_count": 0, "top_users": {}},
            )
            stats["usage_count"] = int(stats.get("usage_count", 0)) + 1
            top_users = stats.setdefault("top_users", {})
            top_users[agent] = int(top_users.get(agent, 0)) + 1

    def get_tool_stats(self) -> dict:
        with self._lock:
            return {
                "tools": {name: dict(values) for name, values in self._tool_stats.items()},
                "sessions_tracked": len(self._usage_by_session),
                "agents_tracked": len(self._usage_by_agent),
            }

    def get_blocked_attempts(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._blocked_attempts]

    def get_blocked_attempts_asdict(self) -> list[dict]:
        return [asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in self.get_blocked_attempts()]

