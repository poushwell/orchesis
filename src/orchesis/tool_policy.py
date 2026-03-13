"""Per-tool policy engine for granular tool controls."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import json
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse
import uuid


@dataclass
class ToolDecision:
    """Result of evaluating a tool call."""

    tool_name: str
    action: str
    reason: str
    rule_source: str
    approval_id: str = ""


class ApprovalQueue:
    """Pending actions waiting for human approval."""

    def __init__(self, max_pending: int = 100):
        self._pending: dict[str, dict[str, Any]] = {}
        self._approved: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_pending = max(1, int(max_pending))
        self._approved_count = 0
        self._denied_count = 0
        self._total_wait_seconds = 0.0
        self._handled = 0

    def add(
        self,
        request_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: dict,
        reason: str,
    ) -> str:
        approval_id = str(request_id or uuid.uuid4().hex)
        payload = {
            "approval_id": approval_id,
            "timestamp": time.time(),
            "agent_id": str(agent_id or "unknown"),
            "tool_name": str(tool_name or ""),
            "tool_args": tool_args if isinstance(tool_args, dict) else {},
            "reason": str(reason or "manual approval required"),
        }
        with self._lock:
            self._pending[approval_id] = payload
            if len(self._pending) > self._max_pending:
                oldest = sorted(self._pending.values(), key=lambda item: float(item.get("timestamp", 0.0)))[0]
                self._pending.pop(str(oldest.get("approval_id", "")), None)
        return approval_id

    def approve(self, request_id: str) -> bool:
        key = str(request_id or "")
        if not key:
            return False
        with self._lock:
            item = self._pending.pop(key, None)
            if item is None:
                return False
            now = time.time()
            self._approved[key] = now
            self._approved_count += 1
            self._handled += 1
            self._total_wait_seconds += max(0.0, now - float(item.get("timestamp", now)))
            if len(self._approved) > self._max_pending * 10:
                self._approved = dict(sorted(self._approved.items(), key=lambda kv: kv[1])[-self._max_pending * 5 :])
            return True

    def deny(self, request_id: str) -> bool:
        key = str(request_id or "")
        if not key:
            return False
        with self._lock:
            item = self._pending.pop(key, None)
            if item is None:
                return False
            now = time.time()
            self._denied_count += 1
            self._handled += 1
            self._total_wait_seconds += max(0.0, now - float(item.get("timestamp", now)))
            return True

    def consume_approved(self, request_id: str) -> bool:
        key = str(request_id or "")
        if not key:
            return False
        with self._lock:
            return self._approved.pop(key, None) is not None

    def get_pending(self) -> list[dict]:
        with self._lock:
            rows = [dict(item) for item in self._pending.values()]
        rows.sort(key=lambda item: float(item.get("timestamp", 0.0)))
        return rows

    def get_stats(self) -> dict:
        with self._lock:
            avg_wait = (self._total_wait_seconds / float(self._handled)) if self._handled > 0 else 0.0
            return {
                "pending_count": len(self._pending),
                "approved_count": int(self._approved_count),
                "denied_count": int(self._denied_count),
                "avg_wait_seconds": round(avg_wait, 3),
            }


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
        self.approval_queue = ApprovalQueue(max_pending=int(cfg.get("max_pending_approvals", 100)))

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
        request_id: str | None = None,
        approval_id: str | None = None,
    ) -> ToolDecision:
        tool = str(tool_name or "").strip()
        agent = str(agent_id or "unknown")
        session = str(session_id or "default")
        args = self._parse_args(tool_args)
        provided_approval_id = str(approval_id or "")
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
            if action == "approve":
                if provided_approval_id and self.approval_queue.consume_approved(provided_approval_id):
                    with self._lock:
                        self._tool_stats[tool]["allow_count"] += 1
                    return ToolDecision(
                        tool_name=tool,
                        action="allow",
                        reason=f"approval '{provided_approval_id}' consumed",
                        rule_source="approval_queue",
                        approval_id=provided_approval_id,
                    )
                approval = self.approval_queue.add(
                    request_id=str(request_id or ""),
                    agent_id=agent,
                    tool_name=tool,
                    tool_args=args,
                    reason="explicit approval rule",
                )
                return ToolDecision(
                    tool_name=tool,
                    action="approve",
                    reason="pending human approval",
                    rule_source="approval_queue",
                    approval_id=approval,
                )
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
                if provided_approval_id and self.approval_queue.consume_approved(provided_approval_id):
                    with self._lock:
                        self._tool_stats[tool]["allow_count"] += 1
                    return ToolDecision(
                        tool_name=tool,
                        action="allow",
                        reason=f"approval '{provided_approval_id}' consumed",
                        rule_source="approval_queue",
                        approval_id=provided_approval_id,
                    )
                with self._lock:
                    self._tool_stats[tool]["approve_count"] += 1
                approval = self.approval_queue.add(
                    request_id=str(request_id or ""),
                    agent_id=agent,
                    tool_name=tool,
                    tool_args=args,
                    reason=f"rule action '{action}'",
                )
                return ToolDecision(
                    tool_name=tool,
                    action="approve",
                    reason="pending human approval",
                    rule_source="approval_queue",
                    approval_id=approval,
                )
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
            approval_stats = self.approval_queue.get_stats()
            return {
                "tools": {name: dict(values) for name, values in self._tool_stats.items()},
                "sessions_tracked": len(self._usage_by_session),
                "agents_tracked": len(self._usage_by_agent),
                "approvals": approval_stats,
            }

    def get_blocked_attempts(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._blocked_attempts]

