"""Orchesis policy guard for stress-test tool calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchesis.config import load_policy  # type: ignore  # noqa: E402
from orchesis.contrib.pii_detector import PiiDetector  # type: ignore  # noqa: E402
from orchesis.contrib.secret_scanner import SecretScanner  # type: ignore  # noqa: E402
from orchesis.engine import PolicyEngine  # type: ignore  # noqa: E402


def _translate_policy(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert stress-test policy shape into engine-compatible rules."""
    policy: dict[str, Any] = {"rules": []}

    tool_access = raw.get("tool_access")
    if isinstance(tool_access, dict):
        policy["tool_access"] = tool_access

    denied_paths = raw.get("denied_paths")
    if isinstance(denied_paths, list):
        policy["rules"].append({"name": "file_access", "denied_paths": denied_paths})

    denied_ops = raw.get("denied_operations")
    if isinstance(denied_ops, list):
        policy["rules"].append({"name": "sql_restriction", "denied_operations": denied_ops})

    max_per_min = raw.get("rate_limit_per_minute")
    if isinstance(max_per_min, int):
        policy["rules"].append({"name": "rate_limit", "max_requests_per_minute": max_per_min})

    daily_budget = raw.get("daily_budget")
    if isinstance(daily_budget, int | float):
        policy["rules"].append(
            {"name": "budget_limit", "max_cost_per_call": float(daily_budget), "daily_budget": float(daily_budget)}
        )

    return policy


class OrchesisToolGuard:
    """Evaluate tool call with Orchesis before execution."""

    def __init__(self, policy_path: Path):
        raw_policy = load_policy(policy_path)
        translated = _translate_policy(raw_policy)
        self._engine = PolicyEngine(translated)
        self._denied_paths = [str(item) for item in raw_policy.get("denied_paths", []) if isinstance(item, str)]
        self._denied_ops = [str(item).upper() for item in raw_policy.get("denied_operations", []) if isinstance(item, str)]
        self._secret_enabled = bool((raw_policy.get("secret_scanning") or {}).get("enabled", False))
        self._pii_enabled = bool((raw_policy.get("pii_detection") or {}).get("enabled", False))
        self._block_on_secret = bool((raw_policy.get("secret_scanning") or {}).get("block_on_detection", True))
        self._secret_scanner = SecretScanner()
        self._pii_detector = PiiDetector(severity_threshold="low")

    def evaluate(self, tool_name: str, params: dict[str, Any]) -> tuple[bool, str]:
        path_value = str(params.get("path", "")) if isinstance(params, dict) else ""
        normalized_path = path_value.replace("\\", "/")
        for denied in self._denied_paths:
            if denied and denied in normalized_path:
                return False, f"denied_paths: '{path_value}' matched '{denied}'"

        query_value = str(params.get("query", "")) if isinstance(params, dict) else ""
        query_upper = query_value.upper()
        for op in self._denied_ops:
            if op and op in query_upper:
                return False, f"denied_operations: '{op}' detected in query"

        request = {
            "tool": tool_name,
            "params": params,
            "cost": 0.0,
            "context": {"agent": "stress-test-agent", "session": "stress-test"},
        }
        decision = self._engine.evaluate(request, session_type="cli")
        if not decision.allowed:
            reason = decision.reasons[0] if decision.reasons else "blocked_by_policy"
            return False, reason

        payload_text = json.dumps(params, ensure_ascii=False)
        if self._secret_enabled and self._block_on_secret:
            if self._secret_scanner.scan_text(payload_text):
                return False, "secret_scanning: secret detected in tool call parameters"
        if self._pii_enabled:
            if self._pii_detector.scan_text(payload_text):
                return False, "pii_detection: pii detected in tool call parameters"
        return True, "allowed"
