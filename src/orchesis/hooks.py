"""IDE hook integration for Claude Code and hook policy checks."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
from typing import Any

from orchesis.error_responses import ErrorResponseBuilder


DEFAULT_POLICY_PATH = Path.home() / ".orchesis" / "policy.yaml"
DEFAULT_LOG_PATH = Path.home() / ".orchesis" / "hooks.log"
_RATE_LOCK = threading.Lock()
_RATE_WINDOWS: dict[str, list[float]] = {}

DEFAULT_POLICY_TEXT = """# Simple policy for Claude Code hooks

rules:
  # Block destructive shell commands
  - tool: shell
    pattern: "rm\\s+-rf"
    action: deny
    message: "Destructive command blocked"

  - tool: shell
    pattern: "DROP\\s+TABLE|DROP\\s+DATABASE"
    action: deny
    message: "SQL destructive command blocked"

  # Warn on sensitive file access
  - tool: file_read
    pattern: "\\.env|\\.secret|credentials|id_rsa"
    action: warn
    message: "Accessing sensitive file"

  # Block external network in MCP
  - tool: mcp
    pattern: "https?://(?!localhost|127\\.0\\.0\\.1)"
    action: warn
    message: "External network access detected"

  # Rate limit
  max_tool_calls_per_minute: 60

  # Logging
  log_file: ~/.orchesis/hooks.log
  log_format: jsonl
"""


@dataclass
class HookResult:
    success: bool
    message: str
    hooks_registered: int


def ensure_default_hook_policy(path: Path | None = None) -> Path:
    target = path or DEFAULT_POLICY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text(DEFAULT_POLICY_TEXT, encoding="utf-8")
    return target


def _coerce_dict(data: Any) -> dict[str, Any]:
    return data if isinstance(data, dict) else {}


def _parse_simple_policy(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    max_per_min = 60
    log_file = str(DEFAULT_LOG_PATH)
    log_format = "jsonl"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- tool:"):
            if current:
                rules.append(current)
            current = {"tool": line.split(":", 1)[1].strip().strip('"').strip("'")}
            continue
        if current is not None and line.startswith("pattern:"):
            current["pattern"] = line.split(":", 1)[1].strip().strip('"').strip("'")
            continue
        if current is not None and line.startswith("action:"):
            current["action"] = line.split(":", 1)[1].strip().strip('"').strip("'").lower()
            continue
        if current is not None and line.startswith("message:"):
            current["message"] = line.split(":", 1)[1].strip().strip('"').strip("'")
            continue
        if line.startswith("max_tool_calls_per_minute:"):
            value = line.split(":", 1)[1].strip()
            try:
                max_per_min = max(1, int(value))
            except Exception:
                max_per_min = 60
        if line.startswith("log_file:"):
            log_file = os.path.expanduser(line.split(":", 1)[1].strip().strip('"').strip("'"))
        if line.startswith("log_format:"):
            log_format = line.split(":", 1)[1].strip().strip('"').strip("'")
    if current:
        rules.append(current)
    return {"rules": rules, "max_tool_calls_per_minute": max_per_min, "log_file": log_file, "log_format": log_format}


def _check_rate_limit(scope_key: str, max_per_minute: int) -> tuple[bool, int]:
    now = time.time()
    with _RATE_LOCK:
        bucket = _RATE_WINDOWS.setdefault(str(scope_key), [])
        cutoff = now - 60.0
        bucket[:] = [ts for ts in bucket if ts >= cutoff]
        if len(bucket) >= max_per_minute:
            return False, len(bucket)
        bucket.append(now)
        return True, len(bucket)


def evaluate_hook_tool(tool_name: str, tool_input: str, config_path: str | None = None) -> tuple[int, str]:
    path = Path(os.path.expanduser(config_path)) if isinstance(config_path, str) and config_path.strip() else ensure_default_hook_policy()
    if not path.exists():
        ensure_default_hook_policy(path)
    policy = _parse_simple_policy(path)
    max_per_minute = int(policy.get("max_tool_calls_per_minute", 60) or 60)
    scope = f"{path.resolve()}::{tool_name}"
    allowed, current_count = _check_rate_limit(scope, max_per_minute)
    if not allowed:
        err = ErrorResponseBuilder.build(
            "rate_limited",
            agent="hook-agent",
            current=current_count,
            max=max_per_minute,
            window="60s",
            retry_after=60,
        )
        return 1, ErrorResponseBuilder.to_hook_output(err)
    payload = str(tool_input or "")
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            continue
        tool = str(rule.get("tool", "")).strip().lower()
        if tool and tool != str(tool_name).strip().lower():
            continue
        pattern = str(rule.get("pattern", "") or "")
        action = str(rule.get("action", "allow") or "allow").strip().lower()
        if not pattern:
            continue
        if re.search(pattern, payload, flags=re.IGNORECASE):
            message = str(rule.get("message", "Policy match"))
            if action == "deny":
                err = ErrorResponseBuilder.build(
                    "tool_blocked",
                    tool=tool_name,
                    agent="hook-agent",
                    allowed="see ~/.orchesis/policy.yaml",
                )
                err.reason = message
                return 1, ErrorResponseBuilder.to_hook_output(err)
            if action == "warn":
                err = ErrorResponseBuilder.build(
                    "unknown",
                    reason=message,
                    suggestion="Review the warning and continue only if expected.",
                    severity="low",
                    detector="hooks",
                    code="ORCH-HOOK-WARN",
                )
                return 0, ErrorResponseBuilder.to_hook_output(err)
            return 0, "ALLOW"
    return 0, "ALLOW"


def log_hook_tool(tool_name: str, tool_output: str, config_path: str | None = None) -> tuple[bool, str]:
    path = Path(os.path.expanduser(config_path)) if isinstance(config_path, str) and config_path.strip() else ensure_default_hook_policy()
    policy = _parse_simple_policy(path)
    log_file = Path(os.path.expanduser(str(policy.get("log_file", str(DEFAULT_LOG_PATH)))))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "tool": str(tool_name or ""),
        "output_preview": str(tool_output or "")[:400],
    }
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return True, str(log_file)


class ClaudeCodeHooks:
    """Register Orchesis as PreToolUse/PostToolUse hook in Claude Code."""

    CLAUDE_SETTINGS_PATHS = [
        Path.home() / ".claude" / "settings.json",
        Path.home() / ".claude" / "settings.local.json",
    ]

    PRE_HOOK = {
        "matcher": ".*",
        "hook": "orchesis hook-check --tool $TOOL_NAME --input $TOOL_INPUT",
    }
    POST_HOOK = {
        "matcher": ".*",
        "hook": "orchesis hook-log --tool $TOOL_NAME --output $TOOL_OUTPUT",
    }

    def install(self) -> HookResult:
        path = self._find_settings(create_if_missing=True)
        if path is None:
            return HookResult(False, "Claude Code settings not found", 0)
        settings = self._read_settings(path)
        hooks = _coerce_dict(settings.get("hooks"))
        pre = hooks.get("PreToolUse")
        post = hooks.get("PostToolUse")
        pre_list = list(pre) if isinstance(pre, list) else []
        post_list = list(post) if isinstance(post, list) else []
        added = 0
        if not any(isinstance(item, dict) and str(item.get("hook", "")).startswith("orchesis hook-check") for item in pre_list):
            pre_list.append(dict(self.PRE_HOOK))
            added += 1
        if not any(isinstance(item, dict) and str(item.get("hook", "")).startswith("orchesis hook-log") for item in post_list):
            post_list.append(dict(self.POST_HOOK))
            added += 1
        hooks["PreToolUse"] = pre_list
        hooks["PostToolUse"] = post_list
        settings["hooks"] = hooks
        self._write_settings(path, settings)
        ensure_default_hook_policy()
        return HookResult(True, f"Hooks installed in {path}", added)

    def uninstall(self) -> HookResult:
        path = self._find_settings(create_if_missing=False)
        if path is None or not path.exists():
            return HookResult(True, "No settings file found", 0)
        settings = self._read_settings(path)
        hooks = _coerce_dict(settings.get("hooks"))
        removed = 0
        for key, prefix in (("PreToolUse", "orchesis hook-check"), ("PostToolUse", "orchesis hook-log")):
            rows = hooks.get(key)
            if not isinstance(rows, list):
                continue
            kept = []
            for item in rows:
                hook_cmd = str(item.get("hook", "")) if isinstance(item, dict) else ""
                if hook_cmd.startswith(prefix):
                    removed += 1
                    continue
                kept.append(item)
            hooks[key] = kept
        settings["hooks"] = hooks
        self._write_settings(path, settings)
        return HookResult(True, f"Hooks removed from {path}", removed)

    def status(self) -> dict:
        path = self._find_settings(create_if_missing=False)
        if path is None or not path.exists():
            return {"installed": False, "path": None, "hooks_registered": 0}
        settings = self._read_settings(path)
        hooks = _coerce_dict(settings.get("hooks"))
        count = 0
        pre = hooks.get("PreToolUse", [])
        post = hooks.get("PostToolUse", [])
        if isinstance(pre, list) and any(isinstance(item, dict) and str(item.get("hook", "")).startswith("orchesis hook-check") for item in pre):
            count += 1
        if isinstance(post, list) and any(isinstance(item, dict) and str(item.get("hook", "")).startswith("orchesis hook-log") for item in post):
            count += 1
        return {"installed": count == 2, "path": str(path), "hooks_registered": count}

    def _find_settings(self, create_if_missing: bool = False) -> Path | None:
        for candidate in self.CLAUDE_SETTINGS_PATHS:
            if candidate.exists():
                return candidate
        if create_if_missing:
            target = self.CLAUDE_SETTINGS_PATHS[0]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}", encoding="utf-8")
            return target
        return None

    @staticmethod
    def _read_settings(path: Path) -> dict:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    def _write_settings(self, path: Path, settings: dict) -> None:
        if path.exists():
            self._backup_settings(path)
        path.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _backup_settings(path: Path) -> Path:
        backup = path.with_name(f"{path.name}.bak.{int(time.time())}")
        shutil.copy2(path, backup)
        return backup

