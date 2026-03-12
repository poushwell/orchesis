"""OpenClaw integration policy presets."""

from __future__ import annotations

from typing import Any


OPENCLAW_TOOL_ALLOWLIST: set[str] = {
    "read",
    "write",
    "edit",
    "multi_edit",
    "glob",
    "grep",
    "ls",
    "apply_patch",
    "session_status",
    "new_session",
    "sessions_list",
    "sessions_spawn",
    "memory_search",
    "memory_add",
    "memory_delete",
    "web_search",
    "web_fetch",
    "execute",
    "exec",
    "run",
    "cron",
    "cron_list",
    "cron_delete",
    "time",
    "browser_navigate",
    "browser_screenshot",
}


def get_openclaw_preset() -> dict[str, Any]:
    """Return a policy preset optimized for OpenClaw integration."""

    capabilities = [
        {
            "tool": name,
            "allow": {
                "paths": ["*"],
                "domains": ["*"],
                "commands": ["*"],
            },
        }
        for name in sorted(OPENCLAW_TOOL_ALLOWLIST)
    ]
    return {
        "default_action": "allow",
        "capabilities": capabilities,
        "threat_intel": {
            "enabled": True,
            "disabled_threats": ["ORCH-TA-002"],
            "default_action": "warn",
            "severity_actions": {"critical": "warn", "high": "warn", "medium": "log"},
        },
        "cascade": {
            "respect_client_tokens": True,
        },
    }


def get_named_preset(name: str) -> dict[str, Any]:
    normalized = str(name or "").strip().lower()
    if normalized == "openclaw":
        return get_openclaw_preset()
    raise ValueError(f"Unknown preset: {name}")
