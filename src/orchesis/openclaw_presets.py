"""OpenClaw integration policy presets."""

from __future__ import annotations

import copy
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

OPENCLAW_SAFE_POLICY: dict[str, Any] = {
    "threat_intel": {
        "enabled": True,
        "default_action": "warn",
        "disabled_threats": ["ORCH-TA-002"],
        "severity_actions": {
            "critical": "warn",
            "high": "warn",
            "medium": "log",
            "low": "log",
        },
    },
    "loop_detection": {
        "enabled": True,
        "openclaw_memory_whitelist": True,
    },
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
        "semantic_cache": {
            "enabled": True,
            "similarity_threshold": 0.85,
        },
        "recording": {
            "enabled": True,
        },
        "loop_detection": {
            "enabled": True,
            "warn_threshold": 3,
            "block_threshold": 5,
            "openclaw_memory_whitelist": True,
        },
        "threat_intel": {
            "enabled": True,
            "disabled_threats": ["ORCH-TA-002"],
            "default_action": "warn",
            "severity_actions": {
                "critical": "warn",
                "high": "warn",
                "medium": "log",
                "low": "log",
            },
        },
        "adaptive_detection": {
            "enabled": True,
        },
        "cascade": {
            "respect_client_tokens": True,
        },
    }


def apply_openclaw_preset(policy: dict[str, Any]) -> dict[str, Any]:
    """Merge OpenClaw-safe settings into policy."""
    merged = copy.deepcopy(policy if isinstance(policy, dict) else {})
    for key, value in OPENCLAW_SAFE_POLICY.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            target = merged.get(key)
            if isinstance(target, dict):
                target.update(copy.deepcopy(value))
                merged[key] = target
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def get_named_preset(name: str) -> dict[str, Any]:
    normalized = str(name or "").strip().lower()
    if normalized == "openclaw":
        return get_openclaw_preset()
    raise ValueError(f"Unknown preset: {name}")
