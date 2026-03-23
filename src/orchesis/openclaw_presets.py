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

# Research-backed detection pattern catalog (metadata + matchers for operators / future engines).
OPENCLAW_DETECTION_PATTERNS: dict[str, dict[str, Any]] = {
    "exec_loop_122": {
        "description": "121+ identical exec/execute/run tool calls in a sliding window (OpenClaw loop issue #34574 class).",
        "related": ["loop_detection", "tool_chain"],
        "matchers": [
            r"(?i)\b(exec|execute|run)\b",
        ],
        "recommended_exact_threshold": 121,
    },
    "skill_marketplace_injection": {
        "description": "Malicious or override-style instructions embedded in marketplace skill descriptions (#30448 class).",
        "related": ["prompt_injection", "mcp", "skills"],
        "matchers": [
            r"(?i)ignore (all|previous) (instructions|rules)",
            r"(?i)system\s*override",
            r"(?i)you are now",
            r"(?i)disregard (the )?policy",
        ],
    },
    "budget_zero_codex": {
        "description": "Codex-style fleets reporting $0.00 remaining budget while spend continues (accounting / policy drift).",
        "related": ["budgets", "cost_tracker", "spend_rate"],
        "matchers": [
            r"(?i)\$0\.00\b",
            r"(?i)remaining[^\n]{0,40}0\.00",
            r"(?i)budget[^\n]{0,40}exhausted",
        ],
    },
    "elevated_sandbox_bypass": {
        "description": "Sandbox disabled or weakened while privileged tools or elevated roles are enabled.",
        "related": ["sandbox", "capabilities", "tool_access"],
        "matchers": [
            r"(?i)sandbox\s*[:=]\s*(off|false|disabled)",
            r"(?i)dangerously_?skip_?permissions",
            r"(?i)elevated\s*[:=]\s*true",
        ],
    },
    "session_hijack_via_header": {
        "description": "Forged or duplicated OpenClaw session headers to hijack another agent session.",
        "related": ["headers", "session"],
        "matchers": [
            r"(?i)x-openclaw-session-id",
            r"(?i)x-openclaw-session\b",
        ],
    },
    "paperclip_dangerously_skip_permissions": {
        "description": "Paperclip / OpenClaw adapter configs with dangerouslySkipPermissions (MCP scanner paperclip_config).",
        "related": ["paperclip_config", "mcp_scanner"],
        "matchers": [
            r"(?i)dangerouslySkipPermissions",
            r"(?i)dangerously_skip_permissions",
        ],
    },
}

PRESET_NAMES: frozenset[str] = frozenset({"openclaw", "paperclip"})

# Top-level keys commonly produced by presets or accepted by load_policy / engine (extension keys included).
ALLOWED_PRESET_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "default_action",
        "capabilities",
        "semantic_cache",
        "recording",
        "loop_detection",
        "threat_intel",
        "adaptive_detection",
        "cascade",
        "openclaw",
        "paperclip",
        "model_routing",
        "denied_paths",
        "rules",
        "tool_access",
        "budgets",
        "tool_costs",
        "proxy",
        "kill_switch",
        "circuit_breaker",
        "behavioral_fingerprint",
        "flow_xray",
        "experiments",
        "task_tracking",
        "compliance",
        "alerts",
        "session_risk",
        "context_engine",
        "otel_export",
        "version",
        "agents",
        "default_trust_tier",
        "preset",
        "policy",
        "name",
        "description",
    }
)

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
            "info": "log",
        },
    },
    "loop_detection": {
        "enabled": True,
        "openclaw_memory_whitelist": True,
        "openclaw_reset_commands": ["/start", "/new", "/reset"],
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
            "openclaw_reset_commands": ["/start", "/new", "/reset"],
            "content_loop": {
                "enabled": True,
                "window_seconds": 300,
                "max_identical": 5,
                "cooldown_seconds": 300,
                "hash_prefix_len": 256,
            },
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
                "info": "log",
            },
        },
        "adaptive_detection": {
            "enabled": True,
        },
        "cascade": {
            "respect_client_tokens": True,
        },
        "openclaw": {
            "primary_session_header": "x-openclaw-session-id",
            "session_headers": ["x-openclaw-session-id", "x-openclaw-session"],
            "detection_pattern_ids": [
                "exec_loop_122",
                "skill_marketplace_injection",
                "budget_zero_codex",
                "elevated_sandbox_bypass",
                "session_hijack_via_header",
            ],
        },
        "task_tracking": {
            "openclaw_session_headers": ["x-openclaw-session-id", "x-openclaw-session"],
        },
    }


def get_paperclip_preset() -> dict[str, Any]:
    """Preset for Paperclip-routed OpenClaw agents: heartbeat-tolerant loops + MCP adapter checks."""

    preset = copy.deepcopy(get_openclaw_preset())
    loop = preset.setdefault("loop_detection", {})
    content_loop = dict(loop.get("content_loop") or {})
    content_loop["enabled"] = True
    content_loop["max_identical"] = max(int(content_loop.get("max_identical", 5) or 5), 12)
    loop["content_loop"] = content_loop

    preset["model_routing"] = {
        "enabled": True,
        "default": "gpt-4o-mini",
        "heartbeat_models": {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-haiku-4-5-20251001",
            "default": "gpt-4o-mini",
        },
    }
    oc = preset.setdefault("openclaw", {})
    base_ids = list(oc.get("detection_pattern_ids") or [])
    if "paperclip_dangerously_skip_permissions" not in base_ids:
        base_ids.append("paperclip_dangerously_skip_permissions")
    oc["detection_pattern_ids"] = base_ids

    preset["paperclip"] = {
        "mcp_scanner": {
            "check_adapter_config": True,
            "check_dangerously_skip_permissions": True,
            "adapter_config_key_hints": ["adapterConfig", "adapter_config", "paperclip"],
        },
        "heartbeat_loop": {
            "content_loop_relaxed_max_identical": content_loop["max_identical"],
            "rationale": "Cron/heartbeat traffic repeats identical user messages; higher max_identical reduces false blocks.",
        },
    }
    return preset


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


def verify_preset_dict(preset: dict[str, Any]) -> list[str]:
    """Validate a preset-shaped policy mapping. Returns human-readable errors (empty if OK)."""
    errors: list[str] = []
    if not isinstance(preset, dict):
        return ["preset must be a mapping"]

    for key in preset:
        if key not in ALLOWED_PRESET_TOP_LEVEL_KEYS:
            errors.append(f"Unknown top-level policy key: {key!r}")

    oc = preset.get("openclaw")
    if isinstance(oc, dict):
        headers = oc.get("session_headers")
        if isinstance(headers, list):
            if "x-openclaw-session-id" not in headers:
                errors.append("openclaw.session_headers must include 'x-openclaw-session-id'")
        ids = oc.get("detection_pattern_ids")
        if ids is not None:
            if not isinstance(ids, list):
                errors.append("openclaw.detection_pattern_ids must be a list")
            else:
                for pid in ids:
                    if not isinstance(pid, str):
                        errors.append(f"openclaw.detection_pattern_ids entries must be strings (got {pid!r})")
                    elif pid not in OPENCLAW_DETECTION_PATTERNS:
                        errors.append(f"Unknown detection_pattern_id: {pid!r}")

    ld = preset.get("loop_detection")
    if isinstance(ld, dict):
        ex = ld.get("exact") if isinstance(ld.get("exact"), dict) else {}
        fz = ld.get("fuzzy") if isinstance(ld.get("fuzzy"), dict) else {}
        if ex and fz:
            et = ex.get("threshold")
            ft = fz.get("threshold")
            if isinstance(et, int | float) and isinstance(ft, int | float) and int(et) >= int(ft):
                errors.append("Conflicting loop_detection: exact.threshold must be < fuzzy.threshold")
        wt = ld.get("warn_threshold")
        bt = ld.get("block_threshold")
        if isinstance(wt, int | float) and isinstance(bt, int | float) and int(wt) >= int(bt):
            errors.append("Conflicting loop_detection: warn_threshold must be < block_threshold")

    return errors


def verify_preset(preset_name: str) -> list[str]:
    """Validate a named preset: patterns, keys, and non-conflicting loop thresholds."""
    normalized = str(preset_name or "").strip().lower()
    try:
        preset = get_named_preset(normalized)
    except ValueError as exc:
        return [str(exc)]
    return verify_preset_dict(preset)


def get_named_preset(name: str) -> dict[str, Any]:
    normalized = str(name or "").strip().lower()
    if normalized == "openclaw":
        return get_openclaw_preset()
    if normalized == "paperclip":
        return get_paperclip_preset()
    raise ValueError(f"Unknown preset: {name}")


PAPERCLIP_PRESET: dict[str, Any] = get_paperclip_preset()
