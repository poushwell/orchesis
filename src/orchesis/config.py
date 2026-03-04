"""Policy loading and validation."""

import hashlib
import logging
import posixpath
import re
import unicodedata
from urllib.parse import unquote
from pathlib import Path
from typing import Any, Callable

import yaml
from orchesis.behavioral import DEFAULT_DIMENSIONS
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier

_TOOL_RATE_LIMIT_PATTERN = re.compile(r"^\s*(\d+)\s*/\s*(second|minute|hour)\s*$", re.IGNORECASE)
_RATE_LIMIT_WINDOW_SECONDS = {"second": 1, "minute": 60, "hour": 3600}
_LOGGER = logging.getLogger(__name__)
_CAPABILITY_CONSTRAINT_KEYS = {"paths", "domains", "commands"}


class PolicyError(ValueError):
    """Raised when policy structure/content is invalid."""


def _normalize_tool_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value.replace("\x00", "")).strip().lower()
    if any(ch in normalized for ch in ("\t", "\n", "\r")):
        return ""
    return normalized


def _normalize_path_value(path: str) -> str:
    decoded = unquote(path)
    cleaned = unicodedata.normalize("NFKC", decoded.replace("\x00", "")).strip().replace("\\", "/")
    cleaned = re.sub(r"/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    normalized = posixpath.normpath(cleaned)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _parse_tool_rate_limit(value: Any) -> tuple[int, int, str]:
    if not isinstance(value, str):
        raise PolicyError("tool_access.rate_limits values must be strings like '10/minute'")
    match = _TOOL_RATE_LIMIT_PATTERN.match(value)
    if match is None:
        raise PolicyError(f"Invalid tool rate limit format: '{value}'")
    max_requests = int(match.group(1))
    unit = match.group(2).lower()
    if max_requests <= 0:
        raise PolicyError(f"Tool rate limit must be positive: '{value}'")
    window_seconds = _RATE_LIMIT_WINDOW_SECONDS.get(unit)
    if not isinstance(window_seconds, int):
        raise PolicyError(f"Unsupported tool rate limit unit in '{value}'")
    return max_requests, window_seconds, unit


def _normalize_tool_access_rate_limits(policy: dict[str, Any]) -> None:
    tool_access = policy.get("tool_access")
    if not isinstance(tool_access, dict):
        return
    raw_rate_limits = tool_access.get("rate_limits")
    if raw_rate_limits is None:
        return
    if not isinstance(raw_rate_limits, dict):
        raise PolicyError("tool_access.rate_limits must be a mapping of tool_name -> 'N/unit'")
    parsed: dict[str, dict[str, Any]] = {}
    for tool_name, value in raw_rate_limits.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise PolicyError("tool_access.rate_limits keys must be non-empty tool names")
        max_requests, window_seconds, unit = _parse_tool_rate_limit(value)
        parsed[tool_name.strip()] = {
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "unit": unit,
            "raw": f"{max_requests}/{unit}",
        }
    tool_access["_parsed_rate_limits"] = parsed


def _normalize_policy_paths(policy: dict[str, Any]) -> None:
    top_denied = policy.get("denied_paths")
    if isinstance(top_denied, list):
        policy["denied_paths"] = [
            _normalize_path_value(item)
            for item in top_denied
            if isinstance(item, str) and item.strip()
        ]

    rules = policy.get("rules")
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for key in ("denied_paths", "allowed_paths"):
                paths = rule.get(key)
                if isinstance(paths, list):
                    rule[key] = [
                        _normalize_path_value(item)
                        for item in paths
                        if isinstance(item, str) and item.strip()
                    ]

    tool_access = policy.get("tool_access")
    if isinstance(tool_access, dict):
        for key in ("allowed", "denied"):
            values = tool_access.get(key)
            if isinstance(values, list):
                tool_access[key] = [
                    _normalize_tool_name(item)
                    for item in values
                    if isinstance(item, str) and _normalize_tool_name(item)
                ]
        allowed = set(tool_access.get("allowed", [])) if isinstance(tool_access.get("allowed"), list) else set()
        denied = set(tool_access.get("denied", [])) if isinstance(tool_access.get("denied"), list) else set()
        overlap = sorted(allowed.intersection(denied))
        if overlap:
            for tool_name in overlap:
                _LOGGER.warning(
                    "tool '%s' in both allowed and denied lists - deny takes precedence",
                    tool_name,
                )


def _normalize_cost_controls(policy: dict[str, Any]) -> None:
    budgets = policy.get("budgets")
    if not isinstance(budgets, dict):
        budgets = {}
        policy["budgets"] = budgets
    daily = budgets.get("daily")
    if isinstance(daily, int | float):
        budgets["daily"] = float(daily)
    elif daily is not None:
        budgets.pop("daily", None)
    per_tool = budgets.get("per_tool")
    if isinstance(per_tool, dict):
        normalized_per_tool: dict[str, float] = {}
        for tool, value in per_tool.items():
            if isinstance(tool, str) and isinstance(value, int | float):
                normalized_per_tool[tool.strip()] = float(value)
        budgets["per_tool"] = normalized_per_tool
    elif per_tool is not None:
        budgets["per_tool"] = {}
    per_task = budgets.get("per_task")
    if isinstance(per_task, int | float):
        budgets["per_task"] = float(per_task)
    elif per_task is not None:
        budgets.pop("per_task", None)
    soft_limit_percent = budgets.get("soft_limit_percent", 80)
    if isinstance(soft_limit_percent, int | float):
        budgets["soft_limit_percent"] = float(max(0, min(100, soft_limit_percent)))
    else:
        budgets["soft_limit_percent"] = 80.0
    on_soft_limit = str(budgets.get("on_soft_limit", "notify")).strip().lower()
    if on_soft_limit not in {"notify", "downgrade_model", "throttle", "block"}:
        on_soft_limit = "notify"
    budgets["on_soft_limit"] = on_soft_limit
    on_hard_limit = str(budgets.get("on_hard_limit", "block")).strip().lower()
    if on_hard_limit not in {"block", "notify"}:
        on_hard_limit = "block"
    budgets["on_hard_limit"] = on_hard_limit

    tool_costs = policy.get("tool_costs")
    if isinstance(tool_costs, dict):
        normalized_costs: dict[str, float] = {}
        for tool, value in tool_costs.items():
            if isinstance(tool, str) and isinstance(value, int | float):
                normalized_costs[tool.strip()] = float(value)
        policy["tool_costs"] = normalized_costs
    elif tool_costs is not None:
        policy["tool_costs"] = {}

    loop_detection = policy.get("loop_detection")
    if not isinstance(loop_detection, dict):
        loop_detection = {}
        policy["loop_detection"] = loop_detection
    loop_detection["enabled"] = bool(loop_detection.get("enabled", False))
    warn_threshold = loop_detection.get("warn_threshold", 5)
    block_threshold = loop_detection.get("block_threshold", 10)
    window_seconds = loop_detection.get("window_seconds", 300)
    loop_detection["warn_threshold"] = int(warn_threshold) if isinstance(warn_threshold, int | float) else 5
    loop_detection["block_threshold"] = int(block_threshold) if isinstance(block_threshold, int | float) else 10
    loop_detection["window_seconds"] = float(window_seconds) if isinstance(window_seconds, int | float) else 300.0
    loop_detection["similarity_check"] = bool(loop_detection.get("similarity_check", True))

    model_routing = policy.get("model_routing")
    if not isinstance(model_routing, dict):
        model_routing = {}
        policy["model_routing"] = model_routing
    model_routing["enabled"] = bool(model_routing.get("enabled", False))
    model_routing["default"] = str(model_routing.get("default", "gpt-4o"))
    rules = model_routing.get("rules")
    if isinstance(rules, list):
        normalized_rules: list[dict[str, str]] = []
        for item in rules:
            if not isinstance(item, dict):
                continue
            complexity = item.get("complexity")
            model = item.get("model")
            if isinstance(complexity, str) and isinstance(model, str):
                normalized_rules.append(
                    {"complexity": complexity.strip().lower(), "model": model.strip()}
                )
        model_routing["rules"] = normalized_rules
    else:
        model_routing["rules"] = []


def _normalize_proxy_config(policy: dict[str, Any]) -> None:
    proxy_cfg = policy.get("proxy")
    if not isinstance(proxy_cfg, dict):
        policy["proxy"] = {
            "max_workers": 200,
            "connection_pool": {
                "max_per_host": 10,
                "max_total": 50,
                "idle_timeout": 60,
                "connection_timeout": 30,
                "retry_on_connection_error": True,
                "max_retries": 2,
            },
            "streaming": {
                "enabled": True,
                "buffer_size": 4096,
                "max_accumulated_events": 10000,
            },
        }
        return

    port = proxy_cfg.get("port")
    if isinstance(port, int | float):
        proxy_cfg["port"] = int(max(1, min(65535, int(port))))
    elif port is not None:
        proxy_cfg.pop("port", None)

    host = proxy_cfg.get("host")
    if isinstance(host, str):
        proxy_cfg["host"] = host.strip() or "127.0.0.1"
    elif host is not None:
        proxy_cfg.pop("host", None)

    timeout = proxy_cfg.get("timeout")
    if isinstance(timeout, int | float):
        proxy_cfg["timeout"] = float(max(1.0, timeout))
    elif timeout is not None:
        proxy_cfg.pop("timeout", None)

    cors = proxy_cfg.get("cors")
    if isinstance(cors, bool):
        proxy_cfg["cors"] = cors
    elif cors is not None:
        proxy_cfg["cors"] = bool(cors)

    upstream = proxy_cfg.get("upstream")
    if isinstance(upstream, dict):
        normalized_upstream: dict[str, str] = {}
        for key in ("anthropic", "openai"):
            value = upstream.get(key)
            if isinstance(value, str) and value.strip():
                normalized_upstream[key] = value.strip()
        proxy_cfg["upstream"] = normalized_upstream
    elif upstream is not None:
        proxy_cfg["upstream"] = {}

    max_workers = proxy_cfg.get("max_workers", 200)
    if not _is_number(max_workers) or int(max_workers) <= 0:
        raise PolicyError("proxy.max_workers must be > 0")
    proxy_cfg["max_workers"] = int(max_workers)

    pool_cfg_raw = proxy_cfg.get("connection_pool")
    pool_cfg = pool_cfg_raw if isinstance(pool_cfg_raw, dict) else {}
    max_per_host = pool_cfg.get("max_per_host", 10)
    max_total = pool_cfg.get("max_total", 50)
    idle_timeout = pool_cfg.get("idle_timeout", 60)
    connection_timeout = pool_cfg.get("connection_timeout", 30)
    max_retries = pool_cfg.get("max_retries", 2)
    if not _is_number(max_per_host) or int(max_per_host) <= 0:
        raise PolicyError("proxy.connection_pool.max_per_host must be > 0")
    if not _is_number(max_total) or int(max_total) <= 0:
        raise PolicyError("proxy.connection_pool.max_total must be > 0")
    if not _is_number(idle_timeout) or float(idle_timeout) <= 0:
        raise PolicyError("proxy.connection_pool.idle_timeout must be > 0")
    if not _is_number(connection_timeout) or float(connection_timeout) <= 0:
        raise PolicyError("proxy.connection_pool.connection_timeout must be > 0")
    if not _is_number(max_retries) or int(max_retries) < 0:
        raise PolicyError("proxy.connection_pool.max_retries must be >= 0")
    pool_cfg["max_per_host"] = int(max_per_host)
    pool_cfg["max_total"] = int(max_total)
    pool_cfg["idle_timeout"] = float(idle_timeout)
    pool_cfg["connection_timeout"] = float(connection_timeout)
    pool_cfg["retry_on_connection_error"] = bool(pool_cfg.get("retry_on_connection_error", True))
    pool_cfg["max_retries"] = int(max_retries)
    proxy_cfg["connection_pool"] = pool_cfg

    streaming_cfg_raw = proxy_cfg.get("streaming")
    streaming_cfg = streaming_cfg_raw if isinstance(streaming_cfg_raw, dict) else {}
    buffer_size = streaming_cfg.get("buffer_size", 4096)
    max_accumulated = streaming_cfg.get("max_accumulated_events", 10000)
    if not _is_number(buffer_size) or int(buffer_size) <= 0:
        raise PolicyError("proxy.streaming.buffer_size must be > 0")
    if not _is_number(max_accumulated) or int(max_accumulated) <= 0:
        raise PolicyError("proxy.streaming.max_accumulated_events must be > 0")
    streaming_cfg["enabled"] = bool(streaming_cfg.get("enabled", True))
    streaming_cfg["buffer_size"] = int(buffer_size)
    streaming_cfg["max_accumulated_events"] = int(max_accumulated)
    proxy_cfg["streaming"] = streaming_cfg


def _normalize_kill_switch(policy: dict[str, Any]) -> None:
    raw = policy.get("kill_switch")
    if raw is None:
        policy["kill_switch"] = {"enabled": False, "auto_triggers": {}, "resume_token": "orchesis-resume-2024"}
        return
    if not isinstance(raw, dict):
        raise PolicyError("kill_switch must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    resume_token = raw.get("resume_token", "orchesis-resume-2024")
    if isinstance(resume_token, str) and resume_token.strip():
        raw["resume_token"] = resume_token.strip()
    else:
        raw["resume_token"] = "orchesis-resume-2024"

    auto = raw.get("auto_triggers")
    if auto is None:
        auto = {}
    if not isinstance(auto, dict):
        raise PolicyError("kill_switch.auto_triggers must be a mapping")
    cost_multiplier = auto.get("cost_multiplier", 5)
    secrets_threshold = auto.get("secrets_threshold", 3)
    loops_threshold = auto.get("loops_threshold", 5)
    auto["cost_multiplier"] = float(cost_multiplier) if _is_number(cost_multiplier) and float(cost_multiplier) > 0 else 5.0
    auto["secrets_threshold"] = int(secrets_threshold) if _is_number(secrets_threshold) and int(secrets_threshold) > 0 else 3
    auto["loops_threshold"] = int(loops_threshold) if _is_number(loops_threshold) and int(loops_threshold) > 0 else 5
    raw["auto_triggers"] = auto
    policy["kill_switch"] = raw


def _normalize_cascade(policy: dict[str, Any]) -> None:
    raw = policy.get("cascade")
    if raw is None:
        policy["cascade"] = {"enabled": False, "levels": {}, "auto_escalate": {}, "cache": {}}
        return
    if not isinstance(raw, dict):
        raise PolicyError("cascade must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    allowed_models = {
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-nano",
        "claude-opus-4",
        "claude-sonnet-4",
        "claude-haiku-4",
    }

    levels = raw.get("levels")
    if levels is None:
        levels = {}
    if not isinstance(levels, dict):
        raise PolicyError("cascade.levels must be a mapping")
    normalized_levels: dict[str, dict[str, Any]] = {}
    for level_name in ("trivial", "simple", "medium", "complex"):
        level_cfg = levels.get(level_name)
        if not isinstance(level_cfg, dict):
            continue
        normalized_level: dict[str, Any] = {}
        action = level_cfg.get("action")
        if isinstance(action, str) and action.strip():
            normalized_level["action"] = action.strip().lower()
        model = level_cfg.get("model")
        if isinstance(model, str) and model.strip():
            model_name = model.strip()
            if model_name not in allowed_models:
                raise PolicyError(f"cascade.levels.{level_name}.model is unsupported: {model_name}")
            normalized_level["model"] = model_name
        max_tokens = level_cfg.get("max_tokens")
        if _is_number(max_tokens):
            normalized_level["max_tokens"] = int(max(1, int(max_tokens)))
        normalized_levels[level_name] = normalized_level
    raw["levels"] = normalized_levels

    auto = raw.get("auto_escalate")
    if auto is None:
        auto = {}
    if not isinstance(auto, dict):
        raise PolicyError("cascade.auto_escalate must be a mapping")
    auto["enabled"] = bool(auto.get("enabled", True))
    auto["on_error"] = bool(auto.get("on_error", True))
    auto["on_low_confidence"] = bool(auto.get("on_low_confidence", True))
    raw["auto_escalate"] = auto

    cache = raw.get("cache")
    if cache is None:
        cache = {}
    if not isinstance(cache, dict):
        raise PolicyError("cascade.cache must be a mapping")
    cache["enabled"] = bool(cache.get("enabled", True))
    ttl_seconds = cache.get("ttl_seconds", 300)
    max_entries = cache.get("max_entries", 1000)
    cache["ttl_seconds"] = int(ttl_seconds) if _is_number(ttl_seconds) and int(ttl_seconds) > 0 else 300
    cache["max_entries"] = int(max_entries) if _is_number(max_entries) and int(max_entries) > 0 else 1000
    raw["cache"] = cache

    policy["cascade"] = raw


def _normalize_circuit_breaker(policy: dict[str, Any]) -> None:
    raw = policy.get("circuit_breaker")
    if raw is None:
        policy["circuit_breaker"] = {
            "enabled": False,
            "error_threshold": 5,
            "window_seconds": 60,
            "cooldown_seconds": 30,
            "max_cooldown_seconds": 300,
            "half_open_max_requests": 1,
            "fallback_status": 503,
            "fallback_message": "Service temporarily unavailable. Circuit breaker is open.",
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("circuit_breaker must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    error_threshold = raw.get("error_threshold", 5)
    window_seconds = raw.get("window_seconds", 60)
    cooldown_seconds = raw.get("cooldown_seconds", 30)
    max_cooldown_seconds = raw.get("max_cooldown_seconds", 300)
    half_open_max_requests = raw.get("half_open_max_requests", 1)
    fallback_status = raw.get("fallback_status", 503)
    fallback_message = raw.get("fallback_message", "Service temporarily unavailable. Circuit breaker is open.")

    if not _is_number(error_threshold) or int(error_threshold) <= 0:
        raise PolicyError("circuit_breaker.error_threshold must be > 0")
    if not _is_number(window_seconds) or float(window_seconds) <= 0:
        raise PolicyError("circuit_breaker.window_seconds must be > 0")
    if not _is_number(cooldown_seconds) or float(cooldown_seconds) <= 0:
        raise PolicyError("circuit_breaker.cooldown_seconds must be > 0")
    if not _is_number(max_cooldown_seconds) or float(max_cooldown_seconds) <= 0:
        raise PolicyError("circuit_breaker.max_cooldown_seconds must be > 0")
    if not _is_number(half_open_max_requests) or int(half_open_max_requests) <= 0:
        raise PolicyError("circuit_breaker.half_open_max_requests must be > 0")
    if not _is_number(fallback_status) or int(fallback_status) <= 0:
        raise PolicyError("circuit_breaker.fallback_status must be > 0")

    raw["error_threshold"] = int(error_threshold)
    raw["window_seconds"] = int(window_seconds)
    raw["cooldown_seconds"] = int(cooldown_seconds)
    raw["max_cooldown_seconds"] = int(max_cooldown_seconds)
    raw["half_open_max_requests"] = int(half_open_max_requests)
    raw["fallback_status"] = int(fallback_status)
    raw["fallback_message"] = str(fallback_message)
    policy["circuit_breaker"] = raw


def _normalize_loop_detection(policy: dict[str, Any]) -> None:
    raw = policy.get("loop_detection")
    if raw is None:
        policy["loop_detection"] = {
            "enabled": False,
            "exact": {"threshold": 5, "window_seconds": 120, "action": "warn"},
            "fuzzy": {"threshold": 8, "window_seconds": 300, "action": "block"},
            "on_detect": {"notify": True, "log": True, "max_cost_saved": True},
            "warn_threshold": 5,
            "block_threshold": 8,
            "window_seconds": 300.0,
            "similarity_check": True,
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("loop_detection must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    allowed_actions = {"warn", "block", "downgrade_model"}

    legacy_warn = raw.get("warn_threshold", 5)
    legacy_block = raw.get("block_threshold", 10)
    legacy_window = raw.get("window_seconds", 300)

    exact = raw.get("exact") if isinstance(raw.get("exact"), dict) else {}
    fuzzy = raw.get("fuzzy") if isinstance(raw.get("fuzzy"), dict) else {}
    on_detect = raw.get("on_detect") if isinstance(raw.get("on_detect"), dict) else {}

    exact_threshold = exact.get("threshold", legacy_warn)
    exact_window = exact.get("window_seconds", legacy_window)
    exact_action = str(exact.get("action", "warn")).lower()
    if not _is_number(exact_threshold) or int(exact_threshold) <= 0:
        raise PolicyError("loop_detection.exact.threshold must be > 0")
    if not _is_number(exact_window) or float(exact_window) <= 0:
        raise PolicyError("loop_detection.exact.window_seconds must be > 0")
    if exact_action not in allowed_actions:
        raise PolicyError("loop_detection.exact.action must be warn|block|downgrade_model")
    raw["exact"] = {
        "threshold": int(exact_threshold),
        "window_seconds": float(exact_window),
        "action": exact_action,
    }

    fuzzy_threshold = fuzzy.get("threshold", legacy_block)
    fuzzy_window = fuzzy.get("window_seconds", legacy_window)
    fuzzy_action = str(fuzzy.get("action", "block")).lower()
    if not _is_number(fuzzy_threshold) or int(fuzzy_threshold) <= 0:
        raise PolicyError("loop_detection.fuzzy.threshold must be > 0")
    if not _is_number(fuzzy_window) or float(fuzzy_window) <= 0:
        raise PolicyError("loop_detection.fuzzy.window_seconds must be > 0")
    if fuzzy_action not in allowed_actions:
        raise PolicyError("loop_detection.fuzzy.action must be warn|block|downgrade_model")
    raw["fuzzy"] = {
        "threshold": int(fuzzy_threshold),
        "window_seconds": float(fuzzy_window),
        "action": fuzzy_action,
    }

    raw["on_detect"] = {
        "notify": bool(on_detect.get("notify", True)),
        "log": bool(on_detect.get("log", True)),
        "max_cost_saved": bool(on_detect.get("max_cost_saved", True)),
    }

    # Keep compatibility fields for legacy callers.
    raw["warn_threshold"] = int(raw["exact"]["threshold"])
    raw["block_threshold"] = int(raw["fuzzy"]["threshold"])
    raw["window_seconds"] = float(max(raw["exact"]["window_seconds"], raw["fuzzy"]["window_seconds"]))
    raw["similarity_check"] = bool(raw.get("similarity_check", True))

    policy["loop_detection"] = raw


def _normalize_behavioral_fingerprint(policy: dict[str, Any]) -> None:
    raw = policy.get("behavioral_fingerprint")
    if raw is None:
        policy["behavioral_fingerprint"] = {
            "enabled": False,
            "learning_window": 20,
            "dimensions": dict(DEFAULT_DIMENSIONS),
            "persist_baselines": False,
            "persist_path": ".orchesis/baselines.json",
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("behavioral_fingerprint must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    learning_window = raw.get("learning_window", 20)
    if not _is_number(learning_window) or int(learning_window) <= 0:
        raise PolicyError("behavioral_fingerprint.learning_window must be > 0")
    raw["learning_window"] = int(learning_window)
    raw["persist_baselines"] = bool(raw.get("persist_baselines", False))
    raw["persist_path"] = str(raw.get("persist_path", ".orchesis/baselines.json"))

    dimensions = raw.get("dimensions")
    dims_in = dimensions if isinstance(dimensions, dict) else {}
    normalized_dims: dict[str, dict[str, Any]] = {}
    for dim_name, default in DEFAULT_DIMENSIONS.items():
        current = dims_in.get(dim_name, {})
        if not isinstance(current, dict):
            current = {}
        z_threshold = current.get("z_threshold", default["z_threshold"])
        action = str(current.get("action", default["action"])).strip().lower()
        if not _is_number(z_threshold) or float(z_threshold) <= 0:
            raise PolicyError(f"behavioral_fingerprint.dimensions.{dim_name}.z_threshold must be > 0")
        if action not in {"warn", "block", "log"}:
            raise PolicyError(f"behavioral_fingerprint.dimensions.{dim_name}.action must be warn|block|log")
        normalized_dims[dim_name] = {"z_threshold": float(z_threshold), "action": action}
    raw["dimensions"] = normalized_dims
    policy["behavioral_fingerprint"] = raw


def _normalize_recording(policy: dict[str, Any]) -> None:
    raw = policy.get("recording")
    if raw is None:
        policy["recording"] = {
            "enabled": False,
            "storage_path": ".orchesis/sessions",
            "max_age_days": 30,
            "max_file_size_mb": 10,
            "compress": True,
            "include_response_body": True,
            "exclude_models": [],
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("recording must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    storage_path = raw.get("storage_path", ".orchesis/sessions")
    if not isinstance(storage_path, str) or not storage_path.strip():
        raise PolicyError("recording.storage_path must be a non-empty string")
    raw["storage_path"] = storage_path.strip()

    max_age_days = raw.get("max_age_days", 30)
    if not _is_number(max_age_days) or int(max_age_days) <= 0:
        raise PolicyError("recording.max_age_days must be > 0")
    raw["max_age_days"] = int(max_age_days)

    max_file_size_mb = raw.get("max_file_size_mb", 10)
    if not _is_number(max_file_size_mb) or int(max_file_size_mb) <= 0:
        raise PolicyError("recording.max_file_size_mb must be > 0")
    raw["max_file_size_mb"] = int(max_file_size_mb)

    raw["compress"] = bool(raw.get("compress", True))
    raw["include_response_body"] = bool(raw.get("include_response_body", True))
    exclude_models = raw.get("exclude_models")
    if isinstance(exclude_models, list):
        raw["exclude_models"] = [str(item) for item in exclude_models if isinstance(item, str)]
    else:
        raw["exclude_models"] = []
    policy["recording"] = raw


def _normalize_flow_xray(policy: dict[str, Any]) -> None:
    raw = policy.get("flow_xray")
    if raw is None:
        policy["flow_xray"] = {
            "enabled": False,
            "max_sessions": 1000,
            "redundancy_window_seconds": 30.0,
            "retry_threshold": 3,
            "ping_pong_min_repetitions": 3,
            "token_waste_stddev_threshold": 2.0,
            "latency_spike_threshold": 0.5,
            "enable_security_patterns": True,
            "enable_efficiency_patterns": True,
            "enable_performance_patterns": True,
            "suspicious_tool_chains": [
                ["read_file", "http_request"],
                ["database_query", "http_request"],
                ["get_secret", "http_request"],
            ],
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("flow_xray must be a mapping")

    raw["enabled"] = bool(raw.get("enabled", False))
    max_sessions = raw.get("max_sessions", 1000)
    if not _is_number(max_sessions) or int(max_sessions) <= 0:
        raise PolicyError("flow_xray.max_sessions must be > 0")
    raw["max_sessions"] = int(max_sessions)

    redundancy_window = raw.get("redundancy_window_seconds", 30.0)
    if not _is_number(redundancy_window) or float(redundancy_window) <= 0:
        raise PolicyError("flow_xray.redundancy_window_seconds must be > 0")
    raw["redundancy_window_seconds"] = float(redundancy_window)

    retry_threshold = raw.get("retry_threshold", 3)
    if not _is_number(retry_threshold) or int(retry_threshold) <= 0:
        raise PolicyError("flow_xray.retry_threshold must be > 0")
    raw["retry_threshold"] = int(retry_threshold)

    ping_pong = raw.get("ping_pong_min_repetitions", 3)
    if not _is_number(ping_pong) or int(ping_pong) < 2:
        raise PolicyError("flow_xray.ping_pong_min_repetitions must be >= 2")
    raw["ping_pong_min_repetitions"] = int(ping_pong)

    token_waste_stddev = raw.get("token_waste_stddev_threshold", 2.0)
    if not _is_number(token_waste_stddev) or float(token_waste_stddev) <= 0:
        raise PolicyError("flow_xray.token_waste_stddev_threshold must be > 0")
    raw["token_waste_stddev_threshold"] = float(token_waste_stddev)

    latency_spike = raw.get("latency_spike_threshold", 0.5)
    if not _is_number(latency_spike) or float(latency_spike) <= 0:
        raise PolicyError("flow_xray.latency_spike_threshold must be > 0")
    raw["latency_spike_threshold"] = float(latency_spike)

    if "security_patterns" in raw and "enable_security_patterns" not in raw:
        raw["enable_security_patterns"] = bool(raw.get("security_patterns", True))
    if "efficiency_patterns" in raw and "enable_efficiency_patterns" not in raw:
        raw["enable_efficiency_patterns"] = bool(raw.get("efficiency_patterns", True))
    if "performance_patterns" in raw and "enable_performance_patterns" not in raw:
        raw["enable_performance_patterns"] = bool(raw.get("performance_patterns", True))
    raw["enable_security_patterns"] = bool(raw.get("enable_security_patterns", True))
    raw["enable_efficiency_patterns"] = bool(raw.get("enable_efficiency_patterns", True))
    raw["enable_performance_patterns"] = bool(raw.get("enable_performance_patterns", True))

    chains = raw.get("suspicious_tool_chains")
    if chains is None:
        chains = [
            ["read_file", "http_request"],
            ["database_query", "http_request"],
            ["get_secret", "http_request"],
        ]
    if not isinstance(chains, list):
        raise PolicyError("flow_xray.suspicious_tool_chains must be a list of lists")
    normalized_chains: list[list[str]] = []
    for index, chain in enumerate(chains):
        if not isinstance(chain, list):
            raise PolicyError(f"flow_xray.suspicious_tool_chains[{index}] must be a list")
        normalized_chain: list[str] = []
        for item in chain:
            if not isinstance(item, str) or not item.strip():
                raise PolicyError(f"flow_xray.suspicious_tool_chains[{index}] entries must be non-empty strings")
            normalized_chain.append(item.strip())
        if normalized_chain:
            normalized_chains.append(normalized_chain)
    raw["suspicious_tool_chains"] = normalized_chains
    policy["flow_xray"] = raw


def _normalize_compliance(policy: dict[str, Any]) -> None:
    raw = policy.get("compliance")
    if raw is None:
        policy["compliance"] = {
            "enabled": True,
            "frameworks": ["owasp_llm_top10", "nist_ai_rmf"],
            "max_findings": 10000,
        }
        return
    if not isinstance(raw, dict):
        raise PolicyError("compliance must be a mapping")
    raw["enabled"] = bool(raw.get("enabled", True))
    frameworks_raw = raw.get("frameworks", ["owasp_llm_top10", "nist_ai_rmf"])
    if not isinstance(frameworks_raw, list):
        raise PolicyError("compliance.frameworks must be a list")
    normalized_frameworks: list[str] = []
    allowed = {"owasp_llm_top10", "nist_ai_rmf", "nist_ai_agent"}
    for item in frameworks_raw:
        if not isinstance(item, str):
            continue
        token = item.strip().lower()
        if not token:
            continue
        if token not in allowed:
            raise PolicyError(f"unsupported compliance framework: {token}")
        if token not in normalized_frameworks:
            normalized_frameworks.append(token)
    if not normalized_frameworks:
        normalized_frameworks = ["owasp_llm_top10", "nist_ai_rmf"]
    raw["frameworks"] = normalized_frameworks
    max_findings = raw.get("max_findings", 10000)
    if not _is_number(max_findings) or int(max_findings) <= 0:
        raise PolicyError("compliance.max_findings must be > 0")
    raw["max_findings"] = int(max_findings)
    policy["compliance"] = raw


def _normalize_capability_constraints(raw: Any, *, key: str, index: int, section: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PolicyError(f"capabilities[{index}].{section}.{key} must be a list of strings")
    normalized: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise PolicyError(f"capabilities[{index}].{section}.{key} entries must be non-empty strings")
        normalized.append(item.strip())
    return normalized


def _normalize_capability_rule(raw: Any, *, index: int, section: str) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"capabilities[{index}].{section} must be a mapping")
    normalized: dict[str, list[str]] = {}
    for key, value in raw.items():
        if key not in _CAPABILITY_CONSTRAINT_KEYS:
            raise PolicyError(
                f"capabilities[{index}].{section} has unsupported key '{key}' "
                f"(allowed: {sorted(_CAPABILITY_CONSTRAINT_KEYS)})"
            )
        normalized[key] = _normalize_capability_constraints(value, key=key, index=index, section=section)
    return normalized


def _normalize_capabilities(policy: dict[str, Any]) -> None:
    default_action_raw = policy.get("default_action")
    if default_action_raw is None:
        policy["default_action"] = "allow"
    elif isinstance(default_action_raw, str):
        normalized_action = default_action_raw.strip().lower()
        if normalized_action not in {"allow", "deny"}:
            raise PolicyError("default_action must be either 'allow' or 'deny'")
        policy["default_action"] = normalized_action
    else:
        raise PolicyError("default_action must be a string: 'allow' or 'deny'")

    raw_capabilities = policy.get("capabilities")
    if raw_capabilities is None:
        policy["capabilities"] = []
        return
    if not isinstance(raw_capabilities, list):
        raise PolicyError("capabilities must be a list")

    normalized_caps: list[dict[str, Any]] = []
    for index, item in enumerate(raw_capabilities):
        if not isinstance(item, dict):
            raise PolicyError(f"capabilities[{index}] must be a mapping")
        raw_tool = item.get("tool")
        if not isinstance(raw_tool, str) or not raw_tool.strip():
            raise PolicyError(f"capabilities[{index}].tool must be a non-empty string")
        tool = raw_tool.strip()
        if tool != "*":
            tool = _normalize_tool_name(tool)
        if not tool:
            raise PolicyError(f"capabilities[{index}].tool is invalid after normalization")
        allow = _normalize_capability_rule(item.get("allow"), index=index, section="allow")
        deny = _normalize_capability_rule(item.get("deny"), index=index, section="deny")
        if not allow and not deny:
            raise PolicyError(f"capabilities[{index}] must define 'allow' and/or 'deny'")
        normalized_caps.append({"tool": tool, "allow": allow, "deny": deny})

    policy["capabilities"] = normalized_caps


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load policy from YAML file path."""
    policy_path = Path(path)
    try:
        with policy_path.open("r", encoding="utf-8") as file:
            loaded = yaml.safe_load(file)
    except (yaml.YAMLError, RecursionError, MemoryError) as error:
        raise ValueError(f"Invalid YAML policy: {error}") from error

    if not isinstance(loaded, dict):
        raise PolicyError("Policy top-level YAML object must be a mapping.")

    _normalize_policy_paths(loaded)
    _normalize_tool_access_rate_limits(loaded)
    _normalize_cost_controls(loaded)
    _normalize_proxy_config(loaded)
    _normalize_kill_switch(loaded)
    _normalize_cascade(loaded)
    _normalize_circuit_breaker(loaded)
    _normalize_loop_detection(loaded)
    _normalize_behavioral_fingerprint(loaded)
    _normalize_recording(loaded)
    _normalize_flow_xray(loaded)
    _normalize_compliance(loaded)
    _normalize_capabilities(loaded)
    return loaded


def _parse_trust_tier(value: Any, default: TrustTier = TrustTier.INTERN) -> TrustTier:
    if isinstance(value, TrustTier):
        return value
    if isinstance(value, int):
        try:
            return TrustTier(value)
        except ValueError:
            return default
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized:
            try:
                return TrustTier[normalized]
            except KeyError:
                return default
    return default


def _parse_str_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    parsed = [item for item in value if isinstance(item, str)]
    return parsed


def load_agent_registry(policy: dict[str, Any]) -> AgentRegistry:
    """Parse policy agent definitions into an AgentRegistry."""
    default_tier = _parse_trust_tier(policy.get("default_trust_tier"), TrustTier.INTERN)
    registry = AgentRegistry(agents={}, default_tier=default_tier)
    agents = policy.get("agents")
    if not isinstance(agents, list):
        return registry

    for entry in agents:
        if not isinstance(entry, dict):
            continue
        agent_id = entry.get("id")
        if not isinstance(agent_id, str) or not agent_id.strip():
            continue
        normalized_id = agent_id.strip()
        name = entry.get("name")
        agent_name = name.strip() if isinstance(name, str) and name.strip() else normalized_id
        tier = _parse_trust_tier(entry.get("trust_tier"), default_tier)
        max_cost = entry.get("max_cost_per_call")
        daily_budget = entry.get("daily_budget")
        rate_limit = entry.get("rate_limit_per_minute")
        metadata = entry.get("metadata")
        identity = AgentIdentity(
            agent_id=normalized_id,
            name=agent_name,
            trust_tier=tier,
            allowed_tools=_parse_str_list(entry.get("allowed_tools")),
            denied_tools=_parse_str_list(entry.get("denied_tools")),
            max_cost_per_call=float(max_cost) if isinstance(max_cost, int | float) else None,
            daily_budget=float(daily_budget) if isinstance(daily_budget, int | float) else None,
            rate_limit_per_minute=rate_limit if isinstance(rate_limit, int) else None,
            metadata=metadata if isinstance(metadata, dict) else {},
        )
        registry.register(identity)
    return registry


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Validate policy structure and return errors."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    errors: list[str] = []
    rules = policy.get("rules")

    if not isinstance(rules, list):
        return ["policy.rules must be a list"]

    named_rules: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, dict):
            name = rule.get("name")
            if isinstance(name, str):
                named_rules[name] = rule

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"rules[{index}] must be a mapping")
            continue

        rule_name = rule.get("name")
        if not isinstance(rule_name, str) or not rule_name.strip():
            errors.append(f"rules[{index}].name must be a non-empty string")
            continue

        if rule_name == "budget_limit":
            if not _is_number(rule.get("max_cost_per_call")):
                errors.append(f"rules[{index}].max_cost_per_call is required for budget_limit")

            daily_budget = rule.get("daily_budget")
            if daily_budget is not None and not _is_number(daily_budget):
                errors.append(f"rules[{index}].daily_budget must be numeric if provided")

        elif rule_name == "file_access":
            allowed = rule.get("allowed_paths")
            denied = rule.get("denied_paths")
            has_allowed = isinstance(allowed, list) and len(allowed) > 0
            has_denied = isinstance(denied, list) and len(denied) > 0
            if not (has_allowed or has_denied):
                errors.append(
                    f"rules[{index}] must define allowed_paths and/or denied_paths for file_access"
                )

        elif rule_name == "sql_restriction":
            if not isinstance(rule.get("denied_operations"), list):
                errors.append(f"rules[{index}].denied_operations is required for sql_restriction")

        elif rule_name == "rate_limit":
            if not isinstance(rule.get("max_requests_per_minute"), int):
                errors.append(f"rules[{index}].max_requests_per_minute is required for rate_limit")

        rule_type = rule.get("type")
        if rule_type == "regex_match":
            field = rule.get("field")
            deny_patterns = rule.get("deny_patterns")
            if not isinstance(field, str) or not field.strip():
                errors.append(f"rules[{index}].field is required for regex_match")
            if not isinstance(deny_patterns, list) or not deny_patterns:
                errors.append(
                    f"rules[{index}].deny_patterns must be a non-empty list for regex_match"
                )
            elif isinstance(deny_patterns, list):
                for pattern in deny_patterns:
                    if not isinstance(pattern, str):
                        errors.append(f"rules[{index}] contains non-string regex pattern")
                        continue
                    if re.search(r"\([^)]*[+*][^)]*\)[+*?]", pattern):
                        errors.append(f"rules[{index}] contains unsafe regex pattern: {pattern}")

        if rule_type == "composite":
            operator = rule.get("operator")
            conditions = rule.get("conditions")
            if not isinstance(operator, str) or operator.upper() not in {"AND", "OR"}:
                errors.append(f"rules[{index}].operator must be AND or OR for composite")
            if not isinstance(conditions, list) or not conditions:
                errors.append(f"rules[{index}].conditions must be a non-empty list for composite")

    # Detect circular references in composite rules.
    graph: dict[str, list[str]] = {}
    for name, rule in named_rules.items():
        if rule.get("type") != "composite":
            continue
        conditions = rule.get("conditions")
        refs: list[str] = []
        if isinstance(conditions, list):
            for item in conditions:
                if isinstance(item, dict):
                    ref = item.get("rule")
                    if isinstance(ref, str):
                        refs.append(ref)
        graph[name] = refs

    visited: set[str] = set()
    stack: set[str] = set()

    def visit(node: str) -> bool:
        if node in stack:
            return True
        if node in visited:
            return False
        visited.add(node)
        stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor in graph and visit(neighbor):
                return True
        stack.remove(node)
        return False

    for node in graph:
        if visit(node):
            errors.append("circular composite reference detected")
            break

    agents = policy.get("agents")
    valid_tiers = {tier.name.lower() for tier in TrustTier}
    if agents is not None and not isinstance(agents, list):
        errors.append("policy.agents must be a list")
    if isinstance(agents, list):
        seen_ids: set[str] = set()
        for index, agent in enumerate(agents):
            if not isinstance(agent, dict):
                errors.append(f"agents[{index}] must be a mapping")
                continue

            agent_id = agent.get("id")
            name = agent.get("name")
            trust_tier = agent.get("trust_tier")
            if not isinstance(agent_id, str) or not agent_id.strip():
                errors.append(f"agents[{index}].id must be a non-empty string")
            elif agent_id.strip() in seen_ids:
                errors.append(f"agents[{index}].id '{agent_id.strip()}' is duplicated")
            else:
                seen_ids.add(agent_id.strip())

            if not isinstance(name, str) or not name.strip():
                errors.append(f"agents[{index}].name must be a non-empty string")

            if not isinstance(trust_tier, str) or trust_tier.strip().lower() not in valid_tiers:
                errors.append(f"agents[{index}].trust_tier must be one of {sorted(valid_tiers)}")

            allowed_tools = agent.get("allowed_tools")
            if allowed_tools is not None:
                if not isinstance(allowed_tools, list) or any(
                    not isinstance(item, str) for item in allowed_tools
                ):
                    errors.append(f"agents[{index}].allowed_tools must be a list of strings")

            denied_tools = agent.get("denied_tools")
            if denied_tools is not None:
                if not isinstance(denied_tools, list) or any(
                    not isinstance(item, str) for item in denied_tools
                ):
                    errors.append(f"agents[{index}].denied_tools must be a list of strings")

            if agent.get("max_cost_per_call") is not None and not _is_number(
                agent.get("max_cost_per_call")
            ):
                errors.append(f"agents[{index}].max_cost_per_call must be numeric if provided")
            if agent.get("daily_budget") is not None and not _is_number(agent.get("daily_budget")):
                errors.append(f"agents[{index}].daily_budget must be numeric if provided")
            rate_limit = agent.get("rate_limit_per_minute")
            if rate_limit is not None:
                if not isinstance(rate_limit, int) or rate_limit <= 0:
                    errors.append(
                        f"agents[{index}].rate_limit_per_minute must be a positive integer"
                    )

    default_tier = policy.get("default_trust_tier")
    if default_tier is not None:
        if not isinstance(default_tier, str) or default_tier.strip().lower() not in valid_tiers:
            errors.append(f"default_trust_tier must be one of {sorted(valid_tiers)}")

    return errors


def validate_policy_warnings(policy: dict[str, Any]) -> list[str]:
    """Return non-fatal policy recommendations."""
    if not isinstance(policy, dict):
        return []
    warnings: list[str] = []
    version = policy.get("version")
    if not isinstance(version, str) or not version.strip():
        warnings.append("policy.version is recommended for version tracking")
    return warnings


class PolicyWatcher:
    """Monitors policy file and reloads on change."""

    def __init__(self, path: str, on_reload: Callable[[dict[str, Any]], None]):
        self.path = Path(path)
        self.on_reload = on_reload
        self._last_hash: str = ""

    def current_hash(self) -> str:
        if not self.path.exists():
            return ""
        content = self.path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def check(self) -> bool:
        try:
            new_hash = self.current_hash()
        except OSError:
            return False
        if not new_hash or new_hash == self._last_hash:
            return False

        try:
            policy = load_policy(self.path)
        except ValueError:
            return False
        self.on_reload(policy)
        self._last_hash = new_hash
        return True
