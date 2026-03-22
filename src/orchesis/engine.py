"""Rule evaluation engine."""

import hashlib
import ipaddress
import json
import fnmatch
import posixpath
import re
import threading
import time
import unicodedata
import uuid
from collections.abc import Iterable
from datetime import date, datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import unquote, urlparse

from orchesis.config import _RATE_LIMIT_WINDOW_SECONDS, _TOOL_RATE_LIMIT_PATTERN
from orchesis.cost_tracker import CostTracker, DEFAULT_TOOL_COSTS
from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier, check_capability
from orchesis.loop_detector import LoopDetector
from orchesis.model_router import ModelRouter
from orchesis.models import Decision
from orchesis.plugins import PluginRegistry
from orchesis.state import DEFAULT_SESSION_ID, GLOBAL_AGENT_ID, RateLimitTracker
from orchesis.telemetry import DecisionEvent, EventEmitter

RULE_EVALUATION_ORDER = [
    "identity_check",
    "budget_limit",
    "rate_limit",
    "file_access",
    "sql_restriction",
    "regex_match",
    "context_rules",
    "composite",
]

KNOWN_RULE_TYPES = set(RULE_EVALUATION_ORDER) - {"identity_check"}
_POLICY_PLAN_CACHE: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
_POLICY_HASH_CACHE: dict[int, tuple[dict[str, Any], str]] = {}
TIER_HIERARCHY = ["blocked", "intern", "assistant", "operator", "admin"]
_daily_token_usage: dict[str, int] = {}
_daily_token_usage_day: date = date.today()
_daily_token_usage_lock = threading.Lock()
_SECRET_SCANNER = SecretScanner()
_PII_DETECTOR = PiiDetector()
_COST_TRACKER = CostTracker()
_LOOP_DETECTORS: dict[str, LoopDetector] = {}
_LOOP_DETECTOR_LOCK = threading.Lock()
_MODEL_ROUTERS: dict[str, ModelRouter] = {}
_MODEL_ROUTER_LOCK = threading.Lock()


class EvaluationGuarantees:
    """Documents formal guarantees of the evaluation engine."""

    DETERMINISTIC = True
    SHORT_CIRCUIT = False
    FAIL_CLOSED = True
    UNKNOWN_FIELD_SAFE = True
    THREAD_SAFE = True
    EVALUATION_ORDER = RULE_EVALUATION_ORDER


def get_cost_tracker() -> CostTracker:
    return _COST_TRACKER


def reset_cost_tracker_daily() -> None:
    _COST_TRACKER.reset_daily()


def get_loop_detector_stats() -> dict[str, Any]:
    with _LOOP_DETECTOR_LOCK:
        detectors = list(_LOOP_DETECTORS.values())
    total_saved = 0.0
    total_detected = 0
    total_warned = 0
    total_blocked = 0
    for detector in detectors:
        stats = detector.get_stats()
        total_saved += float(stats.get("total_saved_usd", 0.0))
        total_detected += int(stats.get("total_loops_detected", 0))
        total_warned += int(stats.get("loops_warned", 0))
        total_blocked += int(stats.get("loops_blocked", 0))
    return {
        "total_saved_usd": round(total_saved, 4),
        "total_loops_detected": total_detected,
        "loops_warned": total_warned,
        "loops_blocked": total_blocked,
    }


def _loop_detector_for_config(config: dict[str, Any] | None) -> LoopDetector:
    safe_config = config if isinstance(config, dict) else {}
    key = json.dumps(
        {
            "warn_threshold": int(safe_config.get("warn_threshold", 5)),
            "block_threshold": int(safe_config.get("block_threshold", 10)),
            "window_seconds": float(safe_config.get("window_seconds", 300.0)),
            "similarity_check": bool(safe_config.get("similarity_check", True)),
        },
        sort_keys=True,
    )
    with _LOOP_DETECTOR_LOCK:
        detector = _LOOP_DETECTORS.get(key)
        if detector is None:
            detector = LoopDetector(
                warn_threshold=int(safe_config.get("warn_threshold", 5)),
                block_threshold=int(safe_config.get("block_threshold", 10)),
                window_seconds=float(safe_config.get("window_seconds", 300.0)),
                similarity_check=bool(safe_config.get("similarity_check", True)),
            )
            _LOOP_DETECTORS[key] = detector
    return detector


def _router_for_config(config: dict[str, Any] | None) -> ModelRouter:
    safe_config = config if isinstance(config, dict) else {}
    key = json.dumps(safe_config, sort_keys=True, default=str)
    with _MODEL_ROUTER_LOCK:
        router = _MODEL_ROUTERS.get(key)
        if router is None:
            router = ModelRouter(safe_config)
            _MODEL_ROUTERS[key] = router
    return router


class ToolRateLimiter:
    """Sliding-window rate limiter for per-tool limits."""

    def __init__(self, tracker: RateLimitTracker, agent_id: str, session_id: str) -> None:
        self._tracker = tracker
        self._agent_id = agent_id
        self._session_id = session_id

    def check_and_record(
        self, *, tool_name: str, max_requests: int, window_seconds: int, now: datetime
    ) -> tuple[bool, int]:
        scoped_tool_name = f"per_tool::{tool_name}"
        over_limit = self._tracker.check_and_record(
            scoped_tool_name,
            max_requests=max_requests,
            window_seconds=window_seconds,
            timestamp=now,
            agent_id=self._agent_id,
            session_id=self._session_id,
        )
        current_count = self._tracker.get_count(
            scoped_tool_name,
            window_seconds=window_seconds,
            now=now,
            agent_id=self._agent_id,
            session_id=self._session_id,
        )
        return over_limit, current_count


def _stable_sha256(payload: Any) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _policy_version_hash(policy: dict[str, Any] | None) -> str:
    if policy is None:
        return hashlib.sha256(b"null").hexdigest()
    cache_key = id(policy)
    cached = _POLICY_HASH_CACHE.get(cache_key)
    if cached is not None and cached[0] is policy:
        return cached[1]
    dumped = json.dumps(policy, sort_keys=True, default=str, separators=(",", ":"))
    digest = _policy_version_hash_cached(dumped)
    if len(_POLICY_HASH_CACHE) >= 32:
        _POLICY_HASH_CACHE.pop(next(iter(_POLICY_HASH_CACHE)))
    _POLICY_HASH_CACHE[cache_key] = (policy, digest)
    return digest


@lru_cache(maxsize=16)
def _policy_version_hash_cached(serialized_policy: str) -> str:
    return hashlib.sha256(serialized_policy.encode("utf-8")).hexdigest()


def _rules_triggered(reasons: list[str]) -> list[str]:
    triggered: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if ":" not in reason:
            continue
        name = reason.split(":", 1)[0].strip()
        if name and name not in seen:
            seen.add(name)
            triggered.append(name)
    return triggered


def _build_state_snapshot(
    state: RateLimitTracker, agent_id: str, session_id: str
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "agent_id": agent_id,
        "session_id": session_id,
        "window_seconds": 60,
        "tool_counts": {},
    }
    for tool in state.get_tools():
        snapshot["tool_counts"][tool] = state.get_count(
            tool, window_seconds=60, agent_id=agent_id, session_id=session_id
        )
    return snapshot


def _sanitize_text(value: str) -> str:
    return _sanitize_text_cached(value)


@lru_cache(maxsize=512)
def _sanitize_text_cached(value: str) -> str:
    return unicodedata.normalize("NFKC", value.replace("\x00", "").strip())


def _normalize_tool_name(value: Any) -> tuple[str, bool]:
    if not isinstance(value, str):
        return "__unknown__", False
    normalized = _sanitize_text(value)
    normalized = "".join(
        ch for ch in unicodedata.normalize("NFKD", normalized) if not unicodedata.combining(ch)
    )
    homoglyph_map = {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0442": "t",
        "\u0456": "i",
        "\u0458": "j",
        "\u04bb": "h",
        "\u0455": "s",
        "\u04c0": "l",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
    }
    for cyrillic, latin in homoglyph_map.items():
        normalized = normalized.replace(cyrillic, latin)
    normalized = normalized.lower()
    if normalized == "":
        return "__unknown__", False
    has_control_chars = any(ch in normalized for ch in ("\t", "\n", "\r"))
    return normalized, has_control_chars


def _normalize_path(path: str) -> str:
    decoded = unquote(path)
    cleaned = _sanitize_text(decoded).replace("\\", "/")
    if any(ch in cleaned for ch in ("\t", "\n", "\r")):
        raise ValueError("path contains control characters")
    cleaned = re.sub(r"/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    normalized = posixpath.normpath(cleaned)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.lower()


def _coerce_cost(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _resolve_agent_id(request: dict[str, Any]) -> str:
    context = request.get("context")
    if not isinstance(context, dict):
        return GLOBAL_AGENT_ID
    agent = context.get("agent")
    if not isinstance(agent, str):
        return GLOBAL_AGENT_ID
    cleaned = _sanitize_text(agent)
    return cleaned if cleaned else GLOBAL_AGENT_ID


def _resolve_session_id(request: dict[str, Any]) -> str:
    context = request.get("context")
    if not isinstance(context, dict):
        return DEFAULT_SESSION_ID
    session = context.get("session")
    if not isinstance(session, str):
        return DEFAULT_SESSION_ID
    cleaned = _sanitize_text(session)
    return cleaned if cleaned else DEFAULT_SESSION_ID


def min_tier(tier_a: str | None, tier_b: str | None) -> str:
    """Return the more restricted tier."""
    def _normalize(value: str | None) -> str:
        if not isinstance(value, str):
            return ""
        normalized = value.strip().lower()
        if normalized == "principal":
            return "admin"
        if normalized in TIER_HIERARCHY:
            return normalized
        return ""

    safe_a = _normalize(tier_a)
    safe_b = _normalize(tier_b)
    if not safe_a and safe_b:
        return safe_b
    if not safe_b and safe_a:
        return safe_a
    if not safe_a and not safe_b:
        return "intern"
    index_a = TIER_HIERARCHY.index(safe_a)
    index_b = TIER_HIERARCHY.index(safe_b)
    return TIER_HIERARCHY[min(index_a, index_b)]


def _normalize_tier(identity: AgentIdentity | None) -> str:
    if identity is None:
        return "intern"
    tier_name = identity.trust_tier.name.lower()
    return "admin" if tier_name == "principal" else tier_name


def _iter_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_string_values(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_string_values(item)


def _extract_tool_access(
    base_tool_access: dict[str, Any] | None,
    session_config: dict[str, Any] | None,
) -> dict[str, Any] | None:
    session_tool_access = (
        session_config.get("tool_access")
        if isinstance(session_config, dict) and isinstance(session_config.get("tool_access"), dict)
        else None
    )
    if session_tool_access is not None:
        return session_tool_access
    return base_tool_access


def _parse_rate_limit_value(raw: Any) -> tuple[int, int, str] | None:
    if isinstance(raw, dict):
        max_requests = raw.get("max_requests")
        window_seconds = raw.get("window_seconds")
        unit_raw = raw.get("unit")
        if isinstance(max_requests, int) and isinstance(window_seconds, int) and max_requests > 0:
            unit = str(unit_raw).lower() if isinstance(unit_raw, str) else "minute"
            return max_requests, window_seconds, unit
        return None
    if not isinstance(raw, str):
        return None
    match = _TOOL_RATE_LIMIT_PATTERN.match(raw)
    if match is None:
        return None
    max_requests = int(match.group(1))
    unit = match.group(2).lower()
    if max_requests <= 0:
        return None
    window_seconds = _RATE_LIMIT_WINDOW_SECONDS.get(unit)
    if not isinstance(window_seconds, int):
        return None
    return max_requests, window_seconds, unit


def _resolve_per_tool_rate_limit(
    *,
    policy: dict[str, Any] | None,
    request: dict[str, Any],
    session_type: str,
) -> dict[str, Any] | None:
    if not isinstance(policy, dict):
        return None
    tool, _invalid_tool_name = _normalize_tool_name(request.get("tool"))
    session_policies = policy.get("session_policies")
    session_config = (
        session_policies.get(session_type)
        if isinstance(session_policies, dict) and isinstance(session_policies.get(session_type), dict)
        else None
    )
    base_tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else None
    tool_access = _extract_tool_access(base_tool_access, session_config)
    if not isinstance(tool_access, dict):
        return None
    parsed_limits = (
        tool_access.get("_parsed_rate_limits")
        if isinstance(tool_access.get("_parsed_rate_limits"), dict)
        else tool_access.get("rate_limits")
    )
    if not isinstance(parsed_limits, dict):
        return None
    normalized_limits: dict[str, Any] = {}
    for key, value in parsed_limits.items():
        normalized_key, _ = _normalize_tool_name(key)
        normalized_limits[normalized_key] = value
    parsed = _parse_rate_limit_value(normalized_limits.get(tool))
    if parsed is None:
        return None
    max_requests, window_seconds, unit = parsed
    return {
        "tool": tool,
        "max_requests": max_requests,
        "window_seconds": window_seconds,
        "unit": unit,
    }


def _tier_allowed_and_denied(
    tiers: dict[str, Any], tier_name: str
) -> tuple[set[str], set[str], bool]:
    raw = tiers.get(tier_name)
    if isinstance(raw, list):
        allowed = {_normalize_tool_name(item)[0] for item in raw if isinstance(item, str)}
        return allowed, set(), "*" in allowed
    if isinstance(raw, dict):
        allowed_raw = raw.get("allowed")
        if isinstance(allowed_raw, list):
            allowed = {
                _normalize_tool_name(item)[0] for item in allowed_raw if isinstance(item, str)
            }
        else:
            allowed = {
                _normalize_tool_name(key)[0]
                for key in raw.keys()
                if isinstance(key, str) and key != "denied"
            }
        denied_raw = raw.get("denied")
        denied = (
            {_normalize_tool_name(item)[0] for item in denied_raw if isinstance(item, str)}
            if isinstance(denied_raw, list)
            else set()
        )
        return allowed, denied, "*" in allowed
    return set(), set(), False


def _extract_domains(params: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for candidate in _extract_network_values(params):
        parsed = urlparse(candidate)
        if parsed.hostname:
            values.append(parsed.hostname.lower())
        elif isinstance(candidate, str) and candidate.strip():
            values.append(candidate.strip().lower())
    return values


def _extract_commands(params: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for key in ("command", "cmd", "shell_command"):
        candidate = params.get(key)
        if isinstance(candidate, str) and candidate.strip():
            commands.append(candidate.strip())
    for value in _iter_string_values(params):
        if not isinstance(value, str) or not value.strip():
            continue
        lowered = value.strip().lower()
        if lowered.startswith(("git ", "ls", "cat ", "python ", "bash ", "sh ")):
            commands.append(value.strip())
    return commands


def _matches_any_glob(value: str, patterns: list[str], *, case_insensitive: bool = True) -> bool:
    source = value.lower() if case_insensitive else value
    for pattern in patterns:
        candidate = pattern.lower() if case_insensitive else pattern
        if fnmatch.fnmatch(source, candidate):
            return True
        if "/**/" in candidate:
            fallback = candidate.replace("/**/", "/*/")
            if fnmatch.fnmatch(source, fallback):
                return True
        if candidate.endswith("/**"):
            fallback = candidate[:-3] + "/*"
            if fnmatch.fnmatch(source, fallback):
                return True
    return False


def _constraint_denies(values: list[str], patterns: list[str], *, normalize_path: bool = False) -> bool:
    if not values or not patterns:
        return False
    for raw in values:
        value = raw
        if normalize_path:
            try:
                value = _normalize_path(raw)
            except Exception:
                continue
        if _matches_any_glob(value, patterns):
            return True
    return False


def _constraint_allows(values: list[str], patterns: list[str], *, normalize_path: bool = False) -> bool:
    if not patterns:
        return True
    if not values:
        return True
    for raw in values:
        value = raw
        if normalize_path:
            try:
                value = _normalize_path(raw)
            except Exception:
                continue
        if not _matches_any_glob(value, patterns):
            return False
    return True


def _evaluate_capabilities(
    *,
    policy: dict[str, Any],
    tool: str,
    request_params: dict[str, Any],
    default_action: str,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked: list[str] = []
    capabilities = policy.get("capabilities")
    if not isinstance(capabilities, list):
        return reasons, checked

    checked.append("capabilities")
    matching: list[dict[str, Any]] = []
    for item in capabilities:
        if not isinstance(item, dict):
            continue
        cap_tool = item.get("tool")
        if not isinstance(cap_tool, str):
            continue
        if cap_tool == "*" or cap_tool == tool:
            matching.append(item)

    paths = _extract_paths(request_params)
    domains = _extract_domains(request_params)
    commands = _extract_commands(request_params)

    for item in matching:
        deny = item.get("deny")
        if not isinstance(deny, dict):
            continue
        deny_paths = [str(pattern) for pattern in deny.get("paths", []) if isinstance(pattern, str)]
        deny_domains = [str(pattern) for pattern in deny.get("domains", []) if isinstance(pattern, str)]
        deny_commands = [str(pattern) for pattern in deny.get("commands", []) if isinstance(pattern, str)]
        if _constraint_denies(paths, deny_paths, normalize_path=True):
            reasons.append(f"capabilities: tool '{tool}' denied by path constraint")
            return reasons, checked
        if _constraint_denies(domains, deny_domains):
            reasons.append(f"capabilities: tool '{tool}' denied by domain constraint")
            return reasons, checked
        if _constraint_denies(commands, deny_commands):
            reasons.append(f"capabilities: tool '{tool}' denied by command constraint")
            return reasons, checked

    if default_action == "allow":
        return reasons, checked

    if not matching:
        reasons.append(f"capabilities: tool '{tool}' is not explicitly allowed (default_action=deny)")
        return reasons, checked

    allow_ok = False
    has_allow_constraints = False
    for item in matching:
        allow = item.get("allow")
        if not isinstance(allow, dict) or not allow:
            allow_ok = True
            continue
        has_allow_constraints = True
        allow_paths = [str(pattern) for pattern in allow.get("paths", []) if isinstance(pattern, str)]
        allow_domains = [str(pattern) for pattern in allow.get("domains", []) if isinstance(pattern, str)]
        allow_commands = [str(pattern) for pattern in allow.get("commands", []) if isinstance(pattern, str)]
        if (
            _constraint_allows(paths, allow_paths, normalize_path=True)
            and _constraint_allows(domains, allow_domains)
            and _constraint_allows(commands, allow_commands)
        ):
            allow_ok = True
            break

    if not allow_ok:
        if has_allow_constraints:
            reasons.append(f"capabilities: tool '{tool}' does not satisfy allow constraints")
        else:
            reasons.append(f"capabilities: tool '{tool}' is blocked by default_action=deny")
    return reasons, checked


def _evaluate_tool_access_control(
    *,
    policy: dict[str, Any] | None,
    request: dict[str, Any],
    state: RateLimitTracker,
    agent_id: str,
    session_id: str,
    session_type: str,
    identity: AgentIdentity | None,
    now: datetime,
) -> tuple[list[str], list[str], str]:
    reasons: list[str] = []
    checked: list[str] = []
    if not isinstance(policy, dict):
        return reasons, checked, _normalize_tier(identity)

    tool, invalid_tool_name = _normalize_tool_name(request.get("tool"))
    session_policies = policy.get("session_policies")
    session_config = (
        session_policies.get(session_type)
        if isinstance(session_policies, dict) and isinstance(session_policies.get(session_type), dict)
        else None
    )
    base_tier = _normalize_tier(identity)
    session_tier = session_config.get("trust_tier") if isinstance(session_config, dict) else None
    effective_tier = min_tier(session_tier, base_tier)

    # Session-level path deny.
    denied_paths = (
        session_config.get("denied_paths")
        if isinstance(session_config, dict) and isinstance(session_config.get("denied_paths"), list)
        else []
    )
    if denied_paths:
        normalized_denied = [
            _normalize_path(item) for item in denied_paths if isinstance(item, str) and item.strip()
        ]
        if normalized_denied:
            checked.append("tool_access_control")
            for value in _iter_string_values(request.get("params")):
                try:
                    normalized_value = _normalize_path(value)
                except Exception:
                    continue
                if any(normalized_value.startswith(prefix) for prefix in normalized_denied):
                    reasons.append(
                        f"tool_access_control: path '{normalized_value}' is denied for session '{session_type}'"
                    )
                    break

    # Session budget cap.
    session_budget = (
        session_config.get("budget_per_session")
        if isinstance(session_config, dict) and isinstance(session_config.get("budget_per_session"), int | float)
        else None
    )
    if isinstance(session_budget, int | float):
        checked.append("tool_access_control")
        cost = _coerce_cost(request.get("cost"))
        safe_cost = cost if isinstance(cost, float) and cost > 0 else 0.0
        if safe_cost > 0:
            spent = state.get_agent_budget_spent(
                agent_id=agent_id,
                window_seconds=86400,
                session_id=session_id,
                now=now,
            )
            if spent + safe_cost > float(session_budget):
                reasons.append(
                    f"tool_access_control: session budget exceeded for '{session_type}' ({spent + safe_cost} > {session_budget})"
                )

    if invalid_tool_name:
        checked.append("tool_access_control")
        reasons.append("tool_access_control: tool name contains control characters")
        return reasons, checked, effective_tier

    default_action = str(policy.get("default_action", "allow")).strip().lower()
    if default_action not in {"allow", "deny"}:
        default_action = "allow"
    request_params = request.get("params")
    safe_params = request_params if isinstance(request_params, dict) else {}
    capability_reasons, capability_checked = _evaluate_capabilities(
        policy=policy,
        tool=tool,
        request_params=safe_params,
        default_action=default_action,
    )
    reasons.extend(capability_reasons)
    checked.extend(capability_checked)

    # Top-level or session-level tool access.
    base_tool_access = policy.get("tool_access") if isinstance(policy.get("tool_access"), dict) else None
    tool_access = _extract_tool_access(base_tool_access, session_config)
    if not isinstance(tool_access, dict):
        return reasons, checked, effective_tier

    mode = str(tool_access.get("mode", "denylist")).strip().lower()
    checked.append("tool_access_control")

    if mode == "allowlist":
        allowed = {
            _normalize_tool_name(item)[0]
            for item in tool_access.get("allowed", [])
            if isinstance(item, str) and item.strip()
        }
        denied = {
            _normalize_tool_name(item)[0]
            for item in tool_access.get("denied", [])
            if isinstance(item, str) and item.strip()
        }
        overrides = tool_access.get("overrides")
        if isinstance(overrides, dict):
            override_entry = overrides.get(agent_id)
            if isinstance(override_entry, dict):
                additional = override_entry.get("additional_allowed")
                if isinstance(additional, list):
                    allowed.update(
                        _normalize_tool_name(item)[0]
                        for item in additional
                        if isinstance(item, str) and item.strip()
                    )
        if tool in denied:
            reasons.append(f"tool_access_control: tool '{tool}' is in denylist")
            return reasons, checked, effective_tier
        if tool not in allowed:
            reasons.append(
                f"tool_access_control: tool '{tool}' not in allowlist (allowed: {sorted(allowed)})"
            )
        return reasons, checked, effective_tier

    if mode == "denylist":
        denied = {
            _normalize_tool_name(item)[0]
            for item in tool_access.get("denied", [])
            if isinstance(item, str) and item.strip()
        }
        if tool in denied:
            reasons.append(f"tool_access_control: tool '{tool}' is in denylist")
        return reasons, checked, effective_tier

    if mode == "tiered":
        tiers = tool_access.get("tiers")
        if not isinstance(tiers, dict):
            reasons.append("tool_access_control: tiered mode requires tiers mapping")
            return reasons, checked, effective_tier
        allowed, denied, wildcard = _tier_allowed_and_denied(tiers, effective_tier)
        if wildcard:
            if tool in denied:
                reasons.append(
                    f"tool_access_control: tool '{tool}' denied for tier '{effective_tier}'"
                )
            return reasons, checked, effective_tier
        if tool not in allowed:
            reasons.append(
                f"tool_access_control: tool '{tool}' not allowed for tier '{effective_tier}' (allowed: {sorted(allowed)})"
            )
        return reasons, checked, effective_tier

    reasons.append(f"tool_access_control: unsupported mode '{mode}'")
    return reasons, checked, effective_tier


def _reset_daily_tokens(now: datetime) -> None:
    global _daily_token_usage_day
    current_day = now.date()
    with _daily_token_usage_lock:
        if _daily_token_usage_day != current_day:
            _daily_token_usage.clear()
            _daily_token_usage_day = current_day


def _get_daily_token_usage(agent_id: str, current_day: date | None = None) -> int:
    """Read per-agent daily token usage with day rollover protection."""
    global _daily_token_usage_day
    with _daily_token_usage_lock:
        day = current_day or date.today()
        if _daily_token_usage_day != day:
            _daily_token_usage.clear()
            _daily_token_usage_day = day
        return int(_daily_token_usage.get(agent_id, 0))


def _set_daily_token_usage(agent_id: str, value: int, current_day: date | None = None) -> None:
    """Write per-agent daily token usage with day rollover protection."""
    global _daily_token_usage_day
    with _daily_token_usage_lock:
        day = current_day or date.today()
        if _daily_token_usage_day != day:
            _daily_token_usage.clear()
            _daily_token_usage_day = day
        _daily_token_usage[agent_id] = int(max(0, value))


def _check_token_limits(
    *,
    policy: dict[str, Any] | None,
    agent_id: str,
    context: dict[str, Any],
    session_type: str,
    now: datetime,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked: list[str] = []
    if not isinstance(policy, dict):
        return reasons, checked

    token_limits = policy.get("token_limits")
    token_limits = token_limits if isinstance(token_limits, dict) else {}
    session_policies = policy.get("session_policies")
    session_config = (
        session_policies.get(session_type)
        if isinstance(session_policies, dict) and isinstance(session_policies.get(session_type), dict)
        else {}
    )
    if not token_limits and not isinstance(session_config, dict):
        return reasons, checked
    if not token_limits and not session_config:
        return reasons, checked

    estimated_raw = context.get("estimated_tokens")
    estimated = int(estimated_raw) if isinstance(estimated_raw, int | float) else 0
    if estimated <= 0:
        return reasons, checked

    checked.append("token_budget")
    max_per_call = session_config.get("max_tokens_per_call") or token_limits.get("max_tokens_per_call")
    if isinstance(max_per_call, int | float) and estimated > int(max_per_call):
        reasons.append(f"token_budget: {estimated} tokens > {int(max_per_call)} max per call")
        return reasons, checked

    session_used_raw = context.get("session_tokens_used")
    session_used = int(session_used_raw) if isinstance(session_used_raw, int | float) else 0
    max_per_session = session_config.get("max_tokens_per_session") or token_limits.get("max_tokens_per_session")
    if isinstance(max_per_session, int | float) and (session_used + estimated) > int(max_per_session):
        reasons.append(
            f"token_budget: session token budget exhausted ({session_used + estimated} > {int(max_per_session)})"
        )
        return reasons, checked

    max_per_day = token_limits.get("max_tokens_per_day")
    if isinstance(max_per_day, int | float):
        _reset_daily_tokens(now)
        used = _get_daily_token_usage(agent_id, now.date())
        projected = used + estimated
        if projected > int(max_per_day):
            reasons.append(
                f"token_budget: daily token budget exhausted for agent '{agent_id}' ({projected} > {int(max_per_day)})"
            )
            return reasons, checked
        _set_daily_token_usage(agent_id, projected, now.date())
        _ = token_limits.get("warn_at_percentage", 80)

    return reasons, checked


def _looks_like_hidden_file(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = [item for item in normalized.split("/") if item]
    return any(part.startswith(".") for part in parts)


def _extract_paths(params: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("path", "file_path", "filename", "directory", "filepath", "target"):
        candidate = params.get(key)
        if isinstance(candidate, str) and candidate.strip():
            values.append(candidate.strip())
    for value in _iter_string_values(params):
        if not isinstance(value, str):
            continue
        if "://" in value:
            continue
        if "/" in value or "\\" in value:
            values.append(value)
    return values


def _extract_network_values(params: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("url", "endpoint", "host", "domain"):
        candidate = params.get(key)
        if isinstance(candidate, str) and candidate.strip():
            values.append(candidate.strip())
    for value in _iter_string_values(params):
        if isinstance(value, str) and ("http://" in value or "https://" in value):
            values.append(value)
    return values


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _check_sandbox(
    *,
    policy: dict[str, Any] | None,
    request: dict[str, Any],
    session_type: str,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked: list[str] = []
    if not isinstance(policy, dict):
        return reasons, checked
    session_policies = policy.get("session_policies")
    session_config = (
        session_policies.get(session_type)
        if isinstance(session_policies, dict) and isinstance(session_policies.get(session_type), dict)
        else None
    )
    if not isinstance(session_config, dict):
        return reasons, checked
    sandbox = session_config.get("sandbox")
    if not isinstance(sandbox, dict):
        return reasons, checked

    tool_name = request.get("tool")
    tool = tool_name if isinstance(tool_name, str) and tool_name else "__unknown__"
    params = request.get("params")
    safe_params = params if isinstance(params, dict) else {}
    checked.append("sandbox")

    filesystem = sandbox.get("filesystem")
    if isinstance(filesystem, dict):
        paths = _extract_paths(safe_params)
        denied_paths = [
            _normalize_path(item)
            for item in filesystem.get("denied_paths", [])
            if isinstance(item, str) and item.strip()
        ]
        if denied_paths:
            for raw in paths:
                try:
                    normalized = _normalize_path(raw)
                except Exception:
                    continue
                if any(normalized.startswith(prefix) for prefix in denied_paths):
                    reasons.append(f"sandbox: filesystem path '{normalized}' denied for session '{session_type}'")
                    break
        if not reasons:
            allowed_paths = [
                _normalize_path(item)
                for item in filesystem.get("allowed_paths", [])
                if isinstance(item, str) and item.strip()
            ]
            if allowed_paths:
                for raw in paths:
                    try:
                        normalized = _normalize_path(raw)
                    except Exception:
                        continue
                    if not any(normalized.startswith(prefix) for prefix in allowed_paths):
                        reasons.append(
                            f"sandbox: filesystem path '{normalized}' outside allowed_paths for session '{session_type}'"
                        )
                        break
        if not reasons and bool(filesystem.get("deny_hidden_files")):
            for raw in paths:
                if _looks_like_hidden_file(raw):
                    reasons.append(f"sandbox: hidden file access denied for session '{session_type}'")
                    break
        max_file_size = filesystem.get("max_file_size_bytes")
        file_size = safe_params.get("file_size_bytes")
        if not isinstance(file_size, int | float):
            file_size = safe_params.get("size")
        if isinstance(max_file_size, int | float) and isinstance(file_size, int | float):
            if int(file_size) > int(max_file_size):
                reasons.append(
                    f"sandbox: file size {int(file_size)} exceeds max_file_size_bytes {int(max_file_size)}"
                )

    if not reasons:
        network = sandbox.get("network")
        if isinstance(network, dict):
            values = _extract_network_values(safe_params)
            denied_domains = {
                item.lower()
                for item in network.get("denied_domains", [])
                if isinstance(item, str) and item.strip()
            }
            allowed_domains = {
                item.lower()
                for item in network.get("allowed_domains", [])
                if isinstance(item, str) and item.strip()
            }
            deny_ip = bool(network.get("deny_ip_addresses"))
            for raw in values:
                parsed = urlparse(raw) if "://" in raw else None
                host = parsed.hostname if parsed is not None else raw
                if not isinstance(host, str):
                    continue
                safe_host = host.lower().strip()
                if deny_ip and _is_ip_address(safe_host):
                    reasons.append(f"sandbox: IP address '{safe_host}' denied for session '{session_type}'")
                    break
                if denied_domains and any(
                    safe_host == denied or safe_host.endswith(f".{denied}") for denied in denied_domains
                ):
                    reasons.append(f"sandbox: domain '{safe_host}' denied for session '{session_type}'")
                    break
                if allowed_domains and not any(
                    safe_host == allowed or safe_host.endswith(f".{allowed}") for allowed in allowed_domains
                ):
                    reasons.append(f"sandbox: domain '{safe_host}' not in allowlist for session '{session_type}'")
                    break
            max_request_size = network.get("max_request_size_bytes")
            request_size = safe_params.get("request_size_bytes")
            if not isinstance(request_size, int | float):
                request_size = safe_params.get("size")
            if isinstance(max_request_size, int | float) and isinstance(request_size, int | float):
                if int(request_size) > int(max_request_size):
                    reasons.append(
                        f"sandbox: request size {int(request_size)} exceeds max_request_size_bytes {int(max_request_size)}"
                    )

    if not reasons:
        execution = sandbox.get("execution")
        if isinstance(execution, dict):
            normalized_tool = tool.lower()
            command_value = safe_params.get("command")
            command_text = command_value if isinstance(command_value, str) else ""
            shell_like = any(token in normalized_tool for token in ("shell", "exec", "command"))
            eval_like = "eval" in normalized_tool or "eval(" in command_text.lower()
            subprocess_like = "subprocess" in normalized_tool or "subprocess" in command_text.lower()
            if bool(execution.get("deny_shell")) and shell_like:
                reasons.append(f"sandbox: shell execution denied for session '{session_type}'")
            if not reasons and bool(execution.get("deny_eval")) and eval_like:
                reasons.append(f"sandbox: eval execution denied for session '{session_type}'")
            if not reasons and bool(execution.get("deny_subprocess")) and subprocess_like:
                reasons.append(f"sandbox: subprocess execution denied for session '{session_type}'")
            allowed_commands = [
                item for item in execution.get("allowed_commands", []) if isinstance(item, str) and item.strip()
            ]
            if not reasons and allowed_commands and command_text:
                if not any(command_text.strip().startswith(prefix) for prefix in allowed_commands):
                    reasons.append("sandbox: command not in allowed_commands")

    if not reasons:
        data_cfg = sandbox.get("data")
        if isinstance(data_cfg, dict):
            output_value = safe_params.get("output")
            if not isinstance(output_value, str):
                output_value = safe_params.get("content")
            if not isinstance(output_value, str):
                output_value = safe_params.get("text")
            output_text = output_value if isinstance(output_value, str) else ""
            max_output_length = data_cfg.get("max_output_length")
            if isinstance(max_output_length, int | float) and output_text:
                if len(output_text) > int(max_output_length):
                    reasons.append(
                        f"sandbox: output length {len(output_text)} exceeds max_output_length {int(max_output_length)}"
                    )
            if not reasons and bool(data_cfg.get("deny_secrets_in_output")) and output_text:
                if _SECRET_SCANNER.scan_text(output_text):
                    reasons.append("sandbox: secrets detected in output")
            if not reasons and bool(data_cfg.get("deny_pii_in_output")) and output_text:
                if _PII_DETECTOR.scan_text(output_text):
                    reasons.append("sandbox: pii detected in output")

    return reasons, checked


def _check_channel_policy(
    *,
    policy: dict[str, Any] | None,
    request: dict[str, Any],
    context: dict[str, Any],
    channel: str | None,
    tracker: RateLimitTracker,
    now: datetime,
    session_id: str,
    effective_tier: str,
) -> tuple[list[str], list[str], str]:
    reasons: list[str] = []
    checked: list[str] = []
    resolved_tier = effective_tier
    if not isinstance(policy, dict):
        return reasons, checked, resolved_tier
    channel_name = channel
    if not isinstance(channel_name, str) or not channel_name.strip():
        raw = context.get("channel")
        channel_name = raw if isinstance(raw, str) and raw.strip() else None
    if not isinstance(channel_name, str) or not channel_name.strip():
        return reasons, checked, resolved_tier
    normalized_channel = channel_name.strip().lower()
    channel_policies = policy.get("channel_policies")
    channel_config = (
        channel_policies.get(normalized_channel)
        if isinstance(channel_policies, dict) and isinstance(channel_policies.get(normalized_channel), dict)
        else None
    )
    if not isinstance(channel_config, dict):
        return reasons, checked, resolved_tier

    checked.append("channel_policy")
    tool_name = request.get("tool")
    tool = tool_name if isinstance(tool_name, str) and tool_name else "__unknown__"

    denied_tools = {
        item for item in channel_config.get("denied_tools", []) if isinstance(item, str) and item.strip()
    }
    if tool in denied_tools:
        reasons.append(f"channel_policy: tool '{tool}' denied for channel '{normalized_channel}'")
        return reasons, checked, resolved_tier

    approval_tools = {
        item
        for item in channel_config.get("require_approval_for", [])
        if isinstance(item, str) and item.strip()
    }
    if tool in approval_tools:
        reasons.append(
            f"channel_policy: requires_human_approval for tool '{tool}' on channel '{normalized_channel}'"
        )
        return reasons, checked, resolved_tier

    max_per_minute = channel_config.get("max_requests_per_minute")
    if isinstance(max_per_minute, int):
        over_limit = tracker.check_and_record(
            f"__channel__:{normalized_channel}",
            max_requests=max_per_minute,
            window_seconds=60,
            timestamp=now,
            agent_id="__channel_policy__",
            session_id=f"channel:{normalized_channel}:{session_id}",
        )
        if over_limit:
            reasons.append(
                f"channel_policy: channel '{normalized_channel}' exceeded max_requests_per_minute {max_per_minute}"
            )
            return reasons, checked, resolved_tier

    channel_tier = channel_config.get("trust_tier")
    resolved_tier = min_tier(channel_tier if isinstance(channel_tier, str) else None, effective_tier)
    tool_access = policy.get("tool_access")
    if isinstance(tool_access, dict):
        mode = str(tool_access.get("mode", "")).lower()
        if mode == "tiered":
            tiers = tool_access.get("tiers")
            if isinstance(tiers, dict):
                allowed, denied, wildcard = _tier_allowed_and_denied(tiers, resolved_tier)
                if tool in denied:
                    reasons.append(
                        f"channel_policy: tool '{tool}' denied for effective tier '{resolved_tier}' on channel '{normalized_channel}'"
                    )
                    return reasons, checked, resolved_tier
                if not wildcard and tool not in allowed:
                    reasons.append(
                        f"channel_policy: tool '{tool}' not allowed for effective tier '{resolved_tier}' on channel '{normalized_channel}'"
                    )
                    return reasons, checked, resolved_tier

    return reasons, checked, resolved_tier


def _is_modify_or_destructive_action(request: dict[str, Any]) -> bool:
    tool_name = request.get("tool")
    if isinstance(tool_name, str):
        normalized_tool = tool_name.strip().lower()
    else:
        normalized_tool = ""
    modify_keywords = ("write", "delete", "modify", "update", "create", "remove")
    if any(keyword in normalized_tool for keyword in modify_keywords):
        return True

    params = request.get("params")
    query = params.get("query") if isinstance(params, dict) else None
    if isinstance(query, str):
        upper_query = _sanitize_text(query).upper()
        for operation in ("UPDATE", "DELETE", "INSERT", "CREATE", "DROP", "ALTER", "TRUNCATE"):
            if _query_contains_operation(upper_query, operation):
                return True
    return False


def _apply_identity_check(
    request: dict[str, Any],
    identity: AgentIdentity,
) -> tuple[list[str], list[str], bool]:
    reasons: list[str] = []
    checked = ["identity_check"]
    tool, _invalid_tool_name = _normalize_tool_name(request.get("tool"))

    if identity.trust_tier == TrustTier.BLOCKED:
        reasons.append(f"identity: agent '{identity.agent_id}' is blocked")
        return reasons, checked, True

    if identity.trust_tier == TrustTier.PRINCIPAL:
        return reasons, [], False

    denied_tools = identity.denied_tools if isinstance(identity.denied_tools, list) else None
    if denied_tools is not None and tool in denied_tools:
        reasons.append(
            f"identity: tool '{tool}' is explicitly denied for agent '{identity.agent_id}'"
        )

    allowed_tools = identity.allowed_tools if isinstance(identity.allowed_tools, list) else None
    if allowed_tools is not None and tool not in allowed_tools:
        reasons.append(
            f"identity: tool '{tool}' is not in allowed_tools for agent '{identity.agent_id}'"
        )

    if not check_capability(identity, tool):
        reasons.append(
            f"identity: agent '{identity.agent_id}' tier '{identity.trust_tier.name.lower()}' "
            f"lacks capability for tool '{tool}'"
        )

    if identity.trust_tier == TrustTier.INTERN and _is_modify_or_destructive_action(request):
        reasons.append(
            f"identity: intern agent '{identity.agent_id}' cannot perform write/delete/modify operations"
        )

    return reasons, checked, False


def _resolve_rule_type(rule: dict[str, Any]) -> tuple[str | None, bool]:
    raw_type = rule.get("type")
    if isinstance(raw_type, str) and raw_type.strip():
        return raw_type.strip(), True
    name = rule.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip(), False
    return None, False


def _extract_field(request: dict[str, Any], field_path: str) -> Any:
    current: Any = request
    for segment in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _get_path(request: dict[str, Any]) -> str | None:
    params = request.get("params")
    if not isinstance(params, dict):
        return None
    raw = params.get("path")
    if not isinstance(raw, str):
        return None
    if "\x00" in raw or any(ch in raw for ch in ("\t", "\n", "\r")):
        return "/__invalid_control_char_path__"
    return _normalize_path(raw)


def _query_contains_operation(query: str, operation: str) -> bool:
    normalized = _sanitize_text(query)
    without_comments = re.sub(r"/\*.*?\*/", " ", normalized, flags=re.DOTALL)
    return _operation_pattern(operation.upper()).search(without_comments.upper()) is not None


def _is_unsafe_regex_pattern(pattern: str) -> bool:
    return re.search(r"\([^)]*[+*][^)]*\)[+*?]", pattern) is not None


@lru_cache(maxsize=64)
def _operation_pattern(operation_upper: str) -> re.Pattern[str]:
    pattern = r"\b" + r"\s*".join(re.escape(ch) for ch in operation_upper) + r"\b"
    return re.compile(pattern)


@lru_cache(maxsize=256)
def _compiled_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _apply_budget_limit(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    agent_id: str,
    session_id: str,
    agent_budget_spent: float | None = None,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["budget_limit"]

    max_cost = rule.get("max_cost_per_call")
    cost = _coerce_cost(request.get("cost"))
    if isinstance(max_cost, int | float) and cost is not None:
        if cost < 0:
            reasons.append("budget_limit: cost must be non-negative")
        elif cost > max_cost:
            reasons.append(f"budget_limit: cost {cost} exceeds max_cost_per_call {max_cost}")

    daily_budget = rule.get("daily_budget")
    if isinstance(daily_budget, int | float):
        spent = (
            agent_budget_spent
            if isinstance(agent_budget_spent, int | float)
            else state.get_agent_budget_spent(
                agent_id, window_seconds=86400, session_id=session_id
            )
        )
        if cost is None:
            projected = spent
        elif cost < 0:
            projected = spent
        else:
            projected = spent + cost
        if projected > daily_budget:
            reasons.append(
                f"budget_limit: agent '{agent_id}' daily budget exceeded ({projected} > {daily_budget})"
            )
    return reasons, checked


def _apply_rate_limit(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    agent_id: str,
    session_id: str,
    now: datetime,
    dry_run: bool = False,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["rate_limit"]
    max_per_minute = rule.get("max_requests_per_minute")
    if not isinstance(max_per_minute, int):
        return reasons, checked

    scope = str(rule.get("scope", "tool")).strip().lower()
    tool, _invalid_tool_name = _normalize_tool_name(request.get("tool"))
    counter_key = "__global__" if scope == "global" else tool
    if dry_run:
        over_limit = state.is_over_limit(
            counter_key, max_per_minute, 60, now=now, agent_id=agent_id, session_id=session_id
        )
    else:
        over_limit = state.check_and_record(
            counter_key,
            max_requests=max_per_minute,
            window_seconds=60,
            timestamp=now,
            agent_id=agent_id,
            session_id=session_id,
        )
    if over_limit:
        reasons.append(
            f"rate_limit: tool '{tool}' exceeded max_requests_per_minute {max_per_minute}"
        )
    return reasons, checked


def _apply_file_access(
    rule: dict[str, Any], request: dict[str, Any]
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["file_access"]
    params = request.get("params")
    raw_path = params.get("path") if isinstance(params, dict) else None
    if isinstance(raw_path, str) and (
        "\x00" in raw_path or any(ch in raw_path for ch in ("\t", "\n", "\r"))
    ):
        reasons.append("file_access: path contains control characters")
        return reasons, checked
    path = _get_path(request)
    if path is None:
        return reasons, checked

    denied_paths = rule.get("denied_paths")
    if isinstance(denied_paths, list):
        for denied_path in denied_paths:
            if isinstance(denied_path, str) and path.startswith(_normalize_path(denied_path)):
                reasons.append(f"file_access: path '{path}' is denied by '{denied_path}'")
                break

    allowed_paths = rule.get("allowed_paths")
    if isinstance(allowed_paths, list) and allowed_paths:
        allowed_match = any(
            isinstance(allowed_path, str) and path.startswith(_normalize_path(allowed_path))
            for allowed_path in allowed_paths
        )
        if not allowed_match:
            reasons.append(f"file_access: path '{path}' is outside allowed_paths")

    return reasons, checked


def _apply_sql_restriction(
    rule: dict[str, Any], request: dict[str, Any]
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["sql_restriction"]
    params = request.get("params")
    query = params.get("query") if isinstance(params, dict) else None
    if not isinstance(query, str):
        return reasons, checked

    denied_operations = rule.get("denied_operations")
    if isinstance(denied_operations, list):
        denied_upper = {op.upper() for op in denied_operations if isinstance(op, str)}
        for op in denied_upper:
            if _query_contains_operation(query, op):
                reasons.append(f"sql_restriction: {op} is denied")
                break

    return reasons, checked


def _apply_regex_match(
    rule: dict[str, Any], request: dict[str, Any]
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["regex_match"]
    field = rule.get("field")
    value = _extract_field(request, field) if isinstance(field, str) else None
    if not isinstance(value, str):
        return reasons, checked
    if "\x00" in value:
        reasons.append(f"regex_match: field '{field}' contains null byte")
        return reasons, checked

    deny_patterns = rule.get("deny_patterns")
    if isinstance(deny_patterns, list):
        for pattern in deny_patterns:
            if not isinstance(pattern, str):
                continue
            if _is_unsafe_regex_pattern(pattern):
                reasons.append(f"regex_match: pattern '{pattern}' rejected as unsafe regex")
                break
            if _compiled_regex(pattern).search(_sanitize_text(value)):
                reasons.append(f"regex_match: field '{field}' matched deny pattern '{pattern}'")
                break
    return reasons, checked


def _apply_context_rules(
    rule: dict[str, Any], request: dict[str, Any]
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["context_rules"]

    context = request.get("context")
    if not isinstance(context, dict):
        return reasons, checked

    agent_raw = context.get("agent")
    if not isinstance(agent_raw, str):
        return reasons, checked

    if "\x00" in agent_raw:
        reasons.append("context_rules: agent contains null byte")
    agent = _sanitize_text(agent_raw)
    if agent == "":
        reasons.append("context_rules: agent must be non-empty")
        return reasons, checked
    if agent == "*":
        reasons.append("context_rules: literal '*' agent value is not allowed")

    entries = rule.get("rules")
    if not isinstance(entries, list):
        return reasons, checked

    exact = [
        item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("agent"), str) and item["agent"] == agent
    ]
    selected = exact or [
        item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("agent"), str) and item["agent"] == "*"
    ]

    for item in selected:
        denied_tools = item.get("denied_tools")
        if isinstance(denied_tools, list):
            tool_name, _invalid_tool = _normalize_tool_name(request.get("tool"))
            normalized_denied = {
                _normalize_tool_name(candidate)[0]
                for candidate in denied_tools
                if isinstance(candidate, str) and candidate.strip()
            }
            if tool_name in normalized_denied:
                reasons.append(
                    f"context_rules: agent '{agent}' is not allowed to call tool '{tool_name}'"
                )

        max_cost = item.get("max_cost_per_call")
        cost = _coerce_cost(request.get("cost"))
        if isinstance(max_cost, int | float) and cost is not None:
            if cost < 0:
                reasons.append("context_rules: cost must be non-negative")
            elif cost > max_cost:
                reasons.append(
                    f"context_rules: agent '{agent}' cost {cost} exceeds max_cost_per_call {max_cost}"
                )

    return reasons, checked


def _apply_composite(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    agent_id: str,
    session_id: str,
    now: datetime,
    all_rules_by_name: dict[str, dict[str, Any]],
    visited: set[str],
    max_cost_per_call_override: float | None = None,
    daily_budget_override: float | None = None,
    rate_limit_per_minute_override: int | None = None,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["composite"]
    operator = rule.get("operator")
    conditions = rule.get("conditions")
    if not isinstance(operator, str) or not isinstance(conditions, list):
        return reasons, checked

    rule_name = rule.get("name") if isinstance(rule.get("name"), str) else "<unnamed>"
    if rule_name in visited:
        reasons.append(f"composite: circular reference detected at '{rule_name}'")
        return reasons, checked

    next_visited = set(visited)
    next_visited.add(rule_name)

    condition_passes: list[bool] = []
    for condition in conditions:
        if not isinstance(condition, dict):
            condition_passes.append(False)
            reasons.append("composite: invalid condition entry")
            continue
        ref_name = condition.get("rule")
        if not isinstance(ref_name, str):
            condition_passes.append(False)
            reasons.append("composite: condition missing rule reference")
            continue
        ref_rule = all_rules_by_name.get(ref_name)
        if ref_rule is None:
            condition_passes.append(False)
            reasons.append(f"composite: referenced rule '{ref_name}' is missing")
            continue

        ref_type, _ = _resolve_rule_type(ref_rule)
        ref_reasons: list[str]
        if ref_type == "budget_limit":
            effective_ref_rule = dict(ref_rule)
            if max_cost_per_call_override is not None:
                effective_ref_rule["max_cost_per_call"] = max_cost_per_call_override
            if daily_budget_override is not None:
                effective_ref_rule["daily_budget"] = daily_budget_override
            ref_reasons, _ = _apply_budget_limit(
                effective_ref_rule,
                request,
                state=state,
                agent_id=agent_id,
                session_id=session_id,
            )
        elif ref_type == "rate_limit":
            effective_ref_rule = dict(ref_rule)
            if rate_limit_per_minute_override is not None:
                effective_ref_rule["max_requests_per_minute"] = rate_limit_per_minute_override
            ref_reasons, _ = _apply_rate_limit(
                effective_ref_rule,
                request,
                state=state,
                agent_id=agent_id,
                session_id=session_id,
                now=now,
                dry_run=True,
            )
        elif ref_type == "file_access":
            ref_reasons, _ = _apply_file_access(ref_rule, request)
        elif ref_type == "sql_restriction":
            ref_reasons, _ = _apply_sql_restriction(ref_rule, request)
        elif ref_type == "regex_match":
            ref_reasons, _ = _apply_regex_match(ref_rule, request)
        elif ref_type == "context_rules":
            ref_reasons, _ = _apply_context_rules(ref_rule, request)
        elif ref_type == "composite":
            ref_reasons, _ = _apply_composite(
                ref_rule,
                request,
                state=state,
                agent_id=agent_id,
                session_id=session_id,
                now=now,
                all_rules_by_name=all_rules_by_name,
                visited=next_visited,
                max_cost_per_call_override=max_cost_per_call_override,
                daily_budget_override=daily_budget_override,
                rate_limit_per_minute_override=rate_limit_per_minute_override,
            )
        else:
            ref_reasons = [f"composite: referenced rule '{ref_name}' is unsupported"]

        passed = len(ref_reasons) == 0
        condition_passes.append(passed)
        if not passed:
            reasons.append(f"composite: condition '{ref_name}' failed")

    op = operator.upper()
    if op == "AND":
        if all(condition_passes):
            reasons.clear()
    elif op == "OR":
        if any(condition_passes):
            reasons.clear()
        elif not reasons:
            reasons.append("composite: no OR condition passed")
    else:
        reasons.append(f"composite: unsupported operator '{operator}'")

    return reasons, checked


_RULE_HANDLERS: dict[str, str] = {
    "budget_limit": "_apply_budget_limit",
    "rate_limit": "_apply_rate_limit",
    "file_access": "_apply_file_access",
    "sql_restriction": "_apply_sql_restriction",
    "regex_match": "_apply_regex_match",
    "context_rules": "_apply_context_rules",
    "composite": "_apply_composite",
}


class PolicyEngine:
    """Stateful wrapper around module-level evaluate()."""

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        *,
        state: RateLimitTracker | None = None,
        emitter: EventEmitter | None = None,
        registry: AgentRegistry | None = None,
        plugins: PluginRegistry | None = None,
    ):
        self._policy = policy or {"rules": []}
        self._state = state if state is not None else RateLimitTracker(persist_path=None)
        self._emitter = emitter
        self._registry = registry
        self._plugins = plugins

    @property
    def policy(self) -> dict[str, Any]:
        return self._policy

    def set_policy(self, policy: dict[str, Any]) -> None:
        self._policy = policy

    def evaluate(
        self,
        request: dict[str, Any],
        *,
        now: datetime | None = None,
        debug: bool = False,
        session_type: str = "cli",
        channel: str | None = None,
        fail_fast: bool = False,
    ) -> Decision:
        return evaluate(
            request=request,
            policy=self._policy,
            state=self._state,
            emitter=self._emitter,
            registry=self._registry,
            plugins=self._plugins,
            now=now,
            debug=debug,
            session_type=session_type,
            channel=channel,
            fail_fast=fail_fast,
        )


def evaluate(
    request: dict[str, Any],
    policy: dict[str, Any] | None,
    *,
    state: RateLimitTracker | None = None,
    emitter: EventEmitter | None = None,
    registry: AgentRegistry | None = None,
    plugins: PluginRegistry | None = None,
    now: datetime | None = None,
    debug: bool = False,
    session_type: str = "cli",
    channel: str | None = None,
    fail_fast: bool = False,
) -> Decision:
    """Evaluate request against policy rules."""
    started_ns = time.perf_counter_ns()
    reasons: list[str] = []
    rules_checked: list[str] = []
    tracker = state or RateLimitTracker(persist_path=None)
    evaluation_now = now if now is not None else datetime.now(timezone.utc)
    agent_id = _resolve_agent_id(request)
    session_id = _resolve_session_id(request)
    identity_getter = getattr(registry, "get", None) if registry is not None else None
    identity = identity_getter(agent_id) if callable(identity_getter) else None
    effective_tier_for_eval = _normalize_tier(identity)
    policy_version_hash = _policy_version_hash(policy) if (emitter is not None or debug) else ""
    policy_version = policy_version_hash if emitter is not None else None
    policy_fail_fast = False
    if isinstance(policy, dict):
        engine_cfg = policy.get("engine")
        if isinstance(engine_cfg, dict):
            policy_fail_fast = bool(engine_cfg.get("fail_fast", False))
    effective_fail_fast = bool(fail_fast or policy_fail_fast)
    decision: Decision
    debug_rule_results: list[dict[str, Any]] = []
    debug_identity_passed = identity is None
    decision_reason: str | None = None
    per_tool_rate_limit_meta: dict[str, Any] | None = None

    tool_access_reasons, tool_access_checked, effective_tier_for_eval = _evaluate_tool_access_control(
        policy=policy,
        request=request,
        state=tracker,
        agent_id=agent_id,
        session_id=session_id,
        session_type=session_type,
        identity=identity,
        now=evaluation_now,
    )
    reasons.extend(tool_access_reasons)
    rules_checked.extend(tool_access_checked)
    if effective_fail_fast and tool_access_reasons:
        decision_reason = "fail_fast:tool_access_control"
        decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
            decision_reason=decision_reason,
            decision_context={"denied_by_rule": "tool_access_control"},
        )
        return decision
    if debug and tool_access_checked:
        debug_rule_results.append(
            {
                "rule": "tool_access_control",
                "passed": len(tool_access_reasons) == 0,
                "duration_us": 0,
                "reason": tool_access_reasons[0] if tool_access_reasons else "",
            }
        )

    per_tool_rate_limit = _resolve_per_tool_rate_limit(
        policy=policy,
        request=request,
        session_type=session_type,
    )
    context = request.get("context")
    safe_context = context if isinstance(context, dict) else {}
    token_reasons, token_checked = _check_token_limits(
        policy=policy,
        agent_id=agent_id,
        context=safe_context,
        session_type=session_type,
        now=evaluation_now,
    )
    reasons.extend(token_reasons)
    rules_checked.extend(token_checked)
    if effective_fail_fast and token_reasons:
        decision_reason = "fail_fast:token_budget"
        decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
            decision_reason=decision_reason,
            decision_context={"denied_by_rule": "token_budget"},
        )
        return decision
    if debug and token_checked:
        debug_rule_results.append(
            {
                "rule": "token_budget",
                "passed": len(token_reasons) == 0,
                "duration_us": 0,
                "reason": token_reasons[0] if token_reasons else "",
            }
        )

    channel_reasons, channel_checked, effective_tier_for_eval = _check_channel_policy(
        policy=policy,
        request=request,
        context=safe_context,
        channel=channel,
        tracker=tracker,
        now=evaluation_now,
        session_id=session_id,
        effective_tier=effective_tier_for_eval,
    )
    reasons.extend(channel_reasons)
    rules_checked.extend(channel_checked)
    if effective_fail_fast and channel_reasons:
        decision_reason = "fail_fast:channel_policy"
        decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
            decision_reason=decision_reason,
            decision_context={"denied_by_rule": "channel_policy"},
        )
        return decision
    if debug and channel_checked:
        debug_rule_results.append(
            {
                "rule": "channel_policy",
                "passed": len(channel_reasons) == 0,
                "duration_us": 0,
                "reason": channel_reasons[0] if channel_reasons else "",
            }
        )

    sandbox_reasons, sandbox_checked = _check_sandbox(
        policy=policy,
        request=request,
        session_type=session_type,
    )
    reasons.extend(sandbox_reasons)
    rules_checked.extend(sandbox_checked)
    if effective_fail_fast and sandbox_reasons:
        decision_reason = "fail_fast:sandbox"
        decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
            decision_reason=decision_reason,
            decision_context={"denied_by_rule": "sandbox"},
        )
        return decision
    if debug and sandbox_checked:
        debug_rule_results.append(
            {
                "rule": "sandbox",
                "passed": len(sandbox_reasons) == 0,
                "duration_us": 0,
                "reason": sandbox_reasons[0] if sandbox_reasons else "",
            }
        )

    def _attach_debug_trace(target: Decision) -> None:
        if not debug:
            return
        try:
            snapshot = _build_state_snapshot(tracker, agent_id, session_id)
        except Exception:
            snapshot = {"error": "state_unavailable"}
        total_duration_us = max(0, (time.perf_counter_ns() - started_ns) // 1000)
        target.debug_trace = {
            "evaluation_order": [
                "tool_access_control",
                "per_tool_rate_limit",
                "token_budget",
                "channel_policy",
                "sandbox",
                *[name for name in RULE_EVALUATION_ORDER if name != "identity_check"],
            ],
            "rule_results": list(debug_rule_results),
            "agent_id": agent_id,
            "agent_tier": effective_tier_for_eval,
            "identity_check_passed": bool(debug_identity_passed),
            "total_duration_us": int(total_duration_us),
            "policy_version": policy_version_hash,
            "state_snapshot": snapshot,
        }

    if per_tool_rate_limit is not None:
        rules_checked.append("per_tool_rate_limit")
        limiter = ToolRateLimiter(tracker, agent_id, session_id)
        over_limit, current_count = limiter.check_and_record(
            tool_name=str(per_tool_rate_limit["tool"]),
            max_requests=int(per_tool_rate_limit["max_requests"]),
            window_seconds=int(per_tool_rate_limit["window_seconds"]),
            now=evaluation_now,
        )
        if over_limit:
            tool = str(per_tool_rate_limit["tool"])
            max_requests = int(per_tool_rate_limit["max_requests"])
            unit = str(per_tool_rate_limit["unit"])
            reasons.append(
                f"rate_limit_exceeded: {tool} limited to {max_requests}/{unit} (current: {current_count})"
            )
            decision_reason = "per_tool_rate_limit"
            per_tool_rate_limit_meta = {
                "tool": tool,
                "limit": f"{max_requests}/{unit}",
                "max_requests": max_requests,
                "window_seconds": int(per_tool_rate_limit["window_seconds"]),
                "current_count": current_count,
            }
            decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
            _attach_debug_trace(decision)
            _emit_event(
                emitter=emitter,
                request=request,
                policy=policy,
                agent_id=agent_id,
                tracker=tracker,
                session_id=session_id,
                decision=decision,
                started_ns=started_ns,
                policy_version=policy_version,
                decision_reason=decision_reason,
                decision_context=per_tool_rate_limit_meta,
            )
            return decision

    if identity is not None:
        identity_reasons, identity_checked, blocked_immediately = _apply_identity_check(
            request, identity
        )
        reasons.extend(identity_reasons)
        rules_checked.extend(identity_checked)
        debug_identity_passed = len(identity_reasons) == 0
        if debug:
            debug_rule_results.append(
                {
                    "rule": "identity_check",
                    "passed": debug_identity_passed,
                    "duration_us": 0,
                    "reason": identity_reasons[0] if identity_reasons else "",
                }
            )
        if blocked_immediately:
            decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
            _attach_debug_trace(decision)
            _emit_event(
                emitter=emitter,
                request=request,
                policy=policy,
                agent_id=agent_id,
                tracker=tracker,
                session_id=session_id,
                decision=decision,
                started_ns=started_ns,
                policy_version=policy_version,
            )
            return decision

    if not policy:
        if registry is not None and hasattr(registry, "run_all"):
            try:
                evaluator_results = registry.run_all(request, safe_context)
            except Exception as error:  # noqa: BLE001
                evaluator_results = []
                reasons.append(f"warning: evaluator registry unavailable ({error})")
            for result in evaluator_results:
                action = getattr(result, "action", "allow")
                reason = str(getattr(result, "reason", ""))
                if action == "deny":
                    reasons.append(f"evaluator:{reason}")
                elif action == "warn":
                    reasons.append(f"warning:evaluator:{reason}")
        decision = Decision(
            allowed=len(reasons) == 0, reasons=reasons, rules_checked=rules_checked
        )
        _attach_debug_trace(decision)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
        )
        return decision

    rules = policy.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        if registry is not None and hasattr(registry, "run_all"):
            try:
                evaluator_results = registry.run_all(request, safe_context)
            except Exception as error:  # noqa: BLE001
                evaluator_results = []
                reasons.append(f"warning: evaluator registry unavailable ({error})")
            for result in evaluator_results:
                action = getattr(result, "action", "allow")
                reason = str(getattr(result, "reason", ""))
                if action == "deny":
                    reasons.append(f"evaluator:{reason}")
                elif action == "warn":
                    reasons.append(f"warning:evaluator:{reason}")
        decision = Decision(
            allowed=len(reasons) == 0, reasons=reasons, rules_checked=rules_checked
        )
        _attach_debug_trace(decision)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            session_id=session_id,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
        )
        return decision

    cached_plan = _get_policy_plan(policy, rules)
    all_rules_by_name = cached_plan["all_rules_by_name"]
    ordered = cached_plan["ordered"]
    unknown_explicit_rules = cached_plan["unknown_explicit_rules"]
    legacy_unknown_name_rules = cached_plan["legacy_unknown_name_rules"]
    cached_agent_spent: float | None = None
    effective_max_cost_per_call = identity.max_cost_per_call if identity is not None else None
    effective_daily_budget = identity.daily_budget if identity is not None else None
    effective_rate_limit_per_minute = (
        identity.rate_limit_per_minute if identity is not None else None
    )
    # Per-tool limits should not be tightened further by identity override;
    # keep global rate-limit rule evaluation with its own configured threshold.
    if per_tool_rate_limit is not None:
        effective_rate_limit_per_minute = None
    effective_daily_budget_limit: float | None = None

    for rule_type in RULE_EVALUATION_ORDER:
        if rule_type == "identity_check":
            continue
        handler_name = _RULE_HANDLERS.get(rule_type)
        handler = globals().get(handler_name) if isinstance(handler_name, str) else None
        if handler is None:
            continue
        for rule in ordered[rule_type]:
            rule_for_eval = rule
            if rule_type == "budget_limit" and (
                effective_max_cost_per_call is not None or effective_daily_budget is not None
            ):
                rule_for_eval = dict(rule)
                if effective_max_cost_per_call is not None:
                    rule_for_eval["max_cost_per_call"] = effective_max_cost_per_call
                if effective_daily_budget is not None:
                    rule_for_eval["daily_budget"] = effective_daily_budget
            elif rule_type == "rate_limit":
                if per_tool_rate_limit is not None:
                    rule_for_eval = dict(rule_for_eval)
                    rule_for_eval["scope"] = "global"
                if effective_rate_limit_per_minute is not None:
                    rule_for_eval = dict(rule_for_eval)
                    rule_for_eval["max_requests_per_minute"] = effective_rate_limit_per_minute
            if rule_type == "budget_limit":
                candidate_budget = rule_for_eval.get("daily_budget")
                if isinstance(candidate_budget, int | float):
                    if (
                        effective_daily_budget_limit is None
                        or float(candidate_budget) < effective_daily_budget_limit
                    ):
                        effective_daily_budget_limit = float(candidate_budget)

            rule_name = rule.get("name")
            safe_rule_name = rule_name if isinstance(rule_name, str) else rule_type
            rule_started_ns = time.perf_counter_ns() if debug else 0
            try:
                if rule_type == "budget_limit":
                    try:
                        has_daily_budget = isinstance(
                            rule_for_eval.get("daily_budget"), int | float
                        )
                        if has_daily_budget and cached_agent_spent is None:
                            cached_agent_spent = tracker.get_agent_budget_spent(
                                agent_id,
                                window_seconds=86400,
                                session_id=session_id,
                                now=evaluation_now,
                            )
                        rule_reasons, checked = handler(
                            rule_for_eval,
                            request,
                            state=tracker,
                            agent_id=agent_id,
                            session_id=session_id,
                            agent_budget_spent=cached_agent_spent if has_daily_budget else None,
                        )
                    except Exception:
                        rule_reasons = [
                            "state_error: rate limit state unavailable, denying for safety"
                        ]
                        checked = ["budget_limit"]
                elif rule_type == "rate_limit":
                    try:
                        rule_reasons, checked = handler(
                            rule_for_eval,
                            request,
                            state=tracker,
                            agent_id=agent_id,
                            session_id=session_id,
                            now=evaluation_now,
                        )
                    except Exception:
                        rule_reasons = [
                            "state_error: rate limit state unavailable, denying for safety"
                        ]
                        checked = ["rate_limit"]
                elif rule_type == "composite":
                    rule_reasons, checked = handler(
                        rule_for_eval,
                        request,
                        state=tracker,
                        agent_id=agent_id,
                        session_id=session_id,
                        now=evaluation_now,
                        all_rules_by_name=all_rules_by_name,
                        visited=set(),
                        max_cost_per_call_override=effective_max_cost_per_call,
                        daily_budget_override=effective_daily_budget,
                        rate_limit_per_minute_override=effective_rate_limit_per_minute,
                    )
                else:
                    rule_reasons, checked = handler(rule_for_eval, request)
            except Exception as error:
                rule_reasons = [f"internal_error: rule '{safe_rule_name}' raised {error}"]
                checked = [rule_type]
            if debug:
                debug_rule_results.append(
                    {
                        "rule": rule_type,
                        "passed": len(rule_reasons) == 0,
                        "duration_us": max(0, (time.perf_counter_ns() - rule_started_ns) // 1000),
                        "reason": rule_reasons[0] if rule_reasons else "",
                    }
                )

            reasons.extend(rule_reasons)
            rules_checked.extend(checked)
            if effective_fail_fast and rule_reasons:
                decision_reason = f"fail_fast:{safe_rule_name}"
                decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
                _attach_debug_trace(decision)
                _emit_event(
                    emitter=emitter,
                    request=request,
                    policy=policy,
                    agent_id=agent_id,
                    tracker=tracker,
                    session_id=session_id,
                    decision=decision,
                    started_ns=started_ns,
                    policy_version=policy_version,
                    decision_reason=decision_reason,
                    decision_context={"denied_by_rule": safe_rule_name, "rule_type": rule_type},
                )
                return decision

    for unknown_type, rule in unknown_explicit_rules:
        plugin_handler = plugins.get_handler(unknown_type) if plugins is not None else None
        if plugin_handler is None:
            rules_checked.append(f"unknown_rule_type:{unknown_type}")
            reasons.append(f"unknown_rule_type: '{unknown_type}' is not supported")
            continue
        rule_started_ns = time.perf_counter_ns() if debug else 0
        try:
            plugin_reasons, checked = plugin_handler.evaluate(
                rule,
                request,
                state=tracker,
                agent_id=agent_id,
                session_id=session_id,
            )
        except Exception as error:
            plugin_reasons = [f"internal_error: plugin '{unknown_type}' raised {error}"]
            checked = [unknown_type]
        reasons.extend(plugin_reasons)
        rules_checked.extend(checked)
        if effective_fail_fast and plugin_reasons:
            decision_reason = f"fail_fast:{unknown_type}"
            decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
            _attach_debug_trace(decision)
            _emit_event(
                emitter=emitter,
                request=request,
                policy=policy,
                agent_id=agent_id,
                tracker=tracker,
                session_id=session_id,
                decision=decision,
                started_ns=started_ns,
                policy_version=policy_version,
                decision_reason=decision_reason,
                decision_context={"denied_by_rule": unknown_type, "rule_type": "plugin"},
            )
            return decision
        if debug:
            debug_rule_results.append(
                {
                    "rule": unknown_type,
                    "passed": len(plugin_reasons) == 0,
                    "duration_us": max(0, (time.perf_counter_ns() - rule_started_ns) // 1000),
                    "reason": plugin_reasons[0] if plugin_reasons else "",
                }
            )

    for rule in legacy_unknown_name_rules:
        rule_name = rule.get("name")
        if isinstance(rule_name, str):
            rules_checked.append(f"unknown_rule:{rule_name}:skipped")

    safe_params = request.get("params") if isinstance(request.get("params"), dict) else {}
    normalized_tool, _invalid_tool_name = _normalize_tool_name(request.get("tool"))
    policy_budget_cfg = policy.get("budgets") if isinstance(policy, dict) and isinstance(policy.get("budgets"), dict) else None
    policy_tool_costs = policy.get("tool_costs") if isinstance(policy, dict) and isinstance(policy.get("tool_costs"), dict) else {}
    policy_loop_cfg = policy.get("loop_detection") if isinstance(policy, dict) and isinstance(policy.get("loop_detection"), dict) else None
    policy_model_routing_cfg = (
        policy.get("model_routing") if isinstance(policy, dict) and isinstance(policy.get("model_routing"), dict) else None
    )
    current_tool_cost = (
        float(policy_tool_costs.get(normalized_tool))
        if isinstance(policy_tool_costs.get(normalized_tool), int | float)
        else float(DEFAULT_TOOL_COSTS.get(normalized_tool, DEFAULT_TOOL_COSTS["default"]))
    )

    allowed = len(reasons) == 0
    if allowed and isinstance(policy_loop_cfg, dict) and bool(policy_loop_cfg.get("enabled", False)):
        rules_checked.append("loop_detection")
        try:
            loop_detector = _loop_detector_for_config(policy_loop_cfg)
            loop_result = loop_detector.check(
                normalized_tool,
                safe_params if isinstance(safe_params, dict) else {},
                cost_per_call=current_tool_cost,
            )
            action = loop_result.get("action")
            if action == "block":
                reasons.append(str(loop_result.get("message", "loop_detection: blocked")))
                allowed = False
                decision_reason = "loop_detection"
            elif action == "warn":
                reasons.append(f"warning: {loop_result.get('message', 'loop risk detected')}")
        except Exception:
            reasons.append("warning: loop detection unavailable")

    if allowed and isinstance(policy_budget_cfg, dict) and policy_budget_cfg:
        rules_checked.append("cost_budget")
        try:
            budget_status = _COST_TRACKER.check_budget(policy_budget_cfg)
            per_tool_status = budget_status.get("per_tool_status", {})
            if isinstance(per_tool_status, dict):
                status = per_tool_status.get(normalized_tool)
                if isinstance(status, dict) and bool(status.get("over", False)):
                    reasons.append(f"cost_budget: per-tool budget exceeded for {normalized_tool}")
                    allowed = False
                    decision_reason = "cost_budget"
            if allowed and bool(budget_status.get("over_budget", False)):
                on_hard = str(policy_budget_cfg.get("on_hard_limit", "block")).strip().lower()
                if on_hard == "block":
                    reasons.append("cost_budget: daily budget exceeded")
                    allowed = False
                    decision_reason = "cost_budget"
                else:
                    reasons.append("warning: daily budget exceeded")
            if allowed and bool(budget_status.get("soft_limit_reached", False)):
                on_soft = str(policy_budget_cfg.get("on_soft_limit", "notify")).strip().lower()
                percent = budget_status.get("daily_percent", 0)
                if on_soft == "block":
                    reasons.append("cost_budget: soft budget limit reached")
                    allowed = False
                    decision_reason = "cost_budget"
                elif on_soft == "downgrade_model":
                    if isinstance(policy_model_routing_cfg, dict) and bool(policy_model_routing_cfg.get("enabled", False)):
                        router = _router_for_config(policy_model_routing_cfg)
                        prompt_text = ""
                        if isinstance(safe_params, dict):
                            prompt_value = safe_params.get("prompt")
                            if isinstance(prompt_value, str):
                                prompt_text = prompt_value
                        route = router.route(prompt_text, tool_name=normalized_tool)
                        reasons.append(
                            f"warning: budget at {percent}%, suggested model fallback to {route['model']}"
                        )
                    else:
                        reasons.append(f"warning: budget at {percent}%")
                elif on_soft == "throttle":
                    reasons.append(f"warning: budget at {percent}%, throttling recommended")
                else:
                    reasons.append(f"warning: budget at {percent}%")

            per_task_budget = policy_budget_cfg.get("per_task")
            task_id = safe_params.get("_task_id") if isinstance(safe_params, dict) else None
            if allowed and isinstance(per_task_budget, int | float) and isinstance(task_id, str) and task_id:
                if _COST_TRACKER.get_task_cost(task_id) >= float(per_task_budget):
                    reasons.append(f"cost_budget: per-task budget exceeded for task '{task_id}'")
                    allowed = False
                    decision_reason = "cost_budget"
        except Exception:
            reasons.append("warning: cost budget evaluation unavailable")

    if allowed:
        cost = _coerce_cost(request.get("cost"))
        if cost is not None and cost > 0:
            try:
                if isinstance(effective_daily_budget_limit, int | float):
                    over_budget = tracker.check_budget_and_record(
                        agent_id=agent_id,
                        cost=cost,
                        daily_budget=float(effective_daily_budget_limit),
                        window_seconds=86400,
                        timestamp=evaluation_now,
                        session_id=session_id,
                    )
                    if over_budget:
                        reasons.append(f"budget_limit: agent '{agent_id}' daily budget exceeded")
                        allowed = False
                else:
                    tracker.record_spend(
                        agent_id,
                        cost,
                        timestamp=evaluation_now,
                        session_id=session_id,
                    )
            except Exception:
                reasons.append("state_error: rate limit state unavailable, denying for safety")
                allowed = False

    if registry is not None and hasattr(registry, "run_all"):
        try:
            evaluator_results = registry.run_all(request, safe_context)
        except Exception as error:  # noqa: BLE001
            evaluator_results = []
            reasons.append(f"warning: evaluator registry unavailable ({error})")
        for result in evaluator_results:
            action = getattr(result, "action", "allow")
            reason = str(getattr(result, "reason", ""))
            if action == "deny":
                allowed = False
                reasons.append(f"evaluator:{reason}")
                if effective_fail_fast:
                    decision_reason = "fail_fast:evaluator"
                    decision = Decision(allowed=False, reasons=reasons, rules_checked=rules_checked)
                    _attach_debug_trace(decision)
                    _emit_event(
                        emitter=emitter,
                        request=request,
                        policy=policy,
                        agent_id=agent_id,
                        tracker=tracker,
                        session_id=session_id,
                        decision=decision,
                        started_ns=started_ns,
                        policy_version=policy_version,
                        decision_reason=decision_reason,
                        decision_context={"denied_by_rule": "evaluator"},
                    )
                    return decision
            elif action == "warn":
                reasons.append(f"warning:evaluator:{reason}")

    decision = Decision(allowed=allowed, reasons=reasons, rules_checked=rules_checked)
    if decision.allowed:
        task_id = safe_params.get("_task_id") if isinstance(safe_params, dict) and isinstance(safe_params.get("_task_id"), str) else None
        model = safe_params.get("_model") if isinstance(safe_params, dict) and isinstance(safe_params.get("_model"), str) else None
        tokens_in = safe_params.get("_tokens_input") if isinstance(safe_params, dict) else 0
        tokens_out = safe_params.get("_tokens_output") if isinstance(safe_params, dict) else 0
        safe_tokens_in = int(tokens_in) if isinstance(tokens_in, int | float) else 0
        safe_tokens_out = int(tokens_out) if isinstance(tokens_out, int | float) else 0
        try:
            _COST_TRACKER.record_call(
                normalized_tool,
                task_id=task_id,
                model=model,
                tokens_input=safe_tokens_in,
                tokens_output=safe_tokens_out,
                cost_override=current_tool_cost if model is None else None,
            )
        except Exception:
            pass
    _attach_debug_trace(decision)
    _emit_event(
        emitter=emitter,
        request=request,
        policy=policy,
        agent_id=agent_id,
        tracker=tracker,
        session_id=session_id,
        decision=decision,
        started_ns=started_ns,
        policy_version=policy_version,
        decision_reason=decision_reason,
        decision_context=per_tool_rate_limit_meta,
    )
    return decision


def _emit_event(
    *,
    emitter: EventEmitter | None,
    request: dict[str, Any],
    policy: dict[str, Any] | None,
    agent_id: str,
    tracker: RateLimitTracker,
    session_id: str,
    decision: Decision,
    started_ns: int,
    policy_version: str | None,
    decision_reason: str | None = None,
    decision_context: dict[str, Any] | None = None,
) -> None:
    if emitter is None:
        return
    try:
        params = request.get("params")
        params_payload = params if isinstance(params, dict) else {}
        cost = _coerce_cost(request.get("cost"))
        safe_cost = cost if cost is not None else 0.0
        tool = request.get("tool") if isinstance(request.get("tool"), str) else "__unknown__"

        try:
            state_snapshot = {
                "agent_id": agent_id,
                "session_id": session_id,
                "window_seconds": 60,
                "tool_counts": {
                    tool: tracker.get_count(
                        tool,
                        window_seconds=60,
                        agent_id=agent_id,
                        session_id=session_id,
                    )
                },
            }
        except Exception:
            state_snapshot = {"error": "state_unavailable"}
        resolved_reason = decision_reason
        if resolved_reason is None and any(
            isinstance(reason, str) and reason.startswith("rate_limit_exceeded:")
            for reason in decision.reasons
        ):
            resolved_reason = "per_tool_rate_limit"
        if isinstance(resolved_reason, str) and resolved_reason:
            state_snapshot["decision_reason"] = resolved_reason
        if isinstance(decision_context, dict) and decision_context:
            state_snapshot["decision_context"] = dict(decision_context)
        context = request.get("context")
        credentials_injected: list[str] | None = None
        if isinstance(context, dict):
            trace_id = context.get("trace_id")
            parent_span_id = context.get("parent_span_id")
            if isinstance(trace_id, str) and trace_id:
                state_snapshot["trace_id"] = trace_id
            if isinstance(parent_span_id, str) and parent_span_id:
                state_snapshot["parent_span_id"] = parent_span_id
            raw_aliases = context.get("credentials_injected")
            if isinstance(raw_aliases, list):
                aliases = [item for item in raw_aliases if isinstance(item, str) and item.strip()]
                if aliases:
                    credentials_injected = aliases

        elapsed_us = max(0, (time.perf_counter_ns() - started_ns) // 1000)
        event = DecisionEvent(
            event_id=str(uuid.uuid4()),
            timestamp=decision.timestamp,
            agent_id=agent_id,
            tool=tool,
            params_hash=_stable_sha256(params_payload),
            cost=float(safe_cost),
            decision="ALLOW" if decision.allowed else "DENY",
            reasons=list(decision.reasons),
            rules_checked=list(decision.rules_checked),
            rules_triggered=_rules_triggered(decision.reasons),
            evaluation_order=list(RULE_EVALUATION_ORDER),
            evaluation_duration_us=int(elapsed_us),
            policy_version=policy_version or "",
            state_snapshot=state_snapshot,
            credentials_injected=credentials_injected,
        )
        emitter.emit(event)
    except Exception:
        pass


def _get_policy_plan(
    policy: dict[str, Any],
    rules: list[Any],
) -> dict[str, Any]:
    key = id(policy)
    cached = _POLICY_PLAN_CACHE.get(key)
    if cached is not None and cached[0] is policy:
        return cached[1]

    all_rules_by_name: dict[str, dict[str, Any]] = {}
    ordered: dict[str, list[dict[str, Any]]] = {
        rule_type: [] for rule_type in RULE_EVALUATION_ORDER
    }
    unknown_explicit_rules: list[tuple[str, dict[str, Any]]] = []
    legacy_unknown_name_rules: list[dict[str, Any]] = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        name = rule.get("name")
        if isinstance(name, str):
            all_rules_by_name[name] = rule

        rule_type, from_type_field = _resolve_rule_type(rule)
        if rule_type is None:
            continue
        if rule_type in KNOWN_RULE_TYPES:
            ordered[rule_type].append(rule)
        elif from_type_field:
            unknown_explicit_rules.append((rule_type, rule))
        else:
            legacy_unknown_name_rules.append(rule)

    plan = {
        "all_rules_by_name": all_rules_by_name,
        "ordered": ordered,
        "unknown_explicit_rules": unknown_explicit_rules,
        "legacy_unknown_name_rules": legacy_unknown_name_rules,
    }
    if len(_POLICY_PLAN_CACHE) >= 16:
        _POLICY_PLAN_CACHE.pop(next(iter(_POLICY_PLAN_CACHE)))
    _POLICY_PLAN_CACHE[key] = (policy, plan)
    return plan
