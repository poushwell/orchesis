"""Rule evaluation engine."""

import hashlib
import json
import posixpath
import re
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

import yaml
from orchesis.models import Decision
from orchesis.state import GLOBAL_AGENT_ID, RateLimitTracker
from orchesis.telemetry import DecisionEvent, EventEmitter

RULE_EVALUATION_ORDER = [
    "budget_limit",
    "rate_limit",
    "file_access",
    "sql_restriction",
    "regex_match",
    "context_rules",
    "composite",
]

KNOWN_RULE_TYPES = set(RULE_EVALUATION_ORDER)


class EvaluationGuarantees:
    """Documents formal guarantees of the evaluation engine."""

    DETERMINISTIC = True
    SHORT_CIRCUIT = False
    FAIL_CLOSED = True
    UNKNOWN_FIELD_SAFE = True
    THREAD_SAFE = True
    EVALUATION_ORDER = RULE_EVALUATION_ORDER


def _stable_sha256(payload: Any) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _policy_version_hash(policy: dict[str, Any] | None) -> str:
    if policy is None:
        return hashlib.sha256(b"null").hexdigest()
    dumped = yaml.dump(policy, sort_keys=True)
    return _policy_version_hash_cached(dumped)


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


def _build_state_snapshot(state: RateLimitTracker, agent_id: str) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"agent_id": agent_id, "window_seconds": 60, "tool_counts": {}}
    for tool in state.get_tools():
        snapshot["tool_counts"][tool] = state.get_count(
            tool, window_seconds=60, agent_id=agent_id
        )
    return snapshot


def _sanitize_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value.replace("\x00", " ").strip())


def _normalize_path(path: str) -> str:
    decoded = unquote(path)
    cleaned = _sanitize_text(decoded).replace("\\", "/")
    cleaned = re.sub(r"/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    normalized = posixpath.normpath(cleaned)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


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
    return re.compile(pattern)


def _apply_budget_limit(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    agent_id: str,
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
            else state.get_agent_budget_spent(agent_id, window_seconds=86400)
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
    now: datetime,
    dry_run: bool = False,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["rate_limit"]
    max_per_minute = rule.get("max_requests_per_minute")
    if not isinstance(max_per_minute, int):
        return reasons, checked

    tool_name = request.get("tool")
    tool = tool_name if isinstance(tool_name, str) else "__unknown__"
    if dry_run:
        over_limit = state.is_over_limit(tool, max_per_minute, 60, now=now, agent_id=agent_id)
    else:
        over_limit = state.check_and_record(
            tool,
            max_requests=max_per_minute,
            window_seconds=60,
            timestamp=now,
            agent_id=agent_id,
        )
    if over_limit:
        reasons.append(f"rate_limit: tool '{tool}' exceeded max_requests_per_minute {max_per_minute}")
    return reasons, checked


def _apply_file_access(rule: dict[str, Any], request: dict[str, Any]) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["file_access"]
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


def _apply_sql_restriction(rule: dict[str, Any], request: dict[str, Any]) -> tuple[list[str], list[str]]:
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


def _apply_regex_match(rule: dict[str, Any], request: dict[str, Any]) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["regex_match"]
    field = rule.get("field")
    value = _extract_field(request, field) if isinstance(field, str) else None
    if not isinstance(value, str):
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


def _apply_context_rules(rule: dict[str, Any], request: dict[str, Any]) -> tuple[list[str], list[str]]:
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
            tool_name = request.get("tool")
            if isinstance(tool_name, str) and tool_name in denied_tools:
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
    now: datetime,
    all_rules_by_name: dict[str, dict[str, Any]],
    visited: set[str],
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
            ref_reasons, _ = _apply_budget_limit(ref_rule, request, state=state, agent_id=agent_id)
        elif ref_type == "rate_limit":
            ref_reasons, _ = _apply_rate_limit(
                ref_rule, request, state=state, agent_id=agent_id, now=now, dry_run=True
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
                now=now,
                all_rules_by_name=all_rules_by_name,
                visited=next_visited,
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


def evaluate(
    request: dict[str, Any],
    policy: dict[str, Any] | None,
    *,
    state: RateLimitTracker | None = None,
    emitter: EventEmitter | None = None,
    now: datetime | None = None,
) -> Decision:
    """Evaluate request against policy rules."""
    started_ns = time.perf_counter_ns()
    reasons: list[str] = []
    rules_checked: list[str] = []
    tracker = state or RateLimitTracker(persist_path=None)
    evaluation_now = now if now is not None else datetime.now(timezone.utc)
    agent_id = _resolve_agent_id(request)
    policy_version = _policy_version_hash(policy) if emitter is not None else None
    decision: Decision

    if not policy:
        decision = Decision(allowed=True, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
        )
        return decision

    rules = policy.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        decision = Decision(allowed=True, reasons=reasons, rules_checked=rules_checked)
        _emit_event(
            emitter=emitter,
            request=request,
            policy=policy,
            agent_id=agent_id,
            tracker=tracker,
            decision=decision,
            started_ns=started_ns,
            policy_version=policy_version,
        )
        return decision

    all_rules_by_name: dict[str, dict[str, Any]] = {}
    ordered: dict[str, list[dict[str, Any]]] = {rule_type: [] for rule_type in RULE_EVALUATION_ORDER}
    unknown_explicit_rules: list[tuple[str, dict[str, Any]]] = []
    legacy_unknown_name_rules: list[dict[str, Any]] = []
    cached_agent_spent: float | None = None

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

    for rule_type in RULE_EVALUATION_ORDER:
        handler_name = _RULE_HANDLERS.get(rule_type)
        handler = globals().get(handler_name) if isinstance(handler_name, str) else None
        if handler is None:
            continue
        for rule in ordered[rule_type]:
            rule_name = rule.get("name")
            safe_rule_name = rule_name if isinstance(rule_name, str) else rule_type
            try:
                if rule_type == "budget_limit":
                    try:
                        has_daily_budget = isinstance(rule.get("daily_budget"), int | float)
                        if has_daily_budget and cached_agent_spent is None:
                            cached_agent_spent = tracker.get_agent_budget_spent(
                                agent_id, window_seconds=86400, now=evaluation_now
                            )
                        rule_reasons, checked = handler(
                            rule,
                            request,
                            state=tracker,
                            agent_id=agent_id,
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
                            rule,
                            request,
                            state=tracker,
                            agent_id=agent_id,
                            now=evaluation_now,
                        )
                    except Exception:
                        rule_reasons = [
                            "state_error: rate limit state unavailable, denying for safety"
                        ]
                        checked = ["rate_limit"]
                elif rule_type == "composite":
                    rule_reasons, checked = handler(
                        rule,
                        request,
                        state=tracker,
                        agent_id=agent_id,
                        now=evaluation_now,
                        all_rules_by_name=all_rules_by_name,
                        visited=set(),
                    )
                else:
                    rule_reasons, checked = handler(rule, request)
            except Exception as error:
                rule_reasons = [f"internal_error: rule '{safe_rule_name}' raised {error}"]
                checked = [rule_type]

            reasons.extend(rule_reasons)
            rules_checked.extend(checked)

    for unknown_type, rule in unknown_explicit_rules:
        rules_checked.append(f"unknown_rule_type:{unknown_type}")
        reasons.append(f"unknown_rule_type: '{unknown_type}' is not supported")

    for rule in legacy_unknown_name_rules:
        rule_name = rule.get("name")
        if isinstance(rule_name, str):
            rules_checked.append(f"unknown_rule:{rule_name}:skipped")

    allowed = len(reasons) == 0
    if allowed:
        cost = _coerce_cost(request.get("cost"))
        if cost is not None and cost > 0:
            try:
                tracker.record_spend(agent_id, cost, timestamp=evaluation_now)
            except Exception:
                reasons.append("state_error: rate limit state unavailable, denying for safety")
                allowed = False

    decision = Decision(allowed=allowed, reasons=reasons, rules_checked=rules_checked)
    _emit_event(
        emitter=emitter,
        request=request,
        policy=policy,
        agent_id=agent_id,
        tracker=tracker,
        decision=decision,
        started_ns=started_ns,
        policy_version=policy_version,
    )
    return decision


def _emit_event(
    *,
    emitter: EventEmitter | None,
    request: dict[str, Any],
    policy: dict[str, Any] | None,
    agent_id: str,
    tracker: RateLimitTracker,
    decision: Decision,
    started_ns: int,
    policy_version: str | None,
) -> None:
    if emitter is None:
        return
    try:
        params = request.get("params")
        params_payload = params if isinstance(params, dict) else {}
        cost = _coerce_cost(request.get("cost"))
        safe_cost = cost if cost is not None else 0.0

        try:
            state_snapshot = _build_state_snapshot(tracker, agent_id)
        except Exception:
            state_snapshot = {"error": "state_unavailable"}

        elapsed_us = max(0, (time.perf_counter_ns() - started_ns) // 1000)
        tool = request.get("tool") if isinstance(request.get("tool"), str) else "__unknown__"
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
        )
        emitter.emit(event)
    except Exception:
        pass
