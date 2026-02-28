"""Rule evaluation engine."""

import posixpath
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from orchesis.models import Decision
from orchesis.state import GLOBAL_AGENT_ID, RateLimitTracker

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
    pattern = r"\b" + r"\s*".join(re.escape(ch) for ch in operation.upper()) + r"\b"
    return re.search(pattern, without_comments.upper()) is not None


def _is_unsafe_regex_pattern(pattern: str) -> bool:
    return re.search(r"\([^)]*[+*][^)]*\)[+*?]", pattern) is not None


def _apply_budget_limit(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    agent_id: str,
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
        spent = state.get_agent_budget_spent(agent_id, window_seconds=86400)
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
    dry_run: bool = False,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked = ["rate_limit"]
    max_per_minute = rule.get("max_requests_per_minute")
    if not isinstance(max_per_minute, int):
        return reasons, checked

    tool_name = request.get("tool")
    tool = tool_name if isinstance(tool_name, str) else "__unknown__"
    now = datetime.now(timezone.utc)
    if state.is_over_limit(tool, max_per_minute, 60, now=now, agent_id=agent_id):
        reasons.append(
            f"rate_limit: tool '{tool}' exceeded max_requests_per_minute {max_per_minute}"
        )
    if not dry_run:
        state.record(tool, now, agent_id=agent_id)
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
            if re.search(pattern, _sanitize_text(value)):
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
                ref_rule, request, state=state, agent_id=agent_id, dry_run=True
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


def evaluate(
    request: dict[str, Any],
    policy: dict[str, Any] | None,
    *,
    state: RateLimitTracker | None = None,
) -> Decision:
    """Evaluate request against policy rules."""
    reasons: list[str] = []
    rules_checked: list[str] = []
    tracker = state or RateLimitTracker(persist_path=None)

    if not policy:
        return Decision(allowed=True, reasons=reasons, rules_checked=rules_checked)

    rules = policy.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        return Decision(allowed=True, reasons=reasons, rules_checked=rules_checked)

    agent_id = _resolve_agent_id(request)

    all_rules_by_name: dict[str, dict[str, Any]] = {}
    ordered: dict[str, list[dict[str, Any]]] = {rule_type: [] for rule_type in RULE_EVALUATION_ORDER}
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

    for rule_type in RULE_EVALUATION_ORDER:
        for rule in ordered[rule_type]:
            rule_name = rule.get("name")
            safe_rule_name = rule_name if isinstance(rule_name, str) else rule_type
            try:
                if rule_type == "budget_limit":
                    try:
                        rule_reasons, checked = _apply_budget_limit(
                            rule, request, state=tracker, agent_id=agent_id
                        )
                    except Exception:
                        rule_reasons = [
                            "state_error: rate limit state unavailable, denying for safety"
                        ]
                        checked = ["budget_limit"]
                elif rule_type == "rate_limit":
                    try:
                        rule_reasons, checked = _apply_rate_limit(
                            rule, request, state=tracker, agent_id=agent_id
                        )
                    except Exception:
                        rule_reasons = [
                            "state_error: rate limit state unavailable, denying for safety"
                        ]
                        checked = ["rate_limit"]
                elif rule_type == "file_access":
                    rule_reasons, checked = _apply_file_access(rule, request)
                elif rule_type == "sql_restriction":
                    rule_reasons, checked = _apply_sql_restriction(rule, request)
                elif rule_type == "regex_match":
                    rule_reasons, checked = _apply_regex_match(rule, request)
                elif rule_type == "context_rules":
                    rule_reasons, checked = _apply_context_rules(rule, request)
                elif rule_type == "composite":
                    rule_reasons, checked = _apply_composite(
                        rule,
                        request,
                        state=tracker,
                        agent_id=agent_id,
                        all_rules_by_name=all_rules_by_name,
                        visited=set(),
                    )
                else:  # pragma: no cover
                    rule_reasons, checked = [], []
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
                tracker.record_spend(agent_id, cost)
            except Exception:
                reasons.append("state_error: rate limit state unavailable, denying for safety")
                allowed = False

    return Decision(allowed=allowed, reasons=reasons, rules_checked=rules_checked)
