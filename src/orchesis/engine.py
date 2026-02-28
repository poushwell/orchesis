"""Rule evaluation engine."""

import posixpath
import re
import unicodedata
from urllib.parse import unquote
from datetime import datetime, timezone
from typing import Any

from orchesis.models import Decision
from orchesis.state import RateLimitTracker


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


def _get_path(request: dict[str, Any]) -> str | None:
    params = request.get("params")
    if not isinstance(params, dict):
        return None
    path = params.get("path")
    if not isinstance(path, str):
        return None
    return _normalize_path(path)


def _get_query_operation(request: dict[str, Any]) -> str | None:
    params = request.get("params")
    if not isinstance(params, dict):
        return None
    query = params.get("query")
    if not isinstance(query, str):
        return None
    normalized = _sanitize_text(query)
    without_comments = re.sub(r"/\*.*?\*/", " ", normalized, flags=re.DOTALL)
    parts = without_comments.strip().split()
    if not parts:
        return None
    return parts[0].upper()


def _query_contains_operation(query: str, operation: str) -> bool:
    normalized = _sanitize_text(query)
    without_comments = re.sub(r"/\*.*?\*/", " ", normalized, flags=re.DOTALL)
    pattern = r"\b" + r"\s*".join(re.escape(ch) for ch in operation.upper()) + r"\b"
    return re.search(pattern, without_comments.upper()) is not None


def _rule_kind(rule: dict[str, Any]) -> str | None:
    raw_type = rule.get("type")
    if isinstance(raw_type, str) and raw_type.strip():
        return raw_type.strip()
    name = rule.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _extract_field(request: dict[str, Any], field_path: str) -> Any:
    current: Any = request
    for segment in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _normalize_agent(context: dict[str, Any]) -> tuple[str | None, list[str]]:
    agent = context.get("agent")
    if not isinstance(agent, str):
        return None, []

    reasons: list[str] = []
    if "\x00" in agent:
        reasons.append("context_rules: agent contains null byte")
    cleaned = _sanitize_text(agent)
    if cleaned == "":
        reasons.append("context_rules: agent must be non-empty")
    if cleaned == "*":
        reasons.append("context_rules: literal '*' agent value is not allowed")
    return (cleaned if cleaned else None), reasons


def _is_unsafe_regex_pattern(pattern: str) -> bool:
    # Detect common catastrophic-backtracking shape like "(a+)+".
    return re.search(r"\([^)]*[+*][^)]*\)[+*?]", pattern) is not None


def _evaluate_named_rule(
    rule: dict[str, Any],
    request: dict[str, Any],
    *,
    state: RateLimitTracker,
    all_rules_by_name: dict[str, dict[str, Any]],
    dry_run: bool = False,
    visited_composites: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    checked: list[str] = []
    rule_kind = _rule_kind(rule)
    if rule_kind is None:
        return reasons, checked

    if rule_kind == "budget_limit":
        max_cost = rule.get("max_cost_per_call")
        cost = _coerce_cost(request.get("cost"))
        if isinstance(max_cost, int | float) and cost is not None:
            checked.append("budget_limit")
            if cost < 0:
                reasons.append("budget_limit: cost must be non-negative")
                return reasons, checked
            if cost > max_cost:
                reasons.append(
                    f"budget_limit: cost {cost} exceeds max_cost_per_call {max_cost}"
                )
        return reasons, checked

    if rule_kind == "file_access":
        path = _get_path(request)
        if path is None:
            return reasons, checked

        checked.append("file_access")
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

    if rule_kind == "sql_restriction":
        params = request.get("params")
        query = params.get("query") if isinstance(params, dict) else None
        if not isinstance(query, str):
            return reasons, checked
        checked.append("sql_restriction")
        denied_operations = rule.get("denied_operations")
        if isinstance(denied_operations, list):
            denied_upper = {op.upper() for op in denied_operations if isinstance(op, str)}
            for op in denied_upper:
                if _query_contains_operation(query, op):
                    reasons.append(f"sql_restriction: {op} is denied")
                    break
        return reasons, checked

    if rule_kind == "rate_limit":
        checked.append("rate_limit")
        max_per_minute = rule.get("max_requests_per_minute")
        if not isinstance(max_per_minute, int):
            return reasons, checked
        tool_name = request.get("tool")
        tool = tool_name if isinstance(tool_name, str) else "__unknown__"
        now = datetime.now(timezone.utc)
        over_limit = state.is_over_limit(tool, max_per_minute, 60, now=now)
        if not dry_run:
            state.record(tool, now)
        if over_limit:
            reasons.append(
                f"rate_limit: tool '{tool}' exceeded max_requests_per_minute {max_per_minute}"
            )
        return reasons, checked

    if rule_kind == "regex_match":
        checked.append("regex_match")
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
                    reasons.append(
                        f"regex_match: pattern '{pattern}' rejected as unsafe regex"
                    )
                    break
                if re.search(pattern, _sanitize_text(value)):
                    reasons.append(
                        f"regex_match: field '{field}' matched deny pattern '{pattern}'"
                    )
                    break
        return reasons, checked

    if rule_kind == "context_rules":
        checked.append("context_rules")
        context = request.get("context")
        if not isinstance(context, dict):
            return reasons, checked
        agent, agent_reasons = _normalize_agent(context)
        reasons.extend(agent_reasons)
        if agent is None:
            return reasons, checked

        entries = rule.get("rules")
        if not isinstance(entries, list):
            return reasons, checked
        exact_entries = [
            item
            for item in entries
            if isinstance(item, dict) and isinstance(item.get("agent"), str) and item["agent"] == agent
        ]
        selected = exact_entries
        if not selected:
            selected = [
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
                    continue
                if cost > max_cost:
                    reasons.append(
                        f"context_rules: agent '{agent}' cost {cost} exceeds max_cost_per_call {max_cost}"
                    )
        return reasons, checked

    if rule_kind == "composite":
        checked.append("composite")
        operator = rule.get("operator")
        conditions = rule.get("conditions")
        if not isinstance(operator, str) or not isinstance(conditions, list):
            return reasons, checked
        composite_name = rule.get("name") if isinstance(rule.get("name"), str) else "<unnamed>"
        seen = visited_composites or set()
        if composite_name in seen:
            reasons.append(f"composite: circular reference detected at '{composite_name}'")
            return reasons, checked
        next_seen = set(seen)
        next_seen.add(composite_name)

        condition_passes: list[bool] = []
        for condition in conditions:
            if not isinstance(condition, dict):
                condition_passes.append(False)
                continue
            ref_rule_name = condition.get("rule")
            if not isinstance(ref_rule_name, str):
                condition_passes.append(False)
                continue
            ref_rule = all_rules_by_name.get(ref_rule_name)
            if ref_rule is None:
                condition_passes.append(False)
                reasons.append(f"composite: referenced rule '{ref_rule_name}' is missing")
                continue
            ref_reasons, _ = _evaluate_named_rule(
                ref_rule,
                request,
                state=state,
                all_rules_by_name=all_rules_by_name,
                dry_run=True,
                visited_composites=next_seen,
            )
            condition_passes.append(len(ref_reasons) == 0)
            if ref_reasons:
                reasons.append(f"composite: condition '{ref_rule_name}' failed")

        op = operator.upper()
        if op == "AND":
            if not all(condition_passes):
                # reasons already added above
                pass
            else:
                reasons.clear()
        elif op == "OR":
            if any(condition_passes):
                reasons.clear()
            elif not reasons:
                reasons.append("composite: no OR condition passed")
        else:
            reasons.append(f"composite: unsupported operator '{operator}'")
        return reasons, checked

    rule_name = rule.get("name")
    if isinstance(rule_name, str):
        checked.append(f"unknown_rule:{rule_name}:skipped")
    return reasons, checked


def evaluate(
    request: dict[str, Any],
    policy: dict[str, Any],
    *,
    state: RateLimitTracker | None = None,
) -> Decision:
    """Evaluate request against policy rules."""
    reasons: list[str] = []
    rules_checked: list[str] = []
    tracker = state or RateLimitTracker(persist_path=None)

    rules = policy.get("rules")
    if not isinstance(rules, list):
        return Decision(allowed=True, reasons=reasons, rules_checked=rules_checked)

    all_rules_by_name: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, dict):
            name = rule.get("name")
            if isinstance(name, str):
                all_rules_by_name[name] = rule

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_reasons, checked = _evaluate_named_rule(
            rule,
            request,
            state=tracker,
            all_rules_by_name=all_rules_by_name,
            visited_composites=set(),
        )
        reasons.extend(rule_reasons)
        rules_checked.extend(checked)

    return Decision(allowed=len(reasons) == 0, reasons=reasons, rules_checked=rules_checked)
