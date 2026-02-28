"""Policy loading and validation."""

import re
from pathlib import Path
from typing import Any

import yaml


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
        raise ValueError("Policy top-level YAML object must be a mapping.")

    return loaded


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Validate policy structure and return errors."""
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
                errors.append(f"rules[{index}].deny_patterns must be a non-empty list for regex_match")
            elif isinstance(deny_patterns, list):
                for pattern in deny_patterns:
                    if not isinstance(pattern, str):
                        errors.append(f"rules[{index}] contains non-string regex pattern")
                        continue
                    if re.search(r"\([^)]*[+*][^)]*\)[+*?]", pattern):
                        errors.append(
                            f"rules[{index}] contains unsafe regex pattern: {pattern}"
                        )

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

    return errors
