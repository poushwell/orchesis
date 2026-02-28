"""Policy loading and validation."""

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
    except yaml.YAMLError as error:
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

    return errors
