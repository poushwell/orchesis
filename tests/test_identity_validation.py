from __future__ import annotations

from orchesis.config import validate_policy


def test_valid_agents_section_passes() -> None:
    policy = {
        "version": "0.3.0",
        "agents": [
            {
                "id": "cursor",
                "name": "Cursor IDE Agent",
                "trust_tier": "operator",
                "allowed_tools": ["read_file", "write_file"],
                "max_cost_per_call": 2.0,
                "daily_budget": 50.0,
                "rate_limit_per_minute": 10,
            }
        ],
        "default_trust_tier": "intern",
        "rules": [],
    }
    assert validate_policy(policy) == []


def test_missing_agent_id_fails() -> None:
    policy = {"agents": [{"name": "A", "trust_tier": "intern"}], "rules": []}
    errors = validate_policy(policy)
    assert "agents[0].id must be a non-empty string" in errors


def test_invalid_trust_tier_fails() -> None:
    policy = {"agents": [{"id": "a", "name": "A", "trust_tier": "superuser"}], "rules": []}
    errors = validate_policy(policy)
    assert any("agents[0].trust_tier must be one of" in error for error in errors)


def test_duplicate_agent_ids_fails() -> None:
    policy = {
        "agents": [
            {"id": "dup", "name": "A", "trust_tier": "intern"},
            {"id": "dup", "name": "B", "trust_tier": "operator"},
        ],
        "rules": [],
    }
    errors = validate_policy(policy)
    assert "agents[1].id 'dup' is duplicated" in errors


def test_non_numeric_cost_override_fails() -> None:
    policy = {
        "agents": [{"id": "a", "name": "A", "trust_tier": "intern", "max_cost_per_call": "oops"}],
        "rules": [],
    }
    errors = validate_policy(policy)
    assert "agents[0].max_cost_per_call must be numeric if provided" in errors


def test_valid_policy_without_agents_passes() -> None:
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 0.5}]}
    assert validate_policy(policy) == []
