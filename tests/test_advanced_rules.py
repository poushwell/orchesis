from __future__ import annotations

from orchesis.engine import evaluate


def test_regex_match_blocks_drop_table_variations() -> None:
    policy = {
        "rules": [
            {
                "name": "sql_pattern",
                "type": "regex_match",
                "field": "params.query",
                "deny_patterns": [r"(?i)drop\s+table", r"(?i)truncate\s+"],
            }
        ]
    }
    request = {"tool": "run_sql", "params": {"query": "DrOp   TaBlE users"}}

    decision = evaluate(request, policy)
    assert decision.allowed is False
    assert any("regex_match" in reason for reason in decision.reasons)


def test_regex_match_allows_safe_queries() -> None:
    policy = {
        "rules": [
            {
                "name": "sql_pattern",
                "type": "regex_match",
                "field": "params.query",
                "deny_patterns": [r"(?i)drop\s+table", r"(?i)truncate\s+"],
            }
        ]
    }
    request = {"tool": "run_sql", "params": {"query": "SELECT * FROM users WHERE id = 1"}}

    decision = evaluate(request, policy)
    assert decision.allowed is True


def test_context_rules_blocks_untrusted_agent() -> None:
    policy = {
        "rules": [
            {
                "name": "agent_restrictions",
                "type": "context_rules",
                "rules": [
                    {
                        "agent": "untrusted_bot",
                        "denied_tools": ["delete_file", "run_sql", "write_file"],
                    },
                    {"agent": "*", "max_cost_per_call": 0.5},
                ],
            }
        ]
    }
    request = {
        "tool": "delete_file",
        "params": {"path": "/data/x"},
        "context": {"agent": "untrusted_bot"},
    }

    decision = evaluate(request, policy)
    assert decision.allowed is False
    assert any("context_rules" in reason for reason in decision.reasons)


def test_context_rules_applies_per_agent_cost_limit() -> None:
    policy = {
        "rules": [
            {
                "name": "agent_restrictions",
                "type": "context_rules",
                "rules": [
                    {"agent": "cursor", "max_cost_per_call": 1.0},
                    {"agent": "*", "max_cost_per_call": 0.5},
                ],
            }
        ]
    }
    request = {"tool": "api_call", "cost": 0.8, "context": {"agent": "cursor"}}

    decision = evaluate(request, policy)
    assert decision.allowed is True


def test_context_rules_wildcard_fallback() -> None:
    policy = {
        "rules": [
            {
                "name": "agent_restrictions",
                "type": "context_rules",
                "rules": [
                    {"agent": "cursor", "max_cost_per_call": 1.0},
                    {"agent": "*", "max_cost_per_call": 0.5},
                ],
            }
        ]
    }
    request = {"tool": "api_call", "cost": 0.8, "context": {"agent": "other_agent"}}

    decision = evaluate(request, policy)
    assert decision.allowed is False
    assert any("context_rules" in reason for reason in decision.reasons)


def test_composite_and_rule_requires_all_conditions() -> None:
    policy = {
        "rules": [
            {
                "name": "write_guard",
                "type": "composite",
                "operator": "AND",
                "conditions": [{"rule": "file_access"}, {"rule": "budget_limit"}],
            },
            {"name": "file_access", "allowed_paths": ["/data"], "denied_paths": ["/etc"]},
            {"name": "budget_limit", "max_cost_per_call": 0.5},
        ]
    }
    request = {"tool": "write_file", "params": {"path": "/data/out.txt"}, "cost": 0.4}

    decision = evaluate(request, policy)
    assert decision.allowed is True


def test_composite_with_one_failing_condition_denies() -> None:
    policy = {
        "rules": [
            {
                "name": "write_guard",
                "type": "composite",
                "operator": "AND",
                "conditions": [{"rule": "file_access"}, {"rule": "budget_limit"}],
            },
            {"name": "file_access", "allowed_paths": ["/data"], "denied_paths": ["/etc"]},
            {"name": "budget_limit", "max_cost_per_call": 0.5},
        ]
    }
    request = {"tool": "write_file", "params": {"path": "/data/out.txt"}, "cost": 0.9}

    decision = evaluate(request, policy)
    assert decision.allowed is False
    assert any("composite" in reason for reason in decision.reasons)
