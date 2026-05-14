from orchesis.engine import evaluate


def test_evaluate_allows_when_no_rules_are_violated() -> None:
    request = {"cost": 0.1, "params": {"path": "/tmp/file.txt", "query": "SELECT 1"}}
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 0.5},
            {"name": "file_access", "allowed_paths": ["/tmp"], "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
        ]
    }

    decision = evaluate(request, policy)

    assert decision.allowed is True
    assert decision.reasons == []
    assert decision.rules_checked == ["budget_limit", "file_access", "sql_restriction"]


def test_evaluate_denies_when_budget_limit_is_exceeded() -> None:
    request = {"cost": 0.6, "params": {}}
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 0.5}]}

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "budget_limit: cost 0.6 exceeds max_cost_per_call 0.5" in decision.reasons
    assert decision.rules_checked == ["budget_limit"]


def test_evaluate_denies_on_denied_file_prefix() -> None:
    request = {"params": {"path": "/etc/passwd"}}
    policy = {"rules": [{"name": "file_access", "denied_paths": ["/etc", "/root"]}]}

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "file_access: path '/etc/passwd' is denied by '/etc'" in decision.reasons


def test_evaluate_denies_when_allowed_paths_set_and_path_not_allowed() -> None:
    request = {"params": {"path": "/home/user/file.txt"}}
    policy = {"rules": [{"name": "file_access", "allowed_paths": ["/data", "/tmp"]}]}

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "file_access: path '/home/user/file.txt' is outside allowed_paths" in decision.reasons


def test_evaluate_denies_for_denied_sql_operation_case_insensitive() -> None:
    request = {"params": {"query": "drop table users"}}
    policy = {"rules": [{"name": "sql_restriction", "denied_operations": ["DROP", "DELETE"]}]}

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "sql_restriction: DROP is denied" in decision.reasons


def test_evaluate_checks_rate_limit_rule() -> None:
    request = {"cost": 0.1}
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100}]}

    decision = evaluate(request, policy)

    assert decision.allowed is True
    assert decision.reasons == []
    assert decision.rules_checked == ["rate_limit"]


def test_evaluate_skips_unknown_rule_without_blocking() -> None:
    request = {"cost": 0.1}
    policy = {"rules": [{"name": "custom_rule"}]}

    decision = evaluate(request, policy)

    assert decision.allowed is True
    assert decision.reasons == []
    assert decision.rules_checked == ["unknown_rule:custom_rule:skipped"]


def test_evaluate_fail_fast_denies_early() -> None:
    request = {"params": {"path": "/etc/passwd", "query": "DROP TABLE users"}}
    policy = {
        "rules": [
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
            {"name": "budget_limit", "max_cost_per_call": 0.01},
        ]
    }

    decision = evaluate(request, policy, fail_fast=True)

    assert decision.allowed is False
    assert "file_access" in decision.rules_checked
    assert "sql_restriction" not in decision.rules_checked


def test_evaluate_no_fail_fast_checks_all() -> None:
    request = {"params": {"path": "/etc/passwd", "query": "DROP TABLE users"}}
    policy = {
        "rules": [
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
            {"name": "budget_limit", "max_cost_per_call": 0.01},
        ]
    }

    decision = evaluate(request, policy, fail_fast=False)

    assert decision.allowed is False
    assert "file_access" in decision.rules_checked
    assert "sql_restriction" in decision.rules_checked
    assert "budget_limit" in decision.rules_checked


def test_evaluate_fail_fast_allow_continues() -> None:
    request = {"cost": 0.1, "params": {"path": "/etc/passwd", "query": "DROP TABLE users"}}
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 1.0},
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
        ]
    }

    decision = evaluate(request, policy, fail_fast=True)

    assert decision.allowed is False
    assert decision.rules_checked == ["budget_limit", "file_access"]


def test_evaluate_fail_fast_default_false() -> None:
    request = {"params": {"path": "/etc/passwd", "query": "DROP TABLE users"}}
    policy = {
        "rules": [
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
        ]
    }

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "file_access" in decision.rules_checked
    assert "sql_restriction" in decision.rules_checked


def test_evaluate_fail_fast_returns_denying_rule() -> None:
    request = {"params": {"path": "/etc/passwd"}}
    policy = {
        "rules": [
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "budget_limit", "max_cost_per_call": 0.01},
        ]
    }

    decision = evaluate(request, policy, fail_fast=True)

    assert decision.allowed is False
    assert decision.rules_checked[-1] == "file_access"
    assert any("file_access" in reason for reason in decision.reasons)
