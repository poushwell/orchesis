from __future__ import annotations

from orchesis import engine
from orchesis.engine import EvaluationGuarantees, RULE_EVALUATION_ORDER, evaluate
from orchesis.state import RateLimitTracker


def test_rule_evaluation_order_is_fixed() -> None:
    policy = {
        "rules": [
            {"name": "composite", "type": "composite", "operator": "AND", "conditions": []},
            {"name": "regex_match", "type": "regex_match", "field": "params.query", "deny_patterns": ["DROP"]},
            {"name": "file_access", "type": "file_access", "denied_paths": ["/etc"]},
            {"name": "budget_limit", "type": "budget_limit", "max_cost_per_call": 10.0},
            {"name": "sql_restriction", "type": "sql_restriction", "denied_operations": ["DROP"]},
            {"name": "context_rules", "type": "context_rules", "rules": [{"agent": "*", "max_cost_per_call": 100.0}]},
            {"name": "rate_limit", "type": "rate_limit", "max_requests_per_minute": 1000},
        ]
    }
    request = {
        "tool": "run_sql",
        "cost": 1.0,
        "params": {"query": "SELECT 1", "path": "/data/a.txt"},
        "context": {"agent": "cursor"},
    }
    decision = evaluate(request, policy, state=RateLimitTracker(persist_path=None))

    assert decision.rules_checked == [rule for rule in RULE_EVALUATION_ORDER if rule != "identity_check"]


def test_unknown_rule_type_causes_deny() -> None:
    policy = {"rules": [{"name": "x", "type": "magic_rule"}]}
    request = {"tool": "read_file", "params": {"path": "/data/a.txt"}}
    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert "unknown_rule_type: 'magic_rule' is not supported" in decision.reasons


def test_fail_closed_on_internal_error(monkeypatch) -> None:
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "_apply_file_access", _boom)
    policy = {"rules": [{"name": "file_access", "type": "file_access", "denied_paths": ["/etc"]}]}
    request = {"tool": "read_file", "params": {"path": "/data/a.txt"}}
    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert any("internal_error: rule 'file_access' raised boom" in reason for reason in decision.reasons)


def test_all_rules_evaluated_no_short_circuit() -> None:
    policy = {
        "rules": [
            {"name": "budget_limit", "type": "budget_limit", "max_cost_per_call": 0.1},
            {"name": "file_access", "type": "file_access", "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "type": "sql_restriction", "denied_operations": ["DROP"]},
        ]
    }
    request = {
        "tool": "run_sql",
        "cost": 1.0,
        "params": {"path": "/etc/passwd", "query": "DROP TABLE users"},
    }
    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert any("budget_limit" in reason for reason in decision.reasons)
    assert any("file_access" in reason for reason in decision.reasons)
    assert any("sql_restriction" in reason for reason in decision.reasons)


def test_evaluation_guarantees_class_exists() -> None:
    assert EvaluationGuarantees.DETERMINISTIC is True
    assert EvaluationGuarantees.SHORT_CIRCUIT is False
    assert EvaluationGuarantees.FAIL_CLOSED is True
    assert EvaluationGuarantees.UNKNOWN_FIELD_SAFE is True
    assert EvaluationGuarantees.THREAD_SAFE is True
    assert EvaluationGuarantees.EVALUATION_ORDER == RULE_EVALUATION_ORDER
