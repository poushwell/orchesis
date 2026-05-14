from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.state import RateLimitTracker


def test_two_agents_independent_rate_limits() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100}]}

    request_a = {
        "tool": "read_file",
        "params": {"path": "/data/a.txt"},
        "context": {"agent": "agent_a"},
    }
    request_b = {
        "tool": "read_file",
        "params": {"path": "/data/b.txt"},
        "context": {"agent": "agent_b"},
    }

    last_a = None
    for _ in range(101):
        last_a = evaluate(request_a, policy, state=tracker)
    assert last_a is not None
    assert last_a.allowed is False
    assert any("rate_limit" in reason for reason in last_a.reasons)

    decision_b = evaluate(request_b, policy, state=tracker)
    assert decision_b.allowed is True


def test_agent_budget_tracked_independently() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 20.0, "daily_budget": 60.0}]}

    # Agent A already spent 50.0; this call should push over limit.
    tracker.record_spend("agent_a", cost=50.0)
    request_a = {"tool": "api_call", "cost": 15.0, "context": {"agent": "agent_a"}}
    request_b = {"tool": "api_call", "cost": 15.0, "context": {"agent": "agent_b"}}

    decision_a = evaluate(request_a, policy, state=tracker)
    decision_b = evaluate(request_b, policy, state=tracker)

    assert decision_a.allowed is False
    assert any("daily budget exceeded" in reason for reason in decision_a.reasons)
    assert decision_b.allowed is True
    assert any("daily budget exceeded" in reason for reason in decision_b.reasons) is False


def test_global_fallback_when_no_agent_id() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    request = {"tool": "read_file", "params": {"path": "/data/x.txt"}}

    first = evaluate(request, policy, state=tracker)
    second = evaluate(request, policy, state=tracker)
    third = evaluate(request, policy, state=tracker)

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False


def test_per_agent_budget_daily_limit() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "budget_limit", "daily_budget": 10.0}]}
    request = {"tool": "api_call", "cost": 3.0, "context": {"agent": "agent_daily"}}

    first = evaluate(request, policy, state=tracker)
    second = evaluate(request, policy, state=tracker)
    third = evaluate(request, policy, state=tracker)
    fourth = evaluate(request, policy, state=tracker)

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is True
    assert fourth.allowed is False
    assert any("daily budget exceeded" in reason for reason in fourth.reasons)
