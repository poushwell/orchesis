from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.state import DEFAULT_SESSION_ID, RateLimitTracker


def test_session_isolation() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    request_s1 = {
        "tool": "read_file",
        "params": {"path": "/data/a.txt"},
        "context": {"agent": "agent_a", "session": "s1"},
    }
    request_s2 = {
        "tool": "read_file",
        "params": {"path": "/data/a.txt"},
        "context": {"agent": "agent_a", "session": "s2"},
    }
    assert evaluate(request_s1, policy, state=tracker).allowed is True
    assert evaluate(request_s1, policy, state=tracker).allowed is True
    assert evaluate(request_s1, policy, state=tracker).allowed is False
    assert evaluate(request_s2, policy, state=tracker).allowed is True


def test_default_session_backward_compatible() -> None:
    tracker = RateLimitTracker(persist_path=None)
    tracker.record("read_file")
    tracker.record("read_file", agent_id="__global__", session_id=DEFAULT_SESSION_ID)
    assert tracker.get_count("read_file", window_seconds=3600) == 2
    assert (
        tracker.get_count(
            "read_file", window_seconds=3600, agent_id="__global__", session_id=DEFAULT_SESSION_ID
        )
        == 2
    )


def test_budget_per_session() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "budget_limit", "daily_budget": 10.0}]}
    request_a = {"tool": "api_call", "cost": 6.0, "context": {"agent": "cursor", "session": "a"}}
    request_b = {"tool": "api_call", "cost": 6.0, "context": {"agent": "cursor", "session": "b"}}
    assert evaluate(request_a, policy, state=tracker).allowed is True
    assert evaluate(request_a, policy, state=tracker).allowed is False
    assert evaluate(request_b, policy, state=tracker).allowed is True


def test_session_in_request_context() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 1}]}
    req = {
        "tool": "read_file",
        "params": {"path": "/data/x.txt"},
        "context": {"session": "abc123"},
    }
    first = evaluate(req, policy, state=tracker)
    second = evaluate(req, policy, state=tracker)
    assert first.allowed is True
    assert second.allowed is False
