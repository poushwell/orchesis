from __future__ import annotations

from datetime import datetime, timezone

from orchesis.engine import evaluate


def _policy() -> dict:
    return {
        "token_limits": {
            "max_tokens_per_call": 4000,
            "max_tokens_per_session": 50000,
            "max_tokens_per_day": 500000,
            "warn_at_percentage": 80,
        },
        "rules": [],
    }


def test_per_call_limit_allows_under() -> None:
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 1000, "agent": "tb_under"}}
    decision = evaluate(request, _policy(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert decision.allowed is True


def test_per_call_limit_denies_over() -> None:
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 5000, "agent": "tb_over"}}
    decision = evaluate(request, _policy(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert decision.allowed is False
    assert any("max per call" in reason for reason in decision.reasons)


def test_per_session_limit_allows_under() -> None:
    request = {
        "tool": "read_file",
        "params": {},
        "cost": 0.0,
        "context": {"estimated_tokens": 1000, "session_tokens_used": 1000, "agent": "tb_sess_ok"},
    }
    decision = evaluate(request, _policy(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert decision.allowed is True


def test_per_session_limit_denies_over() -> None:
    request = {
        "tool": "read_file",
        "params": {},
        "cost": 0.0,
        "context": {"estimated_tokens": 2000, "session_tokens_used": 49000, "agent": "tb_sess_denied"},
    }
    decision = evaluate(request, _policy(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert decision.allowed is False
    assert any("session token budget exhausted" in reason for reason in decision.reasons)


def test_per_day_limit_allows_under() -> None:
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 3000, "agent": "tb_day_ok"}}
    first = evaluate(request, _policy(), now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    second = evaluate(request, _policy(), now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert first.allowed is True
    assert second.allowed is True


def test_per_day_limit_denies_over() -> None:
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 4000, "agent": "tb_day_over"}}
    for _ in range(125):
        assert evaluate(request, _policy(), now=datetime(2026, 1, 3, tzinfo=timezone.utc)).allowed is True
    denied = evaluate(request, _policy(), now=datetime(2026, 1, 3, tzinfo=timezone.utc))
    assert denied.allowed is False


def test_daily_usage_accumulates() -> None:
    policy = _policy()
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 1000, "agent": "tb_acc"}}
    for _ in range(5):
        assert evaluate(request, policy, now=datetime(2026, 1, 4, tzinfo=timezone.utc)).allowed is True
    assert evaluate(request, policy, now=datetime(2026, 1, 4, tzinfo=timezone.utc)).allowed is True


def test_session_override_per_call() -> None:
    policy = {
        "token_limits": {"max_tokens_per_call": 4000},
        "session_policies": {"background": {"max_tokens_per_call": 1000}},
        "rules": [],
    }
    request = {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 1200, "agent": "tb_bg"}}
    decision = evaluate(request, policy, session_type="background", now=datetime(2026, 1, 5, tzinfo=timezone.utc))
    assert decision.allowed is False


def test_no_token_info_skips_check() -> None:
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0, "context": {"agent": "tb_skip"}}, _policy(), now=datetime(2026, 1, 6, tzinfo=timezone.utc))
    assert decision.allowed is True


def test_no_token_limits_allows_all() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {}, "cost": 0.0, "context": {"estimated_tokens": 999999, "agent": "tb_none"}},
        {"rules": []},
        now=datetime(2026, 1, 7, tzinfo=timezone.utc),
    )
    assert decision.allowed is True
