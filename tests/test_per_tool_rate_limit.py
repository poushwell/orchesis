from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from orchesis.config import PolicyError, load_agent_registry, load_policy
from orchesis.engine import evaluate
from orchesis.state import RateLimitTracker
from orchesis.telemetry import InMemoryEmitter


def _write_policy(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(content.strip(), encoding="utf-8")
    return path


def _request(tool: str = "shell_execute", agent: str = "agent_a") -> dict[str, object]:
    return {"tool": tool, "params": {"command": "echo ok"}, "context": {"agent": agent}, "cost": 0.0}


def test_load_policy_parses_tool_rate_limits_minute(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  mode: allowlist
  allowed: ["shell_execute"]
  rate_limits:
    shell_execute: 2/minute
""",
    )
    policy = load_policy(path)
    parsed = policy["tool_access"]["_parsed_rate_limits"]["shell_execute"]
    assert parsed["max_requests"] == 2
    assert parsed["window_seconds"] == 60
    assert parsed["unit"] == "minute"


def test_load_policy_parses_tool_rate_limits_hour_and_second(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  mode: allowlist
  allowed: ["web_search", "send_email"]
  rate_limits:
    web_search: 10/second
    send_email: 5/hour
""",
    )
    policy = load_policy(path)
    parsed = policy["tool_access"]["_parsed_rate_limits"]
    assert parsed["web_search"]["window_seconds"] == 1
    assert parsed["send_email"]["window_seconds"] == 3600


def test_load_policy_rejects_invalid_rate_limit_format(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  rate_limits:
    shell_execute: abc/minute
""",
    )
    with pytest.raises(PolicyError, match="Invalid tool rate limit format"):
        load_policy(path)


def test_load_policy_rejects_invalid_rate_limit_unit(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  rate_limits:
    shell_execute: 10/year
""",
    )
    with pytest.raises(PolicyError, match="Invalid tool rate limit format"):
        load_policy(path)


def test_load_policy_rejects_non_positive_rate_limit(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  rate_limits:
    shell_execute: 0/minute
""",
    )
    with pytest.raises(PolicyError, match="must be positive"):
        load_policy(path)


def test_load_policy_rejects_negative_rate_limit(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  rate_limits:
    shell_execute: -1/minute
""",
    )
    with pytest.raises(PolicyError, match="Invalid tool rate limit format"):
        load_policy(path)


def test_load_policy_rejects_non_mapping_rate_limits(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
rules: []
tool_access:
  rate_limits: 123
""",
    )
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_policy(path)


def test_per_tool_limit_enforcement_two_pass_third_denied() -> None:
    policy = {"rules": [], "tool_access": {"rate_limits": {"shell_execute": "2/minute"}}}
    tracker = RateLimitTracker(persist_path=None)
    now = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    first = evaluate(_request(), policy, state=tracker, now=now)
    second = evaluate(_request(), policy, state=tracker, now=now + timedelta(seconds=1))
    third = evaluate(_request(), policy, state=tracker, now=now + timedelta(seconds=2))
    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert any("rate_limit_exceeded: shell_execute limited to 2/minute" in reason for reason in third.reasons)


def test_per_tool_sliding_window_allows_after_expiration() -> None:
    policy = {"rules": [], "tool_access": {"rate_limits": {"shell_execute": "2/second"}}}
    tracker = RateLimitTracker(persist_path=None)
    base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    _ = evaluate(_request(), policy, state=tracker, now=base)
    _ = evaluate(_request(), policy, state=tracker, now=base + timedelta(milliseconds=100))
    denied = evaluate(_request(), policy, state=tracker, now=base + timedelta(milliseconds=200))
    allowed_again = evaluate(_request(), policy, state=tracker, now=base + timedelta(seconds=2))
    assert denied.allowed is False
    assert allowed_again.allowed is True


def test_fallback_to_agent_level_limit_when_tool_has_no_specific_limit() -> None:
    policy = {
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 100}],
        "agents": [{"id": "agent_a", "name": "A", "trust_tier": "operator", "rate_limit_per_minute": 2}],
        "tool_access": {"rate_limits": {"shell_execute": "10/minute"}},
    }
    registry = load_agent_registry(policy)
    tracker = RateLimitTracker(persist_path=None)
    request = _request(tool="read_file")
    a = evaluate(request, policy, state=tracker, registry=registry)
    b = evaluate(request, policy, state=tracker, registry=registry)
    c = evaluate(request, policy, state=tracker, registry=registry)
    assert a.allowed is True
    assert b.allowed is True
    assert c.allowed is False
    assert any("rate_limit: tool 'read_file' exceeded max_requests_per_minute 2" in reason for reason in c.reasons)


def test_without_rate_limits_section_is_backward_compatible() -> None:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    tracker = RateLimitTracker(persist_path=None)
    request = _request(tool="read_file")
    _ = evaluate(request, policy, state=tracker)
    _ = evaluate(request, policy, state=tracker)
    denied = evaluate(request, policy, state=tracker)
    assert denied.allowed is False
    assert any("rate_limit" in reason for reason in denied.reasons)


def test_multiple_tools_with_different_limits() -> None:
    policy = {
        "rules": [],
        "tool_access": {"rate_limits": {"shell_execute": "2/minute", "web_search": "3/minute"}},
    }
    tracker = RateLimitTracker(persist_path=None)
    base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(2):
        assert evaluate(_request("shell_execute"), policy, state=tracker, now=base + timedelta(seconds=i)).allowed
    assert evaluate(_request("shell_execute"), policy, state=tracker, now=base + timedelta(seconds=3)).allowed is False
    for i in range(3):
        assert evaluate(_request("web_search"), policy, state=tracker, now=base + timedelta(seconds=10 + i)).allowed
    assert evaluate(_request("web_search"), policy, state=tracker, now=base + timedelta(seconds=20)).allowed is False


def test_hour_based_per_tool_limit() -> None:
    policy = {"rules": [], "tool_access": {"rate_limits": {"send_email": "2/hour"}}}
    tracker = RateLimitTracker(persist_path=None)
    base = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert evaluate(_request("send_email"), policy, state=tracker, now=base).allowed
    assert evaluate(_request("send_email"), policy, state=tracker, now=base + timedelta(minutes=10)).allowed
    denied = evaluate(_request("send_email"), policy, state=tracker, now=base + timedelta(minutes=20))
    assert denied.allowed is False
    assert any("2/hour" in reason for reason in denied.reasons)


def test_per_tool_limit_takes_priority_over_agent_rate_limit() -> None:
    policy = {
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 999}],
        "agents": [{"id": "agent_a", "name": "A", "trust_tier": "operator", "rate_limit_per_minute": 1}],
        "tool_access": {"rate_limits": {"shell_execute": "2/minute"}},
    }
    registry = load_agent_registry(policy)
    tracker = RateLimitTracker(persist_path=None)
    first = evaluate(_request("shell_execute"), policy, state=tracker, registry=registry)
    second = evaluate(_request("shell_execute"), policy, state=tracker, registry=registry)
    third = evaluate(_request("shell_execute"), policy, state=tracker, registry=registry)
    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert any("rate_limit_exceeded:" in reason for reason in third.reasons)


def test_rate_limit_denial_sets_decision_reason_in_audit_event() -> None:
    policy = {"rules": [], "tool_access": {"rate_limits": {"shell_execute": "1/minute"}}}
    tracker = RateLimitTracker(persist_path=None)
    emitter = InMemoryEmitter()
    _ = evaluate(_request(), policy, state=tracker, emitter=emitter)
    _ = evaluate(_request(), policy, state=tracker, emitter=emitter)
    event = emitter.get_events()[-1]
    assert event.decision == "DENY"
    assert event.state_snapshot.get("decision_reason") == "per_tool_rate_limit"
    context = event.state_snapshot.get("decision_context")
    assert isinstance(context, dict)
    assert context.get("tool") == "shell_execute"


def test_per_tool_rate_limit_parses_without_load_policy() -> None:
    policy = {"rules": [], "tool_access": {"rate_limits": {"shell_execute": "2/minute"}}}
    tracker = RateLimitTracker(persist_path=None)
    _ = evaluate(_request(), policy, state=tracker)
    _ = evaluate(_request(), policy, state=tracker)
    denied = evaluate(_request(), policy, state=tracker)
    assert denied.allowed is False

