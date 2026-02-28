from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from orchesis.contrib.ip_allowlist import IPAllowlistHandler
from orchesis.contrib.pii_detector import PIIDetectorHandler
from orchesis.contrib.time_window import TimeWindowHandler
from orchesis.engine import evaluate
from orchesis.plugins import PluginInfo, PluginRegistry, load_plugins_for_policy
from orchesis.state import RateLimitTracker
from orchesis.telemetry import InMemoryEmitter


@dataclass
class _SimpleHandler:
    reason: str = ""

    def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
        _ = (rule, request, kwargs)
        return ([self.reason] if self.reason else []), ["custom_rule"]


def test_register_plugin() -> None:
    registry = PluginRegistry()
    info = PluginInfo("test", "custom_rule", "1.0", "test plugin", _SimpleHandler())
    registry.register(info)
    assert registry.is_registered("custom_rule") is True


def test_cannot_override_builtin_type() -> None:
    registry = PluginRegistry()
    info = PluginInfo("bad", "file_access", "1.0", "bad", _SimpleHandler())
    try:
        registry.register(info)
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_plugin_evaluation() -> None:
    registry = PluginRegistry()
    registry.register(
        PluginInfo(
            "custom", "custom_rule", "1.0", "custom", _SimpleHandler("custom_rule: blocked")
        )
    )
    policy = {"rules": [{"name": "r1", "type": "custom_rule"}]}
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy, plugins=registry)
    assert decision.allowed is False
    assert "custom_rule: blocked" in decision.reasons


def test_plugin_fail_closed() -> None:
    class Broken:
        def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
            _ = (rule, request, kwargs)
            raise RuntimeError("boom")

    registry = PluginRegistry()
    registry.register(PluginInfo("broken", "broken_rule", "1.0", "broken", Broken()))
    policy = {"rules": [{"name": "x", "type": "broken_rule"}]}
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy, plugins=registry)
    assert decision.allowed is False
    assert any("internal_error" in reason for reason in decision.reasons)


def test_plugin_in_debug_trace() -> None:
    registry = PluginRegistry()
    registry.register(PluginInfo("custom", "custom_rule", "1.0", "custom", _SimpleHandler()))
    decision = evaluate(
        {"tool": "read_file", "params": {}, "cost": 0.0},
        {"rules": [{"name": "x", "type": "custom_rule"}]},
        plugins=registry,
        debug=True,
    )
    assert isinstance(decision.debug_trace, dict)
    assert any(item["rule"] == "custom_rule" for item in decision.debug_trace["rule_results"])


def test_plugin_in_telemetry() -> None:
    registry = PluginRegistry()
    registry.register(PluginInfo("custom", "custom_rule", "1.0", "custom", _SimpleHandler()))
    emitter = InMemoryEmitter()
    _ = evaluate(
        {"tool": "read_file", "params": {}, "cost": 0.0},
        {"rules": [{"name": "x", "type": "custom_rule"}]},
        plugins=registry,
        emitter=emitter,
        state=RateLimitTracker(persist_path=None),
    )
    event = emitter.get_events()[0]
    assert "custom_rule" in event.rules_checked


def test_unregister_plugin() -> None:
    registry = PluginRegistry()
    registry.register(PluginInfo("custom", "custom_rule", "1.0", "custom", _SimpleHandler()))
    registry.unregister("custom_rule")
    assert registry.is_registered("custom_rule") is False


def test_pii_detector_blocks_email() -> None:
    handler = PIIDetectorHandler()
    reasons, _ = handler.evaluate(
        {"type": "pii_detector"},
        {"params": {"query": "contact me at user@example.com"}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert any("email" in reason for reason in reasons)


def test_pii_detector_allows_clean() -> None:
    handler = PIIDetectorHandler()
    reasons, _ = handler.evaluate(
        {"type": "pii_detector"},
        {"params": {"query": "no sensitive content here"}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert reasons == []


def test_time_window_allows_in_hours() -> None:
    handler = TimeWindowHandler()
    handler._now = lambda tz: datetime(2026, 2, 28, 10, 0, tzinfo=timezone.utc)  # type: ignore[method-assign]
    reasons, _ = handler.evaluate(
        {
            "type": "time_window",
            "allowed_hours": {"start": "09:00", "end": "17:00", "timezone": "UTC"},
        },
        {"params": {}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert reasons == []


def test_time_window_blocks_outside() -> None:
    handler = TimeWindowHandler()
    handler._now = lambda tz: datetime(2026, 2, 28, 22, 0, tzinfo=timezone.utc)  # type: ignore[method-assign]
    reasons, _ = handler.evaluate(
        {
            "type": "time_window",
            "allowed_hours": {"start": "09:00", "end": "17:00", "timezone": "UTC"},
        },
        {"params": {}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert any("outside allowed window" in reason for reason in reasons)


def test_ip_allowlist_allows_valid() -> None:
    handler = IPAllowlistHandler()
    reasons, _ = handler.evaluate(
        {"type": "ip_allowlist", "allowed_ips": ["10.0.0.0/8"]},
        {"context": {"source_ip": "10.1.2.3"}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert reasons == []


def test_ip_allowlist_blocks_invalid() -> None:
    handler = IPAllowlistHandler()
    reasons, _ = handler.evaluate(
        {"type": "ip_allowlist", "allowed_ips": ["10.0.0.0/8"]},
        {"context": {"source_ip": "8.8.8.8"}},
        state=RateLimitTracker(persist_path=None),
        agent_id="a",
        session_id="s",
    )
    assert any("not in allowlist" in reason for reason in reasons)


def test_auto_discover_plugins_from_policy() -> None:
    policy = {"rules": [{"name": "x", "type": "pii_detector"}]}
    registry = load_plugins_for_policy(policy)
    assert registry.is_registered("pii_detector") is True


def test_multiple_plugins_evaluate_in_order() -> None:
    class First:
        def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
            _ = (rule, request, kwargs)
            return ["first: denied"], ["first"]

    class Second:
        def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
            _ = (rule, request, kwargs)
            return ["second: denied"], ["second"]

    registry = PluginRegistry()
    registry.register(PluginInfo("first", "first_rule", "1.0", "first", First()))
    registry.register(PluginInfo("second", "second_rule", "1.0", "second", Second()))
    policy = {
        "rules": [
            {"name": "a", "type": "first_rule"},
            {"name": "b", "type": "second_rule"},
        ]
    }
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy, plugins=registry)
    assert "first: denied" in decision.reasons
    assert "second: denied" in decision.reasons
    assert "first" in decision.rules_checked
    assert "second" in decision.rules_checked
