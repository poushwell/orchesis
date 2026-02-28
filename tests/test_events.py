from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.state import RateLimitTracker
from orchesis.telemetry import DecisionEvent, InMemoryEmitter


def _event(decision: str = "ALLOW") -> DecisionEvent:
    return DecisionEvent(
        event_id="evt-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="agent",
        tool="read_file",
        params_hash="hash",
        cost=0.1,
        decision=decision,
        reasons=[],
        rules_checked=[],
        rules_triggered=[],
        evaluation_order=[],
        evaluation_duration_us=10,
        policy_version="v1",
        state_snapshot={"tool_counts": {}},
    )


def test_event_bus_publish_to_subscribers() -> None:
    bus = EventBus()
    a = InMemoryEmitter()
    b = InMemoryEmitter()
    c = InMemoryEmitter()
    bus.subscribe(a)
    bus.subscribe(b)
    bus.subscribe(c)
    bus.publish(_event("ALLOW"))
    assert len(a.get_events()) == 1
    assert len(b.get_events()) == 1
    assert len(c.get_events()) == 1


def test_event_bus_with_filter() -> None:
    bus = EventBus()
    sink = InMemoryEmitter()
    bus.subscribe(sink, filter_fn=lambda event: event.decision == "DENY")
    bus.publish(_event("ALLOW"))
    bus.publish(_event("DENY"))
    assert len(sink.get_events()) == 1
    assert sink.get_events()[0].decision == "DENY"


def test_event_bus_subscriber_error_doesnt_crash() -> None:
    class BrokenEmitter:
        def emit(self, event: DecisionEvent) -> None:
            _ = event
            raise RuntimeError("boom")

    bus = EventBus()
    sink = InMemoryEmitter()
    bus.subscribe(BrokenEmitter())  # type: ignore[arg-type]
    bus.subscribe(sink)
    bus.publish(_event("ALLOW"))
    assert len(sink.get_events()) == 1


def test_event_bus_unsubscribe() -> None:
    bus = EventBus()
    sink = InMemoryEmitter()
    sub_id = bus.subscribe(sink)
    bus.publish(_event("ALLOW"))
    bus.unsubscribe(sub_id)
    bus.publish(_event("ALLOW"))
    assert len(sink.get_events()) == 1


def test_event_bus_is_emitter() -> None:
    bus = EventBus()
    sink = InMemoryEmitter()
    bus.subscribe(sink)
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/data/a.txt"}, "cost": 0.1},
        {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        emitter=bus,
        state=RateLimitTracker(persist_path=None),
    )
    assert decision.allowed is True
    assert len(sink.get_events()) == 1
