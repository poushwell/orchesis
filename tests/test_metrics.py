from __future__ import annotations

from orchesis.metrics import MetricsCollector
from orchesis.telemetry import DecisionEvent


def _event(
    *, agent: str, tool: str, decision: str, duration: int = 10, reasons: list[str] | None = None
):
    return DecisionEvent(
        event_id=f"{agent}-{tool}-{decision}-{duration}",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id=agent,
        tool=tool,
        params_hash="hash",
        cost=0.1,
        decision=decision,
        reasons=reasons or [],
        rules_checked=[],
        rules_triggered=[],
        evaluation_order=[],
        evaluation_duration_us=duration,
        policy_version="v1",
        state_snapshot={"tool_counts": {}},
    )


def test_metrics_count_decisions() -> None:
    metrics = MetricsCollector()
    for _ in range(5):
        metrics.emit(_event(agent="a", tool="read_file", decision="ALLOW"))
    for _ in range(3):
        metrics.emit(_event(agent="a", tool="write_file", decision="DENY"))
    snapshot = metrics.snapshot()
    counters = snapshot["counters"]
    assert counters["orchesis_decisions_total|decision=ALLOW"] == 5
    assert counters["orchesis_decisions_total|decision=DENY"] == 3


def test_metrics_by_agent() -> None:
    metrics = MetricsCollector()
    metrics.emit(_event(agent="agent_a", tool="read_file", decision="ALLOW"))
    metrics.emit(_event(agent="agent_b", tool="read_file", decision="DENY"))
    counters = metrics.snapshot()["counters"]
    assert counters["orchesis_decisions_by_agent|agent=agent_a|decision=ALLOW"] == 1
    assert counters["orchesis_decisions_by_agent|agent=agent_b|decision=DENY"] == 1


def test_metrics_prometheus_format() -> None:
    metrics = MetricsCollector()
    metrics.emit(_event(agent="a", tool="read_file", decision="ALLOW"))
    text = metrics.prometheus_text()
    assert "# HELP orchesis_decisions_total" in text
    assert 'orchesis_decisions_total{decision="ALLOW"}' in text
    assert "# TYPE orchesis_evaluation_duration_us histogram" in text


def test_metrics_evaluation_duration() -> None:
    metrics = MetricsCollector()
    metrics.emit(_event(agent="a", tool="read_file", decision="ALLOW", duration=50))
    metrics.emit(_event(agent="a", tool="read_file", decision="ALLOW", duration=150))
    hist = metrics.snapshot()["histograms"]["orchesis_evaluation_duration_us"]
    assert hist == [50.0, 150.0]


def test_metrics_reset() -> None:
    metrics = MetricsCollector()
    metrics.emit(_event(agent="a", tool="read_file", decision="ALLOW"))
    metrics.reset()
    snapshot = metrics.snapshot()
    assert snapshot["counters"] == {}
    assert snapshot["histograms"] == {}
