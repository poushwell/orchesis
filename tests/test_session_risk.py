from __future__ import annotations

import threading
import time

from orchesis.session_risk import RiskSignal, SessionRiskAccumulator


def _sig(
    category: str = "prompt_injection",
    *,
    confidence: float = 1.0,
    severity: str = "low",
    source: str = "threat_intel",
    description: str = "signal",
    timestamp: float = 0.0,
) -> RiskSignal:
    return RiskSignal(
        category=category,
        confidence=confidence,
        severity=severity,
        source=source,
        description=description,
        timestamp=timestamp,
    )


def test_empty_session_allows() -> None:
    acc = SessionRiskAccumulator()
    out = acc.evaluate("s1")
    assert out.action == "allow"
    assert out.composite_score == 0.0


def test_single_low_signal_allows() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig(severity="low", confidence=0.5))
    out = acc.evaluate("s1")
    assert out.action == "allow"
    assert out.composite_score < 30.0


def test_single_critical_signal_warns_or_blocks() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig(severity="critical", confidence=1.0))
    out = acc.evaluate("s1")
    assert out.action in {"warn", "block"}


def test_multiple_low_signals_same_category_accumulates() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig(category="prompt_injection", severity="low", confidence=1.0))
    acc.record_signal("s1", _sig(category="prompt_injection", severity="low", confidence=1.0))
    out = acc.evaluate("s1")
    assert out.composite_score >= 10.0


def test_multiple_signals_different_categories_diversity_bonus() -> None:
    acc = SessionRiskAccumulator(category_diversity_bonus=10.0)
    acc.record_signal("s1", _sig(category="prompt_injection", severity="low"))
    acc.record_signal("s1", _sig(category="data_exfiltration", severity="low"))
    out = acc.evaluate("s1")
    assert out.unique_categories == 2
    assert out.composite_score >= 20.0


def test_three_low_different_categories_crosses_warn() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig(category="prompt_injection", severity="low"))
    acc.record_signal("s1", _sig(category="data_exfiltration", severity="low"))
    acc.record_signal("s1", _sig(category="path_traversal", severity="low"))
    out = acc.evaluate("s1")
    assert out.action in {"warn", "block"}
    assert out.composite_score >= 30.0


def test_escalation_observe_to_warn() -> None:
    acc = SessionRiskAccumulator(warn_threshold=10.0, block_threshold=80.0)
    acc.record_signal("s1", _sig(category="a", severity="medium", confidence=1.0))
    out = acc.evaluate("s1")
    assert out.action == "warn"


def test_escalation_warn_to_block() -> None:
    acc = SessionRiskAccumulator(warn_threshold=20.0, block_threshold=40.0)
    acc.record_signal("s1", _sig(category="a", severity="high", confidence=1.0))
    acc.record_signal("s1", _sig(category="b", severity="high", confidence=1.0))
    out = acc.evaluate("s1")
    assert out.action == "block"


def test_escalation_does_not_downgrade_without_decay() -> None:
    acc = SessionRiskAccumulator(warn_threshold=20.0, block_threshold=40.0)
    acc.record_signal("s1", _sig(category="a", severity="high"))
    acc.record_signal("s1", _sig(category="b", severity="high"))
    first = acc.evaluate("s1")
    second = acc.evaluate("s1")
    assert first.action == "block"
    assert second.action == "block"


def test_old_signals_decay_reduces_score() -> None:
    now = time.monotonic()
    acc = SessionRiskAccumulator(decay_half_life_seconds=10.0)
    acc.record_signal("s1", _sig(category="a", severity="high", timestamp=now - 60.0))
    out = acc.evaluate("s1")
    assert out.composite_score < 5.0


def test_fresh_signals_full_weight() -> None:
    acc = SessionRiskAccumulator(decay_half_life_seconds=300.0)
    acc.record_signal("s1", _sig(category="a", severity="medium", confidence=1.0))
    out = acc.evaluate("s1")
    assert 10.0 <= out.composite_score <= 13.0


def test_half_life_halves_weight() -> None:
    now = time.monotonic()
    acc = SessionRiskAccumulator(decay_half_life_seconds=10.0)
    acc.record_signal("s1", _sig(category="a", severity="medium", confidence=1.0, timestamp=now - 10.0))
    out = acc.evaluate("s1")
    assert 5.0 <= out.composite_score <= 7.0


def test_session_ttl_cleanup() -> None:
    acc = SessionRiskAccumulator(session_ttl_seconds=60.0)
    acc.record_signal("s1", _sig(category="a"))
    with acc._lock:  # noqa: SLF001
        acc._sessions["s1"].last_updated = time.monotonic() - 1000.0  # noqa: SLF001
    _ = acc.evaluate("another-session")
    assert acc.get_session_state("s1") is None


def test_max_signals_per_session_bounded() -> None:
    acc = SessionRiskAccumulator(max_signals_per_session=10)
    for i in range(30):
        acc.record_signal("s1", _sig(category=f"c{i}", severity="low"))
    state = acc.get_session_state("s1")
    assert state is not None
    assert state["total_signals"] == 10


def test_reset_session() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig())
    assert acc.reset_session("s1") is True
    assert acc.get_session_state("s1") is None


def test_get_session_state() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig(category="x"))
    state = acc.get_session_state("s1")
    assert state is not None
    assert state["session_id"] == "s1"
    assert state["total_signals"] == 1


def test_concurrent_record_and_evaluate() -> None:
    acc = SessionRiskAccumulator()
    stop = False
    errors: list[Exception] = []

    def writer() -> None:
        nonlocal stop
        try:
            while not stop:
                acc.record_signal("s1", _sig(category="c", severity="low", confidence=0.7))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reader() -> None:
        nonlocal stop
        try:
            for _ in range(500):
                _ = acc.evaluate("s1")
            stop = True
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=writer)
    t2 = threading.Thread(target=reader)
    t1.start()
    t2.start()
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)
    assert not errors
    assert acc.stats["signals_recorded"] > 0


def test_disabled_always_allows() -> None:
    acc = SessionRiskAccumulator(enabled=False)
    acc.record_signal("s1", _sig(severity="critical"))
    out = acc.evaluate("s1")
    assert out.action == "allow"
    assert out.reason == "disabled"


def test_custom_thresholds() -> None:
    acc = SessionRiskAccumulator(warn_threshold=10.0, block_threshold=20.0)
    acc.record_signal("s1", _sig(category="a", severity="medium"))
    out = acc.evaluate("s1")
    assert out.action in {"warn", "block"}


def test_default_config() -> None:
    acc = SessionRiskAccumulator()
    stats = acc.stats
    assert stats["warn_threshold"] == 30.0
    assert stats["block_threshold"] == 60.0


def test_threat_intel_signals_feed_correctly() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal(
        "s1",
        _sig(
            category="prompt_injection",
            confidence=0.9,
            severity="high",
            source="threat_intel",
            description="threat match",
        ),
    )
    out = acc.evaluate("s1")
    assert out.total_signals == 1
    assert out.contributing_signals[0]["source"] == "threat_intel"


def test_composite_attack_scenario() -> None:
    acc = SessionRiskAccumulator()
    categories = ["prompt_injection", "data_exfiltration", "path_traversal", "tool_abuse", "resource_abuse"]
    for cat in categories:
        acc.record_signal("s1", _sig(category=cat, severity="low", confidence=1.0))
    out = acc.evaluate("s1")
    assert out.action == "block"
    assert out.composite_score >= 60.0


def test_benign_session_stays_low() -> None:
    acc = SessionRiskAccumulator()
    for _ in range(20):
        out = acc.evaluate("benign")
        assert out.composite_score < 30.0
    out = acc.evaluate("benign")
    assert out.action == "allow"


def test_mixed_benign_and_suspicious() -> None:
    acc = SessionRiskAccumulator()
    for _ in range(3):
        _ = acc.evaluate("s1")
    acc.record_signal("s1", _sig(category="prompt_injection", severity="low", confidence=0.9))
    acc.record_signal("s1", _sig(category="data_exfiltration", severity="low", confidence=0.9))
    out = acc.evaluate("s1")
    assert out.action in {"allow", "warn", "block"}
    assert out.composite_score > 0.0


def test_stats_tracking() -> None:
    acc = SessionRiskAccumulator()
    acc.record_signal("s1", _sig())
    _ = acc.evaluate("s1")
    stats = acc.stats
    assert stats["signals_recorded"] == 1
    assert stats["total_evaluations"] >= 1
    assert stats["sessions_tracked"] == 1


def test_stats_escalation_counts() -> None:
    acc = SessionRiskAccumulator(warn_threshold=10.0, block_threshold=30.0)
    acc.record_signal("s1", _sig(category="a", severity="medium", confidence=1.0))
    acc.record_signal("s1", _sig(category="b", severity="high", confidence=1.0))
    stats = acc.stats
    assert stats["escalations_warn"] >= 1
    assert stats["escalations_block"] >= 1
