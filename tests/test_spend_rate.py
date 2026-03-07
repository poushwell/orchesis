from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
import time

from orchesis.spend_rate import SpendRateDetector, SpendWindow


def _heartbeat_body(text: str = "Read HEARTBEAT.md and report HEARTBEAT_OK") -> dict:
    return {"messages": [{"role": "user", "content": text}]}


def test_basic_spend_tracking() -> None:
    detector = SpendRateDetector()
    detector.record_spend(0.5)
    stats = detector.stats
    assert stats["total_spend_tracked"] >= 0.5


def test_window_spend_limit_blocks() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=1.0)], pause_seconds=2)
    detector.record_spend(0.6)
    detector.record_spend(0.6)
    result = detector.check()
    assert result.allowed is False
    assert "window" in result.reason


def test_window_spend_under_limit_allows() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=5.0)])
    detector.record_spend(0.4)
    assert detector.check().allowed is True


def test_multiple_windows_checked() -> None:
    detector = SpendRateDetector(
        windows=[SpendWindow(window_seconds=30, max_spend=10.0), SpendWindow(window_seconds=300, max_spend=0.5)]
    )
    detector.record_spend(0.6)
    result = detector.check()
    assert result.allowed is False


def test_spike_detection() -> None:
    detector = SpendRateDetector(
        windows=[SpendWindow(window_seconds=10, max_spend=999.0), SpendWindow(window_seconds=120, max_spend=999.0)],
        spike_multiplier=2.0,
        pause_seconds=2,
    )
    for _ in range(4):
        detector.record_spend(0.01)
    detector.record_spend(0.8)
    result = detector.check()
    assert result.allowed is False
    assert result.reason in {"spike", "10s window", "120s window"}


def test_pause_duration_respected() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=0.1)], pause_seconds=1)
    detector.record_spend(0.2)
    blocked = detector.check()
    assert blocked.allowed is False
    still_blocked = detector.check()
    assert still_blocked.allowed is False


def test_pause_expires_allows() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=1, max_spend=0.1)], pause_seconds=1)
    detector.record_spend(0.2)
    assert detector.check().allowed is False
    time.sleep(1.05)
    assert detector.check().allowed is True


def test_heartbeat_detection_positive() -> None:
    detector = SpendRateDetector()
    assert detector.is_heartbeat_request(_heartbeat_body("HEARTBEAT check")) is True


def test_heartbeat_detection_positive_md() -> None:
    detector = SpendRateDetector()
    assert detector.is_heartbeat_request(_heartbeat_body("Read HEARTBEAT.md now")) is True


def test_heartbeat_detection_negative() -> None:
    detector = SpendRateDetector()
    assert detector.is_heartbeat_request({"messages": [{"role": "user", "content": "Tell me a joke"}]}) is False


def test_heartbeat_detection_system_event() -> None:
    detector = SpendRateDetector()
    body = {"messages": [{"role": "system", "content": "cron scheduler tick HEARTBEAT_OK"}]}
    assert detector.is_heartbeat_request(body) is True


def test_stats_tracking() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=0.1)], pause_seconds=1)
    detector.record_spend(0.2)
    detector.check()
    stats = detector.stats
    assert stats["pauses"] >= 1


def test_prevented_spend_accounting() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=0.1)], pause_seconds=1)
    detector.record_spend(1.0)
    detector.check()
    assert detector.stats["prevented_spend"] > 0


def test_concurrent_access() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=1000.0)])
    errors: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            for _ in range(50):
                detector.record_spend(0.01)
                _ = detector.check()
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(str(exc))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(8):
            pool.submit(worker)
    assert errors == []


def test_config_defaults() -> None:
    detector = SpendRateDetector()
    stats = detector.stats
    assert len(stats["windows"]) >= 2


def test_zero_spend_window() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=0.0)], pause_seconds=1)
    assert detector.check().allowed is True
    detector.record_spend(0.01)
    assert detector.check().allowed is False


def test_large_spike_multiplier() -> None:
    detector = SpendRateDetector(
        windows=[SpendWindow(window_seconds=60, max_spend=999.0)],
        spike_multiplier=1000.0,
    )
    detector.record_spend(0.5)
    assert detector.check().allowed is True


def test_heartbeat_cost_flagging() -> None:
    detector = SpendRateDetector(heartbeat_cost_threshold=0.1)
    assert detector.is_heartbeat_cost_high(_heartbeat_body(), 0.2) is True
    assert detector.is_heartbeat_cost_high(_heartbeat_body(), 0.01) is False


def test_empty_windows() -> None:
    detector = SpendRateDetector(windows=[])
    assert len(detector.stats["windows"]) >= 1


def test_record_and_check_interleaved() -> None:
    detector = SpendRateDetector(windows=[SpendWindow(window_seconds=60, max_spend=2.0)])
    detector.record_spend(0.2)
    assert detector.check().allowed is True
    detector.record_spend(0.3)
    assert detector.check().current_rate >= 0.0


def test_heartbeat_false_positive_schedule() -> None:
    """Normal 'schedule' message with multiple messages should not match."""
    detector = SpendRateDetector()
    body = {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Can you help me schedule a meeting with the team?"},
            {"role": "assistant", "content": "Sure, when would you like to meet?"},
            {"role": "user", "content": "Tomorrow at 3pm please"},
        ]
    }
    assert detector.is_heartbeat_request(body) is False
