from __future__ import annotations

import threading
import pytest

from orchesis.cost_velocity import CostVelocity


def test_record_and_rate() -> None:
    cv = CostVelocity()
    cv.record(1.5)
    assert cv.current_rate_per_hour() == 6.0


def test_projection_24h() -> None:
    cv = CostVelocity()
    cv.record(2.0)
    assert cv.projection_24h() == 192.0


def test_anomalous_spike() -> None:
    cv = CostVelocity()
    now = 10_000_000.0
    cv._now = lambda: now  # noqa: SLF001
    for day in range(1, 8):
        now -= 24 * 3600
        cv.record(1.0)
    now = 10_000_000.0
    cv.record(5.0)
    assert cv.is_anomalous()


def test_empty_no_data() -> None:
    cv = CostVelocity()
    assert cv.current_rate_per_hour() == 0.0
    assert cv.projection_24h() == 0.0
    assert cv.is_anomalous() is False


def test_thread_safety() -> None:
    cv = CostVelocity()

    def worker() -> None:
        for _ in range(100):
            cv.record(0.01)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    stats = cv.get_stats()
    assert stats["current_rate_per_hour"] > 0.0
    assert stats["projection_24h"] > 0.0


def test_record_ignores_non_positive() -> None:
    cv = CostVelocity()
    cv.record(0.0)
    cv.record(-5.0)
    assert cv.get_stats()["current_rate_per_hour"] == 0.0


def test_prunes_old_data() -> None:
    cv = CostVelocity()
    now = 2_000_000.0
    cv._now = lambda: now  # noqa: SLF001
    cv.record(1.0)
    now += 8 * 24 * 3600
    cv.record(1.0)
    assert cv.get_stats()["avg_7d_rate"] < 0.02


def test_anomalous_false_with_no_baseline() -> None:
    cv = CostVelocity()
    cv.record(1.0)
    assert cv.is_anomalous() is False


def test_get_stats_keys() -> None:
    cv = CostVelocity()
    keys = set(cv.get_stats().keys())
    assert keys == {"current_rate_per_hour", "projection_24h", "avg_7d_rate", "is_anomalous"}


def test_rate_window_15_minutes_only() -> None:
    cv = CostVelocity()
    now = 3_000_000.0
    cv._now = lambda: now  # noqa: SLF001
    cv.record(1.0)
    now += (16 * 60)
    cv.record(1.0)
    assert cv.current_rate_per_hour() == 4.0


def test_projection_uses_current_rate() -> None:
    cv = CostVelocity()
    cv.record(0.25)
    assert cv.projection_24h() == cv.current_rate_per_hour() * 24.0


def test_is_anomalous_respects_threshold_multiplier() -> None:
    cv = CostVelocity()
    now = 4_000_000.0
    cv._now = lambda: now  # noqa: SLF001
    for _ in range(20):
        now -= 6 * 3600
        cv.record(0.5)
    now = 4_000_000.0
    cv.record(1.0)
    assert cv.is_anomalous(threshold_multiplier=100.0) is False


def test_get_stats_rounding() -> None:
    cv = CostVelocity()
    cv.record(0.123456789)
    stats = cv.get_stats()
    assert isinstance(stats["current_rate_per_hour"], float)
    assert isinstance(stats["projection_24h"], float)
    assert isinstance(stats["avg_7d_rate"], float)


def test_avg_7d_rate_positive_after_records() -> None:
    cv = CostVelocity()
    cv.record(2.0)
    assert cv.get_stats()["avg_7d_rate"] > 0.0


def test_multiple_records_accumulate_rate() -> None:
    cv = CostVelocity()
    cv.record(0.1)
    cv.record(0.2)
    assert cv.current_rate_per_hour() == pytest.approx(1.2, abs=1e-9)

