from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orchesis.engine import evaluate
from orchesis.state import RateLimitTracker


def test_rate_limit_allows_under_threshold() -> None:
    tracker = RateLimitTracker(persist_path=None)
    now = datetime.now(timezone.utc)
    tracker.record("read_file", now - timedelta(seconds=10))
    tracker.record("read_file", now - timedelta(seconds=5))

    assert tracker.is_over_limit("read_file", max_requests=3, window_seconds=60, now=now) is False


def test_rate_limit_denies_over_threshold() -> None:
    tracker = RateLimitTracker(persist_path=None)
    now = datetime.now(timezone.utc)
    for _ in range(3):
        tracker.record("read_file", now - timedelta(seconds=5))

    assert tracker.is_over_limit("read_file", max_requests=3, window_seconds=60, now=now) is True


def test_sliding_window_expires_old_entries() -> None:
    tracker = RateLimitTracker(persist_path=None)
    now = datetime.now(timezone.utc)
    tracker.record("read_file", now - timedelta(seconds=120))
    tracker.record("read_file", now - timedelta(seconds=10))

    assert tracker.get_count("read_file", window_seconds=60, now=now) == 1


def test_thread_safety_with_concurrent_record_calls() -> None:
    tracker = RateLimitTracker(persist_path=None)

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(lambda _: tracker.record("read_file"), range(1000)))

    assert tracker.get_count("read_file", window_seconds=3600) == 1000


def test_persistence_write_reload_counts_preserved(tmp_path: Path) -> None:
    state_path = tmp_path / ".orchesis" / "state.jsonl"
    tracker = RateLimitTracker(persist_path=state_path)
    tracker.record("read_file")
    tracker.record("read_file")
    tracker.record("run_sql")

    reloaded = RateLimitTracker(persist_path=state_path)
    assert reloaded.get_count("read_file", window_seconds=3600) == 2
    assert reloaded.get_count("run_sql", window_seconds=3600) == 1


def test_rate_limit_integration_with_evaluate() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    request = {"tool": "read_file", "params": {"path": "/data/a.txt"}, "cost": 0.0}

    first = evaluate(request, policy, state=tracker)
    second = evaluate(request, policy, state=tracker)
    third = evaluate(request, policy, state=tracker)

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert any("rate_limit" in reason for reason in third.reasons)


def test_per_agent_state_isolation() -> None:
    tracker = RateLimitTracker(persist_path=None)
    now = datetime.now(timezone.utc)
    for _ in range(3):
        tracker.record("read_file", now - timedelta(seconds=5), agent_id="agent_a")

    assert (
        tracker.is_over_limit(
            "read_file", max_requests=3, window_seconds=60, now=now, agent_id="agent_a"
        )
        is True
    )
    assert (
        tracker.is_over_limit(
            "read_file", max_requests=3, window_seconds=60, now=now, agent_id="agent_b"
        )
        is False
    )


def test_backward_compatible_global_default() -> None:
    tracker = RateLimitTracker(persist_path=None)
    tracker.record("read_file")
    tracker.record("read_file")

    assert tracker.get_count("read_file", window_seconds=3600) == 2
    assert tracker.get_count("read_file", window_seconds=3600, agent_id="__global__") == 2
