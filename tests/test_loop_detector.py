from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from orchesis.loop_detector import LoopDetector


def test_single_call_no_loop() -> None:
    detector = LoopDetector()
    result = detector.check("web_search", {"q": "a"})
    assert result["action"] == "allow"


def test_calls_below_warn_threshold_allow() -> None:
    detector = LoopDetector(warn_threshold=5, block_threshold=10)
    for _ in range(4):
        result = detector.check("web_search", {"q": "same"})
    assert result["action"] == "allow"


def test_warn_at_warn_threshold() -> None:
    detector = LoopDetector(warn_threshold=3, block_threshold=10)
    detector.check("web_search", {"q": "same"})
    detector.check("web_search", {"q": "same"})
    result = detector.check("web_search", {"q": "same"})
    assert result["action"] == "warn"


def test_block_at_block_threshold() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3)
    detector.check("web_search", {"q": "same"})
    detector.check("web_search", {"q": "same"})
    result = detector.check("web_search", {"q": "same"}, cost_per_call=0.5)
    assert result["action"] == "block"
    assert result["saved_usd"] == 0.5


def test_different_params_not_counted_when_similarity_enabled() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3, similarity_check=True)
    detector.check("web_search", {"q": "a"})
    result = detector.check("web_search", {"q": "b"})
    assert result["action"] == "allow"


def test_same_tool_different_params_counted_when_similarity_disabled() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3, similarity_check=False)
    detector.check("web_search", {"q": "a"})
    result = detector.check("web_search", {"q": "b"})
    assert result["action"] == "warn"


def test_window_expiry_old_calls_not_counted() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3, window_seconds=10)
    with patch("orchesis.loop_detector.time.time", side_effect=[0.0, 1.0, 20.0]):
        detector.check("tool", {"x": 1})
        detector.check("tool", {"x": 1})
        result = detector.check("tool", {"x": 1})
    assert result["action"] == "allow"


def test_total_saved_accumulates() -> None:
    detector = LoopDetector(warn_threshold=1, block_threshold=2)
    detector.check("t", {"x": 1}, cost_per_call=0.2)
    detector.check("t", {"x": 1}, cost_per_call=0.2)
    detector.check("t", {"x": 1}, cost_per_call=0.3)
    assert detector.total_saved > 0.0


def test_events_recorded_for_warn_and_block() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3)
    detector.check("t", {"x": 1})
    detector.check("t", {"x": 1})
    detector.check("t", {"x": 1})
    events = detector.events
    assert len(events) == 2
    assert {item.action_taken for item in events} == {"warned", "blocked"}


def test_stats_reporting_fields() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3)
    detector.check("t", {"x": 1})
    detector.check("t", {"x": 1})
    detector.check("t", {"x": 1})
    stats = detector.get_stats()
    assert "total_saved_usd" in stats
    assert "total_loops_detected" in stats
    assert "loops_warned" in stats
    assert "loops_blocked" in stats


def test_thread_safety_under_concurrency() -> None:
    detector = LoopDetector(warn_threshold=10, block_threshold=20)

    def worker() -> None:
        for _ in range(50):
            detector.check("search", {"q": "x"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(8):
            pool.submit(worker)
    stats = detector.get_stats()
    assert stats["total_loops_detected"] >= 1


def test_custom_thresholds_work() -> None:
    detector = LoopDetector(warn_threshold=1, block_threshold=2)
    first = detector.check("a", {"k": 1})
    second = detector.check("a", {"k": 1})
    assert first["action"] == "warn"
    assert second["action"] == "block"


def test_unhashable_params_do_not_crash() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3)
    result = detector.check("a", {"x": {1, 2, 3}})
    assert result["action"] in {"allow", "warn", "block"}


def test_message_present_on_warn() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=5)
    detector.check("a", {"k": 1})
    result = detector.check("a", {"k": 1})
    assert "Warning" in result["message"]


def test_message_present_on_block() -> None:
    detector = LoopDetector(warn_threshold=1, block_threshold=2)
    detector.check("a", {"k": 1})
    result = detector.check("a", {"k": 1})
    assert "Loop detected" in result["message"]


def test_events_property_returns_copy() -> None:
    detector = LoopDetector(warn_threshold=1, block_threshold=2)
    detector.check("a", {"k": 1})
    copied = detector.events
    copied.clear()
    assert len(detector.events) >= 1


def test_total_saved_initial_zero() -> None:
    detector = LoopDetector()
    assert detector.total_saved == 0.0

