from __future__ import annotations

import time

from orchesis.loop_detector import ContentLoopDetector


def test_content_hash_basic() -> None:
    detector = ContentLoopDetector(max_identical=3)
    out = detector.check("Read HEARTBEAT.md")
    assert out["action"] == "allow"
    assert out["count"] == 1


def test_content_hash_identical_blocked() -> None:
    detector = ContentLoopDetector(max_identical=2)
    detector.check("same message")
    out = detector.check("same message")
    assert out["action"] == "block"


def test_content_hash_similar_but_different_allowed() -> None:
    detector = ContentLoopDetector(max_identical=2, hash_prefix_len=8)
    detector.check("abcdefgg_1")
    out = detector.check("abcdefhh_2")
    assert out["action"] == "allow"


def test_content_hash_per_session_isolation() -> None:
    detector = ContentLoopDetector(max_identical=2)
    detector.check("same", session_id="a")
    detector.check("same", session_id="a")
    out_b = detector.check("same", session_id="b")
    assert out_b["action"] == "allow"


def test_content_hash_cooldown() -> None:
    detector = ContentLoopDetector(max_identical=2, cooldown_seconds=1)
    detector.check("loop")
    detector.check("loop")
    out = detector.check("loop")
    assert out["action"] == "block"


def test_content_hash_exponential_backoff() -> None:
    detector = ContentLoopDetector(window_seconds=600, max_identical=2, cooldown_seconds=300)
    detector.check("aaa")
    first = detector.check("aaa")
    assert first["action"] == "block"
    second = detector.check("aaa")
    assert second["action"] == "block"
    assert int(first.get("retry_after", 0)) == 300
    assert int(second.get("retry_after", 0)) > 0


def test_content_hash_window_expiry() -> None:
    detector = ContentLoopDetector(window_seconds=1, max_identical=2)
    detector.check("same")
    time.sleep(1.05)
    out = detector.check("same")
    assert out["action"] == "allow"


def test_content_hash_stats() -> None:
    detector = ContentLoopDetector(max_identical=2)
    detector.check("one")
    detector.check("one")
    stats = detector.stats
    assert stats["detected"] >= 1
    assert stats["blocked"] >= 1


def test_content_hash_prefix_length() -> None:
    detector = ContentLoopDetector(hash_prefix_len=4)
    one = detector.check("abcdXX")
    two = detector.check("abcdYY")
    assert one["content_hash"] == two["content_hash"]


def test_loop_detector_session_hash_ttl_prune() -> None:
    detector = ContentLoopDetector(session_hash_ttl=0.05, max_identical=10)
    detector.check("one", session_id="s1")
    time.sleep(0.08)
    detector.check("two", session_id="s1")
    with detector._lock:
        assert "s1" in detector._last_hash_by_session


def test_loop_detector_max_sessions_cap() -> None:
    detector = ContentLoopDetector(max_sessions=3, session_hash_ttl=3600, max_identical=10)
    for i in range(5):
        detector.check(f"content-{i}", session_id=f"sid-{i}")
    with detector._lock:
        assert len(detector._last_hash_by_session) <= 3


def test_content_hash_unicode() -> None:
    detector = ContentLoopDetector(max_identical=2)
    detector.check("Привет HEARTBEAT")
    out = detector.check("Привет HEARTBEAT")
    assert out["action"] == "block"
