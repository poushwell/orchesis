from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import time

from orchesis.loop_detector import LoopDetector


def _cfg(action_exact: str = "warn", action_fuzzy: str = "block") -> dict:
    return {
        "enabled": True,
        "exact": {"threshold": 5, "window_seconds": 120, "action": action_exact},
        "fuzzy": {"threshold": 8, "window_seconds": 300, "action": action_fuzzy},
        "on_detect": {"notify": True, "log": True, "max_cost_saved": True},
    }


def _req(model: str = "gpt-4o", content: str = "hello", tools: list[dict] | None = None) -> dict:
    return {
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "tool_calls": tools or [],
        "content_text": content,
    }


def test_exact_loop_threshold_allow_then_warn() -> None:
    detector = LoopDetector(config=_cfg(action_exact="warn"))
    for _ in range(4):
        result = detector.check_request(_req(content="same"))
        assert result.action == "allow"
    fifth = detector.check_request(_req(content="same"))
    assert fifth.action == "warn"


def test_fuzzy_loop_threshold_blocks() -> None:
    detector = LoopDetector(config=_cfg(action_fuzzy="block"))
    req = _req(content="similar prompt", tools=[{"name": "read_file"}])
    for _ in range(7):
        detector.check_request(req)
    blocked = detector.check_request(req)
    assert blocked.action == "block"
    assert blocked.loop_type == "fuzzy"


def test_window_expiry_old_requests_not_counted() -> None:
    cfg = _cfg()
    cfg["exact"]["threshold"] = 2
    cfg["exact"]["window_seconds"] = 1
    detector = LoopDetector(config=cfg)
    detector.check_request(_req(content="same"))
    time.sleep(1.1)
    second = detector.check_request(_req(content="same"))
    assert second.action == "allow"


def test_different_models_are_separate_patterns() -> None:
    cfg = _cfg()
    cfg["exact"]["threshold"] = 2
    detector = LoopDetector(config=cfg)
    detector.check_request(_req(model="gpt-4o", content="same"))
    second = detector.check_request(_req(model="claude-opus-4", content="same"))
    assert second.action == "allow"


def test_action_warn_vs_block_vs_downgrade_model() -> None:
    warn_detector = LoopDetector(config=_cfg(action_exact="warn"))
    block_cfg = _cfg(action_exact="block")
    downgrade_cfg = _cfg(action_exact="downgrade_model")
    for cfg in (warn_detector, LoopDetector(config=block_cfg), LoopDetector(config=downgrade_cfg)):
        for _ in range(4):
            cfg.check_request(_req(content="same"))
    assert warn_detector.check_request(_req(content="same")).action == "warn"
    assert LoopDetector(config=block_cfg).check_request(_req(content="new")).action == "allow"
    downgrade = LoopDetector(config=downgrade_cfg)
    for _ in range(5):
        decision = downgrade.check_request(_req(content="same"))
    assert decision.action == "downgrade_model"


def test_estimated_cost_saved_positive_on_block() -> None:
    cfg = _cfg(action_exact="block")
    cfg["exact"]["threshold"] = 2
    detector = LoopDetector(config=cfg)
    detector.check_request(_req(content="same"))
    blocked = detector.check_request(_req(content="same"))
    assert blocked.estimated_cost_saved > 0


def test_reset_and_auto_cleanup() -> None:
    detector = LoopDetector(config=_cfg())
    for _ in range(8):
        detector.check_request(_req(content="same", tools=[{"name": "read_file"}]))
    assert detector.get_stats()["active_patterns_count"] >= 1
    detector.reset()
    assert detector.get_stats()["active_patterns_count"] == 0


def test_thread_safety_check_request() -> None:
    detector = LoopDetector(config=_cfg())

    def worker() -> None:
        for _ in range(50):
            detector.check_request(_req(content="same", tools=[{"name": "read_file"}]))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(8):
            pool.submit(worker)
    stats = detector.get_stats()
    assert stats["fuzzy_detections"] >= 1


def test_legacy_check_api_still_works() -> None:
    detector = LoopDetector(warn_threshold=2, block_threshold=3)
    detector.check("web_search", {"q": "same"})
    result = detector.check("web_search", {"q": "same"})
    assert result["action"] == "warn"


def test_legacy_stats_fields_present() -> None:
    detector = LoopDetector(warn_threshold=1, block_threshold=2)
    detector.check("a", {"x": 1})
    detector.check("a", {"x": 1})
    stats = detector.get_stats()
    assert "total_saved_usd" in stats
    assert "loops_blocked" in stats
    assert "exact_detections" in stats
    assert "fuzzy_detections" in stats

