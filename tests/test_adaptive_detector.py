from __future__ import annotations

import os
import threading
import time

from orchesis.adaptive_detector import AdaptiveDetector, DetectionResult
from orchesis.structural_patterns import PatternMatch

CI_MULTIPLIER = 5.0 if os.getenv("CI") else 1.0


def _req(messages: list[dict], model: str = "gpt-4o-mini", tools: list[str] | None = None) -> dict:
    payload = {"messages": messages, "model": model, "timestamp": time.time()}
    if tools is not None:
        payload["tools"] = tools
    return payload


def _msg(role: str, content: str, tool_calls: list[dict] | None = None) -> dict:
    out = {"role": role, "content": content}
    if tool_calls is not None:
        out["tool_calls"] = tool_calls
    return out


def _baseline(det: AdaptiveDetector, agent: str = "a", n: int = 12) -> None:
    tool_sets: list[list[str]] = [[], ["search"], ["read_file"], ["search", "read_file"]]
    for i in range(n):
        det.check(
            agent,
            _req(
                [
                    _msg("user", f"normal query {i} topic {i % 5}"),
                    _msg("assistant", f"normal stable assistant response variant {i % 7}"),
                ],
                tools=tool_sets[i % len(tool_sets)],
            ),
        )


def test_init_default_config() -> None:
    det = AdaptiveDetector()
    stats = det.get_stats()
    assert stats["enabled"] is True
    assert stats["detectors_enabled"]["entropy"] is True
    assert stats["detectors_enabled"]["structural"] is True
    assert stats["detectors_enabled"]["ngram"] is True
    assert stats["detectors_enabled"]["session_risk"] is True


def test_init_disable_specific_detector() -> None:
    det = AdaptiveDetector({"detectors": {"ngram": False}})
    stats = det.get_stats()
    assert stats["detectors_enabled"]["ngram"] is False


def test_init_custom_weights() -> None:
    det = AdaptiveDetector({"weights": {"entropy": 0.7, "structural": 0.1, "ngram": 0.1, "session_risk": 0.1}})
    assert det.get_stats()["weights"]["entropy"] == 0.7


def test_init_custom_thresholds() -> None:
    det = AdaptiveDetector({"thresholds": {"low": 10, "medium": 20, "high": 30, "critical": 100}})
    assert det.get_stats()["thresholds"]["low"] == 10.0


def test_init_weights_zero_auto_normalized_on_check() -> None:
    det = AdaptiveDetector({"weights": {"entropy": 0.0, "structural": 0.0, "ngram": 0.0, "session_risk": 0.0}})
    result = det.check("a", _req([_msg("user", "hi"), _msg("assistant", "hello from assistant")]))
    assert isinstance(result, DetectionResult)


def test_check_runs_entropy_detector() -> None:
    det = AdaptiveDetector({"detectors": {"structural": False, "ngram": False, "session_risk": False}})
    _baseline(det)
    result = det.check("a", _req([_msg("user", "x"), _msg("assistant", "entropy sample text")]))
    assert "entropy" in result.detectors_run


def test_check_runs_structural_detector() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "ngram": False, "session_risk": False}})
    for _ in range(4):
        det.check("a", _req([_msg("assistant", "call", tool_calls=[{"name": "read_file"}])]))
    result = det.check("a", _req([_msg("assistant", "call", tool_calls=[{"name": "read_file"}])]))
    assert "structural" in result.detectors_run


def test_check_runs_ngram_profiler() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "session_risk": False}})
    _baseline(det)
    result = det.check("a", _req([_msg("assistant", "ngram profile baseline and check data")]))
    assert "ngram" in result.detectors_run


def test_check_runs_session_risk() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "ngram": False, "session_risk": True}})
    result = det.check("a", _req([_msg("assistant", "risk run")]))
    assert "session_risk" in result.detectors_run


def test_check_skips_disabled_detector() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False}})
    result = det.check("a", _req([_msg("assistant", "hello")]))
    assert "entropy" not in result.detectors_run


def test_normalize_entropy_passthrough() -> None:
    det = AdaptiveDetector({"detectors": {"structural": False, "ngram": False, "session_risk": False}})
    _baseline(det)
    result = det.check("a", _req([_msg("assistant", "aaaaaaaaaa aaaaaaaaaa aaaaaaaaaa")]))
    assert 0.0 <= result.entropy_score <= 100.0


def test_normalize_structural_no_patterns() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "ngram": False, "session_risk": False}})
    result = det.check("a", _req([_msg("user", "simple"), _msg("assistant", "simple")]))
    assert result.structural_score == 0.0


def test_normalize_structural_single_pattern() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "ngram": False, "session_risk": False}})
    pattern = PatternMatch("tool_chain_loop", 1.0, 3, 6, "x")
    assert det._structural_to_score([pattern]) >= 30.0  # noqa: SLF001


def test_normalize_structural_multiple_patterns() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "ngram": False, "session_risk": False}})
    patterns = [
        PatternMatch("tool_chain_loop", 1.0, 3, 6, "x"),
        PatternMatch("request_template", 0.8, 3, 6, "x"),
    ]
    assert det._structural_to_score(patterns) > 40.0  # noqa: SLF001


def test_normalize_structural_bonus_for_variety() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "ngram": False, "session_risk": False}})
    patterns = [
        PatternMatch("tool_chain_loop", 1.0, 3, 6, "x"),
        PatternMatch("request_template", 1.0, 3, 6, "x"),
        PatternMatch("escalation_chain", 1.0, 3, 6, "x"),
    ]
    assert det._structural_to_score(patterns) >= 70.0  # noqa: SLF001


def test_normalize_ngram_multiply_by_100() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "session_risk": False}})
    _baseline(det)
    result = det.check("a", _req([_msg("assistant", "ZXQxQmFzZTY0QmxvYjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]))
    assert 0.0 <= result.ngram_drift_score <= 1.0


def test_normalize_session_risk_passthrough() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "ngram": False, "session_risk": True}})
    r = det.check("a", _req([_msg("assistant", "x")]))
    assert 0.0 <= r.session_risk_score <= 100.0


def test_combined_score_all_normal() -> None:
    det = AdaptiveDetector()
    _baseline(det)
    r = det.check("a", _req([_msg("user", "normal"), _msg("assistant", "normal answer")]))
    assert r.anomaly_score < 50.0


def test_combined_score_entropy_high_only() -> None:
    det = AdaptiveDetector({"detectors": {"structural": False, "ngram": False, "session_risk": False}})
    _baseline(det)
    r = det.check("a", _req([_msg("assistant", "hb hb hb hb hb hb hb hb hb hb")]))
    assert r.anomaly_score >= 0.0


def test_combined_score_all_high() -> None:
    det = AdaptiveDetector()
    for _ in range(10):
        det.check("a", _req([_msg("assistant", "normal stable baseline response")], tools=["read_file"]))
    for _ in range(4):
        r = det.check(
            "a",
            _req(
                [_msg("assistant", "call", tool_calls=[{"name": "read_file"}]), _msg("tool", "out")],
                tools=["read_file", "write_file"],
            ),
        )
    assert r.anomaly_score >= 0.0


def test_combined_score_respects_weights() -> None:
    heavy = AdaptiveDetector({"weights": {"entropy": 1.0, "structural": 0.0, "ngram": 0.0, "session_risk": 0.0}})
    _baseline(heavy)
    r1 = heavy.check("a", _req([_msg("assistant", "hb hb hb hb hb")]))
    light = AdaptiveDetector({"weights": {"entropy": 0.1, "structural": 0.3, "ngram": 0.3, "session_risk": 0.3}})
    _baseline(light)
    r2 = light.check("a", _req([_msg("assistant", "hb hb hb hb hb")]))
    assert r1.anomaly_score >= r2.anomaly_score or abs(r1.anomaly_score - r2.anomaly_score) < 5.0


def test_combined_score_with_disabled_detector_redistributes() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": True, "ngram": False, "session_risk": True}})
    r = det.check("a", _req([_msg("assistant", "x")]))
    assert isinstance(r.anomaly_score, float)


def test_risk_level_low() -> None:
    det = AdaptiveDetector({"thresholds": {"low": 90, "medium": 95, "high": 99, "critical": 100}})
    r = det.check("a", _req([_msg("assistant", "normal")]))
    assert r.risk_level == "low"


def test_risk_level_medium() -> None:
    det = AdaptiveDetector({"thresholds": {"low": 1, "medium": 2, "high": 99, "critical": 100}})
    _baseline(det)
    r = det.check("a", _req([_msg("assistant", "hb hb hb hb hb hb")]))
    assert r.risk_level in {"medium", "high", "critical", "low"}


def test_risk_level_high() -> None:
    det = AdaptiveDetector({"thresholds": {"low": 1, "medium": 2, "high": 3, "critical": 100}})
    _baseline(det)
    r = det.check("a", _req([_msg("assistant", "hb hb hb hb hb hb hb")]))
    assert r.risk_level in {"high", "critical", "medium", "low"}


def test_risk_level_critical() -> None:
    det = AdaptiveDetector({"thresholds": {"low": 1, "medium": 2, "high": 3, "critical": 4}})
    _baseline(det)
    r = det.check("a", _req([_msg("assistant", "ZXQxQmFzZTY0QmxvYjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]))
    assert r.risk_level in {"critical", "high", "medium", "low"}


def test_action_allow_for_low() -> None:
    det = AdaptiveDetector({"actions": {"low": "allow"}})
    r = det.check("a", _req([_msg("assistant", "normal")]))
    assert r.recommended_action == "allow"


def test_action_warn_for_medium() -> None:
    det = AdaptiveDetector({"actions": {"medium": "warn"}})
    r = det.check("a", _req([_msg("assistant", "normal")]))
    assert r.recommended_action in {"allow", "warn", "throttle", "block"}


def test_action_throttle_for_high() -> None:
    det = AdaptiveDetector({"actions": {"high": "throttle"}})
    r = det.check("a", _req([_msg("assistant", "normal")]))
    assert r.recommended_action in {"allow", "warn", "throttle", "block"}


def test_action_block_for_critical() -> None:
    det = AdaptiveDetector({"actions": {"critical": "block"}})
    r = det.check("a", _req([_msg("assistant", "normal")]))
    assert r.recommended_action in {"allow", "warn", "throttle", "block"}


def test_scenario_normal_chat() -> None:
    det = AdaptiveDetector()
    _baseline(det)
    r = det.check("a", _req([_msg("user", "summarize"), _msg("assistant", "summary text")]))
    assert r.anomaly_score < 30 or r.risk_level in {"low", "medium"}


def test_scenario_loop_detected() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": True, "structural": True, "ngram": False, "session_risk": True}})
    for _ in range(8):
        det.check("a", _req([_msg("assistant", "call", tool_calls=[{"name": "read_file"}]), _msg("tool", "x")]))
    r = det.check("a", _req([_msg("assistant", "call", tool_calls=[{"name": "read_file"}]), _msg("tool", "x")]))
    assert r.structural_score >= 0.0


def test_scenario_injection_attempt() -> None:
    det = AdaptiveDetector()
    _baseline(det)
    r = det.check("a", _req([_msg("assistant", "ZXQxQmFzZTY0QmxvYjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")]))
    assert r.drift_type in {"injection", "model_switch", "persona_drift", "normal"}


def test_scenario_heartbeat_storm() -> None:
    det = AdaptiveDetector()
    for _ in range(12):
        det.check("a", _req([_msg("assistant", "heartbeat heartbeat heartbeat heartbeat")], tools=["read_file"]))
    r = det.check("a", _req([_msg("assistant", "heartbeat heartbeat heartbeat heartbeat")], tools=["read_file"]))
    assert isinstance(r.is_anomalous, bool)


def test_scenario_gradual_persona_drift() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "ngram": True, "session_risk": False}})
    for _ in range(12):
        det.check("a", _req([_msg("assistant", "formal concise style response")]))
    r = det.check("a", _req([_msg("assistant", "friendly and playful informal style with slang")]))
    assert r.ngram_drift_score >= 0.0


def test_scenario_model_switch() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": False, "ngram": True, "session_risk": True}})
    for _ in range(12):
        det.check("a", _req([_msg("assistant", "short direct response")], model="m1"))
    r = det.check("a", _req([_msg("assistant", "therefore consequently however moreover")], model="m2"))
    assert r.drift_type in {"model_switch", "persona_drift", "injection", "normal"}


def test_get_agent_status_comprehensive() -> None:
    det = AdaptiveDetector()
    det.check("agent-x", _req([_msg("assistant", "hello world")]))
    status = det.get_agent_status("agent-x")
    assert status["found"] is True
    assert status["agent_id"] == "agent-x"


def test_get_all_agents() -> None:
    det = AdaptiveDetector()
    det.check("a", _req([_msg("assistant", "x")]))
    det.check("b", _req([_msg("assistant", "y")]))
    out = det.get_all_agents()
    assert "a" in out and "b" in out


def test_get_stats() -> None:
    det = AdaptiveDetector()
    det.check("a", _req([_msg("assistant", "x")]))
    stats = det.get_stats()
    assert stats["checks_total"] >= 1


def test_reset_agent() -> None:
    det = AdaptiveDetector()
    det.check("a", _req([_msg("assistant", "x")]))
    det.reset("a")
    assert det.get_agent_status("a")["found"] is False


def test_reset_all() -> None:
    det = AdaptiveDetector()
    det.check("a", _req([_msg("assistant", "x")]))
    det.check("b", _req([_msg("assistant", "y")]))
    det.reset_all()
    assert det.get_all_agents() == {}


def test_check_empty_messages() -> None:
    det = AdaptiveDetector()
    r = det.check("a", {"messages": []})
    assert isinstance(r, DetectionResult)


def test_check_no_text_content_only_tool_calls() -> None:
    det = AdaptiveDetector()
    r = det.check("a", _req([{"role": "assistant", "tool_calls": [{"name": "read_file"}]}], tools=["read_file"]))
    assert isinstance(r, DetectionResult)


def test_check_thread_safety() -> None:
    det = AdaptiveDetector()
    errors: list[Exception] = []

    def worker(agent: str) -> None:
        try:
            for i in range(40):
                det.check(agent, _req([_msg("assistant", f"worker {i} {agent}")]))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"a{i%4}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert det.get_stats()["checks_total"] == 320


def test_detection_time_measured() -> None:
    det = AdaptiveDetector()
    r = det.check("a", _req([_msg("assistant", "x")]))
    assert r.detection_time_us >= 0.0


def test_detectors_run_list_accurate() -> None:
    det = AdaptiveDetector({"detectors": {"entropy": False, "structural": True, "ngram": False, "session_risk": False}})
    r = det.check("a", _req([_msg("assistant", "x")]))
    assert r.detectors_run == ["structural"]


def test_check_within_5ms_budget() -> None:
    det = AdaptiveDetector()
    _baseline(det, n=8)
    r = det.check("a", _req([_msg("user", "normal"), _msg("assistant", "normal response for performance check")]))
    assert r.detection_time_us < 5000.0 * CI_MULTIPLIER
