from __future__ import annotations

import threading
import time

from orchesis.thompson_router import ModelStats, ThompsonRouter


def _cfg(tmp_path, **extra):
    cfg = {
        "enabled": True,
        "models": [
            {
                "name": "expensive",
                "cost_per_1k_input": 0.01,
                "cost_per_1k_output": 0.03,
                "max_context": 128000,
                "tier": "premium",
            },
            {
                "name": "cheap",
                "cost_per_1k_input": 0.0001,
                "cost_per_1k_output": 0.0004,
                "max_context": 128000,
                "tier": "economy",
            },
        ],
        "objective": "balanced",
        "min_exploration_rate": 0.0,
        "initial_exploration_rate": 0.0,
        "exploration_decay": 0.99,
        "save_interval_seconds": 1,
        "save_path": str(tmp_path / "thompson_stats.json"),
        "seed": 12345,
    }
    cfg.update(extra)
    return cfg


def _req(text: str = "hello", tools: bool = False):
    req = {"messages": [{"role": "user", "content": text}]}
    if tools:
        req["tools"] = [{"name": "read_file"}]
    return req


# Beta sampling
def test_beta_sample_returns_0_to_1(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        v = r.sample_beta(2.0, 3.0)
        assert 0.0 <= v <= 1.0
    finally:
        r.stop()


def test_beta_sample_high_alpha_biased_high(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        vals = [r.sample_beta(100.0, 1.0) for _ in range(200)]
        assert sum(vals) / len(vals) > 0.9
    finally:
        r.stop()


def test_beta_sample_high_beta_biased_low(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        vals = [r.sample_beta(1.0, 100.0) for _ in range(200)]
        assert sum(vals) / len(vals) < 0.1
    finally:
        r.stop()


def test_beta_sample_uniform_prior(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        vals = [r.sample_beta(1.0, 1.0) for _ in range(500)]
        mean = sum(vals) / len(vals)
        assert 0.4 < mean < 0.6
    finally:
        r.stop()


def test_beta_sample_deterministic_seed(tmp_path) -> None:
    r1 = ThompsonRouter(_cfg(tmp_path, seed=42))
    r2 = ThompsonRouter(_cfg(tmp_path, seed=42))
    try:
        assert r1.sample_beta(3.0, 7.0) == r2.sample_beta(3.0, 7.0)
    finally:
        r1.stop()
        r2.stop()


def test_gamma_sample_positive(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        assert r._gamma_sample(2.5) > 0.0
    finally:
        r.stop()


# Request classification
def test_classify_short_chat(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        assert "short" in c and "chat" in c
    finally:
        r.stop()


def test_classify_long_tools(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("x" * 50000, tools=True))
        assert "long" in c and "tools" in c
    finally:
        r.stop()


def test_classify_medium_chat(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("x" * 8000))
        assert "medium" in c
    finally:
        r.stop()


def test_classify_with_agent_id(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"), agent_id="agent-A")
        assert "agent_" in c
    finally:
        r.stop()


def test_classify_empty_request(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request({})
        assert isinstance(c, str) and c
    finally:
        r.stop()


# Model selection
def test_select_model_with_no_history(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        d = r.select_model(_req("hello"))
        assert d.selected_model in {"cheap", "expensive"}
    finally:
        r.stop()


def test_select_model_prefers_successful(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        cat = r.classify_request(_req("hello"))
        for _ in range(40):
            r.record_outcome("cheap", cat, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
            r.record_outcome("expensive", cat, {"success": False, "latency_ms": 400, "cost_usd": 0.01})
        d = r.select_model(_req("hello"))
        assert d.selected_model == "cheap"
    finally:
        r.stop()


def test_select_model_avoids_failing(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        cat = r.classify_request(_req("hello"))
        for _ in range(50):
            r.record_outcome("expensive", cat, {"success": False, "latency_ms": 500, "cost_usd": 0.02})
        d = r.select_model(_req("hello"))
        assert d.selected_model == "cheap"
    finally:
        r.stop()


def test_select_model_excludes_specified(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        d = r.select_model(_req("hello"), excluded_models=["cheap"])
        assert d.selected_model == "expensive"
    finally:
        r.stop()


def test_select_model_forced_exploration(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, min_exploration_rate=1.0, initial_exploration_rate=1.0))
    try:
        d = r.select_model(_req("hello"))
        assert d.reason == "forced_exploration"
    finally:
        r.stop()


def test_select_model_objective_cost_prefers_cheap(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="cost"))
    try:
        cat = r.classify_request(_req("hello"))
        r._stats[cat] = {
            "cheap": ModelStats(model="cheap", successes=10, failures=2, avg_cost_usd=0.001, avg_latency_ms=200),
            "expensive": ModelStats(model="expensive", successes=10, failures=2, avg_cost_usd=0.05, avg_latency_ms=200),
        }
        r.sample_beta = lambda a, b: 0.8  # type: ignore[method-assign]
        d = r.select_model(_req("hello"))
        assert d.selected_model == "cheap"
    finally:
        r.stop()


def test_select_model_objective_quality_prefers_best(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="quality"))
    try:
        cat = r.classify_request(_req("hello"))
        r._stats[cat] = {
            "cheap": ModelStats(model="cheap", successes=1, failures=20),
            "expensive": ModelStats(model="expensive", successes=40, failures=1),
        }
        d = r.select_model(_req("hello"))
        assert d.selected_model == "expensive"
    finally:
        r.stop()


def test_select_model_objective_speed_prefers_fast(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="speed"))
    try:
        cat = r.classify_request(_req("hello"))
        r._stats[cat] = {
            "cheap": ModelStats(model="cheap", successes=10, failures=2, avg_cost_usd=0.01, avg_latency_ms=100),
            "expensive": ModelStats(model="expensive", successes=10, failures=2, avg_cost_usd=0.01, avg_latency_ms=2000),
        }
        r.sample_beta = lambda a, b: 0.8  # type: ignore[method-assign]
        d = r.select_model(_req("hello"))
        assert d.selected_model == "cheap"
    finally:
        r.stop()


def test_select_model_objective_balanced(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="balanced"))
    try:
        d = r.select_model(_req("hello"))
        assert d.selected_model in {"cheap", "expensive"}
    finally:
        r.stop()


# Outcome recording
def test_record_success_increases_alpha(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": True})
        assert r._stats[c]["cheap"].successes == 1
    finally:
        r.stop()


def test_record_failure_increases_beta(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": False})
        assert r._stats[c]["cheap"].failures == 1
    finally:
        r.stop()


def test_record_updates_stats(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome(
            "cheap",
            c,
            {"success": True, "latency_ms": 120.0, "input_tokens": 20, "output_tokens": 10, "cost_usd": 0.002},
        )
        s = r._stats[c]["cheap"]
        assert s.avg_latency_ms == 120.0
        assert s.avg_tokens == 30.0
        assert s.avg_cost_usd == 0.002
    finally:
        r.stop()


def test_record_multiple_outcomes_converges(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        for _ in range(10):
            r.record_outcome("cheap", c, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
        s = r._stats[c]["cheap"]
        assert s.successes == 10
        assert s.failures == 0
    finally:
        r.stop()


# Quality scoring
def test_quality_score_perfect(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        for _ in range(5):
            r.record_outcome("cheap", c, {"success": True, "latency_ms": 200, "cost_usd": 0.01})
        q = r.compute_quality_score(
            {"model": "cheap", "success": True, "latency_ms": 100, "cost_usd": 0.001, "loop_detected": False, "injection_detected": False}
        )
        assert q >= 0.9
    finally:
        r.stop()


def test_quality_score_failure(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        q = r.compute_quality_score({"model": "cheap", "success": False, "error_type": "upstream_error"})
        assert q == 0.0
    finally:
        r.stop()


def test_quality_score_slow_but_successful(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        for _ in range(5):
            r.record_outcome("cheap", c, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
        q = r.compute_quality_score({"model": "cheap", "success": True, "latency_ms": 2000, "cost_usd": 0.001})
        assert 0.0 <= q <= 1.0
    finally:
        r.stop()


def test_quality_score_with_loop_detected(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        q = r.compute_quality_score({"model": "cheap", "success": True, "loop_detected": True, "injection_detected": False})
        assert q <= 1.0
    finally:
        r.stop()


def test_quality_score_clamped_0_1(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        q = r.compute_quality_score({"model": "cheap", "success": True, "error_type": "context_length"})
        assert 0.0 <= q <= 1.0
    finally:
        r.stop()


# Objective functions
def test_objective_cost_penalizes_expensive(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="cost"))
    try:
        cheap = ModelStats(model="cheap", avg_cost_usd=0.001, avg_latency_ms=100)
        expensive = ModelStats(model="expensive", avg_cost_usd=0.1, avg_latency_ms=100)
        r._stats["x"] = {"cheap": cheap, "expensive": expensive}
        assert r._apply_objective(0.8, cheap, "cost") > r._apply_objective(0.8, expensive, "cost")
    finally:
        r.stop()


def test_objective_speed_penalizes_slow(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="speed"))
    try:
        fast = ModelStats(model="cheap", avg_cost_usd=0.01, avg_latency_ms=100)
        slow = ModelStats(model="expensive", avg_cost_usd=0.01, avg_latency_ms=2000)
        r._stats["x"] = {"cheap": fast, "expensive": slow}
        assert r._apply_objective(0.8, fast, "speed") > r._apply_objective(0.8, slow, "speed")
    finally:
        r.stop()


def test_objective_balanced_combination(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, objective="balanced"))
    try:
        s = ModelStats(model="cheap", avg_cost_usd=0.01, avg_latency_ms=100)
        r._stats["x"] = {"cheap": s}
        v = r._apply_objective(0.7, s, "balanced")
        assert 0.0 <= v <= 1.0
    finally:
        r.stop()


# Learning over time
def test_learning_converges_to_best_model(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, min_exploration_rate=0.02, initial_exploration_rate=0.2))
    try:
        req = _req("hello")
        cat = r.classify_request(req)
        for _ in range(100):
            d = r.select_model(req)
            success = d.selected_model == "cheap"
            r.record_outcome(d.selected_model, cat, {"success": success, "latency_ms": 80 if success else 500, "cost_usd": 0.001 if success else 0.02})
        assert r._stats[cat]["cheap"].successes > r._stats[cat]["expensive"].successes
    finally:
        r.stop()


def test_learning_adapts_when_model_degrades(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, min_exploration_rate=0.02, initial_exploration_rate=0.2))
    try:
        req = _req("hello")
        cat = r.classify_request(req)
        for _ in range(40):
            r.record_outcome("cheap", cat, {"success": True, "latency_ms": 80, "cost_usd": 0.001})
        for _ in range(80):
            d = r.select_model(req)
            success = d.selected_model != "cheap"
            r.record_outcome(d.selected_model, cat, {"success": success, "latency_ms": 120, "cost_usd": 0.002})
        assert r._stats[cat]["cheap"].failures > 0
    finally:
        r.stop()


def test_learning_per_category_independent(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c1 = r.classify_request(_req("hello"))
        c2 = r.classify_request(_req("x" * 60000, tools=True))
        r.record_outcome("cheap", c1, {"success": True})
        r.record_outcome("expensive", c2, {"success": True})
        assert r._stats[c1]["cheap"].successes == 1
        assert r._stats[c2]["expensive"].successes == 1
    finally:
        r.stop()


def test_learning_exploration_decreases_over_time(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, min_exploration_rate=0.0, initial_exploration_rate=0.8, exploration_decay=0.9))
    try:
        r._rng.random = lambda: 0.2  # type: ignore[method-assign]
        d1 = r.select_model(_req("hello"))
        for _ in range(40):
            r.select_model(_req("hello"))
        d2 = r.select_model(_req("hello"))
        assert d1.reason in {"forced_exploration", "thompson_sample"}
        assert d2.reason == "thompson_sample"
    finally:
        r.stop()


# Persistence
def test_save_and_load_roundtrip(tmp_path) -> None:
    cfg = _cfg(tmp_path)
    r1 = ThompsonRouter(cfg)
    try:
        c = r1.classify_request(_req("hello"))
        r1.record_outcome("cheap", c, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
        r1.save()
    finally:
        r1.stop()
    r2 = ThompsonRouter(cfg)
    try:
        c = r2.classify_request(_req("hello"))
        assert r2._stats[c]["cheap"].successes >= 1
    finally:
        r2.stop()


def test_load_missing_file_no_crash(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path, save_path=str(tmp_path / "missing.json")))
    try:
        assert r.get_model_stats()
    finally:
        r.stop()


def test_load_corrupt_file_resets(tmp_path) -> None:
    p = tmp_path / "corrupt.json"
    p.write_text("{bad json", encoding="utf-8")
    r = ThompsonRouter(_cfg(tmp_path, save_path=str(p)))
    try:
        assert r._stats == {}
    finally:
        r.stop()


def test_auto_save_worker_runs(tmp_path) -> None:
    p = tmp_path / "autosave.json"
    r = ThompsonRouter(_cfg(tmp_path, save_path=str(p), save_interval_seconds=1))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": True})
        time.sleep(1.2)
        assert p.exists()
    finally:
        r.stop()


# Stats and reporting
def test_get_model_stats_comprehensive(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
        s = r.get_model_stats()
        assert "cheap" in s
        assert "thompson_alpha" in s["cheap"]
    finally:
        r.stop()


def test_get_routing_report_readable(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        txt = r.get_routing_report()
        assert "Thompson Router Report" in txt
    finally:
        r.stop()


def test_get_recommendation_after_data(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        for _ in range(30):
            r.record_outcome("cheap", c, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
            r.record_outcome("expensive", c, {"success": True, "latency_ms": 100, "cost_usd": 0.01})
        rec = r.get_recommendation()
        assert "recommendations" in rec
    finally:
        r.stop()


def test_reset_model(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": True})
        r.reset(model="cheap")
        assert "cheap" not in r._stats.get(c, {})
    finally:
        r.stop()


def test_reset_category(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        r.record_outcome("cheap", c, {"success": True})
        r.reset(category=c)
        assert c not in r._stats
    finally:
        r.stop()


# Edge cases
def test_single_model_always_selected(tmp_path) -> None:
    cfg = _cfg(tmp_path, models=[{"name": "only", "cost_per_1k_input": 0.001, "cost_per_1k_output": 0.002}])
    r = ThompsonRouter(cfg)
    try:
        d = r.select_model(_req("hello"))
        assert d.selected_model == "only"
    finally:
        r.stop()


def test_all_models_excluded_returns_fallback(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        d = r.select_model(_req("hello"), excluded_models=["cheap", "expensive"])
        assert d.reason == "fallback"
        assert d.selected_model in {"cheap", "expensive"}
    finally:
        r.stop()


def test_zero_successes_zero_failures(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    try:
        c = r.classify_request(_req("hello"))
        _ = r._stats_for(c, "cheap")
        d = r.select_model(_req("hello"))
        assert 0.0 <= d.confidence <= 1.0
    finally:
        r.stop()


def test_thread_safety_concurrent_select_and_record(tmp_path) -> None:
    r = ThompsonRouter(_cfg(tmp_path))
    errors = []
    cat = r.classify_request(_req("hello"))

    def worker():
        try:
            for _ in range(50):
                d = r.select_model(_req("hello"))
                r.record_outcome(d.selected_model, cat, {"success": True, "latency_ms": 100, "cost_usd": 0.001})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    r.stop()
    assert errors == []
