from __future__ import annotations

import random

from orchesis.model_router import ModelRouter, ThompsonSampler


def test_sampler_register() -> None:
    sampler = ThompsonSampler()
    sampler.register_model("a")
    stats = sampler.get_stats()
    assert "a" in stats
    assert stats["a"]["alpha"] == 1.0
    assert stats["a"]["beta"] == 1.0


def test_sampler_sample_returns_valid_model() -> None:
    random.seed(7)
    sampler = ThompsonSampler()
    sampler.register_model("a")
    sampler.register_model("b")
    picked = sampler.sample(["a", "b"])
    assert picked in {"a", "b"}


def test_sampler_update_success() -> None:
    sampler = ThompsonSampler()
    sampler.register_model("a")
    sampler.update("a", True)
    assert sampler.get_stats()["a"]["alpha"] == 2.0


def test_sampler_update_failure() -> None:
    sampler = ThompsonSampler()
    sampler.register_model("a")
    sampler.update("a", False)
    assert sampler.get_stats()["a"]["beta"] == 2.0


def test_sampler_convergence() -> None:
    random.seed(42)
    sampler = ThompsonSampler()
    sampler.register_model("A")
    sampler.register_model("B")
    for _ in range(100):
        sampler.update("A", True)
    for _ in range(10):
        sampler.update("B", True)
    picks = {"A": 0, "B": 0}
    for _ in range(1000):
        picks[sampler.sample(["A", "B"])] += 1
    assert picks["A"] > picks["B"]
    assert picks["A"] / 1000.0 >= 0.55


def test_sampler_uniform_prior() -> None:
    random.seed(123)
    sampler = ThompsonSampler()
    sampler.register_model("A")
    sampler.register_model("B")
    picks = {"A": 0, "B": 0}
    for _ in range(1000):
        picks[sampler.sample(["A", "B"])] += 1
    ratio_a = picks["A"] / 1000.0
    assert 0.35 <= ratio_a <= 0.65


def test_router_record_outcome() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    before = router.get_sampler_stats()["gpt-4o"]["alpha"]
    router.record_outcome("gpt-4o", True)
    after = router.get_sampler_stats()["gpt-4o"]["alpha"]
    assert after == before + 1.0


def test_router_get_sampler_stats() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    stats = router.get_sampler_stats()
    assert "gpt-4o" in stats
    assert "alpha" in stats["gpt-4o"]
    assert "beta" in stats["gpt-4o"]


def test_router_sampler_used_flag() -> None:
    random.seed(1)
    router = ModelRouter(
        {
            "default": "gpt-4o",
            "rules": [
                {"complexity": "low", "model": "gpt-4o-mini"},
                {"complexity": "low", "model": "gpt-4.1-mini"},
                {"complexity": "high", "model": "gpt-4o"},
            ],
        }
    )
    result = router.route("please list files")
    assert result["complexity"] == "low"
    assert result["sampler_used"] is True


def test_router_backward_compatible() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("please analyze this")
    for key in ("model", "complexity", "reason", "cost_ratio"):
        assert key in result
    assert "sampler_used" in result


def test_router_single_candidate_no_sampler() -> None:
    router = ModelRouter(
        {
            "default": "gpt-4o",
            "rules": [
                {"complexity": "low", "model": "gpt-4o-mini"},
                {"complexity": "high", "model": "gpt-4o"},
            ],
        }
    )
    result = router.route("please list files")
    assert result["sampler_used"] is False


def test_thompson_exploration() -> None:
    random.seed(99)
    sampler = ThompsonSampler()
    sampler.register_model("A")
    sampler.register_model("B")
    for _ in range(30):
        sampler.update("A", True)
    picks = {"A": 0, "B": 0}
    for _ in range(1000):
        picks[sampler.sample(["A", "B"])] += 1
    assert picks["B"] > 0


def test_get_savings_estimate_unchanged() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    router.route("rename this file")
    router.route("format this text")
    estimate = router.get_savings_estimate()
    assert "estimated_savings_percent" in estimate
    assert estimate["total_calls_routed"] == 2


def test_sampler_stats_estimated_rate() -> None:
    sampler = ThompsonSampler()
    sampler.register_model("A")
    sampler.update("A", True)
    sampler.update("A", False)
    stats = sampler.get_stats()["A"]
    expected = stats["alpha"] / (stats["alpha"] + stats["beta"])
    assert stats["estimated_success_rate"] == expected


def test_router_registers_all_models() -> None:
    router = ModelRouter(
        {
            "default": "gpt-4o",
            "rules": [
                {"complexity": "low", "model": "gpt-4o-mini"},
                {"complexity": "medium", "model": "gpt-4.1-mini"},
                {"complexity": "high", "model": "claude-sonnet-4-20250514"},
            ],
        }
    )
    stats = router.get_sampler_stats()
    assert "gpt-4o" in stats
    assert "gpt-4o-mini" in stats
    assert "gpt-4.1-mini" in stats
    assert "claude-sonnet-4-20250514" in stats

