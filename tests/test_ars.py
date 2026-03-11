from __future__ import annotations

import threading

from orchesis.ars import AgentReliabilityScore


def test_task_completion_wilson_score() -> None:
    ars = AgentReliabilityScore()
    for _ in range(8):
        ars.update("a", is_session_end=True, session_success=True)
    for _ in range(2):
        ars.update("a", is_session_end=True, session_success=False)
    result = ars.compute("a")
    assert result is not None
    assert 0 < result.components["task_completion"] < 100


def test_task_completion_no_data_neutral() -> None:
    ars = AgentReliabilityScore()
    ars.update("a")
    result = ars.compute("a")
    assert result is not None
    assert result.components["task_completion"] == 50.0


def test_task_completion_all_success() -> None:
    ars = AgentReliabilityScore()
    for _ in range(20):
        ars.update("a", is_session_end=True, session_success=True)
    result = ars.compute("a")
    assert result is not None
    assert result.components["task_completion"] > 80


def test_task_completion_all_failure() -> None:
    ars = AgentReliabilityScore()
    for _ in range(20):
        ars.update("a", is_session_end=True, session_success=False)
    result = ars.compute("a")
    assert result is not None
    assert result.components["task_completion"] < 10


def test_task_completion_small_sample_conservative() -> None:
    ars = AgentReliabilityScore()
    ars.update("a", is_session_end=True, session_success=True)
    result = ars.compute("a")
    assert result is not None
    assert result.components["task_completion"] < 90


def test_loop_freedom_no_loops() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", loop_flagged=False)
    result = ars.compute("a")
    assert result is not None
    assert result.components["loop_freedom"] > 90


def test_loop_freedom_all_loops() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", loop_flagged=True)
    result = ars.compute("a")
    assert result is not None
    assert result.components["loop_freedom"] < 20


def test_loop_freedom_laplace_smoothing() -> None:
    ars = AgentReliabilityScore()
    ars.update("a", loop_flagged=True)
    result = ars.compute("a")
    assert result is not None
    assert 0 < result.components["loop_freedom"] < 50


def test_cost_efficiency_under_budget() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", cost_usd=1.0)
    result = ars.compute("a")
    assert result is not None
    assert result.components["cost_efficiency"] > 70


def test_cost_efficiency_at_budget() -> None:
    ars = AgentReliabilityScore()
    for _ in range(50):
        ars.update("a", cost_usd=1.0)
    result = ars.compute("a")
    assert result is not None
    assert result.components["cost_efficiency"] == 0.0


def test_cost_efficiency_over_budget() -> None:
    ars = AgentReliabilityScore()
    for _ in range(70):
        ars.update("a", cost_usd=1.0)
    result = ars.compute("a")
    assert result is not None
    assert result.components["cost_efficiency"] == 0.0


def test_latency_health_fast() -> None:
    ars = AgentReliabilityScore(latency_baseline_ms=2000)
    for _ in range(10):
        ars.update("a", latency_ms=100)
    result = ars.compute("a")
    assert result is not None
    assert result.components["latency_health"] == 100.0


def test_latency_health_slow() -> None:
    ars = AgentReliabilityScore(latency_baseline_ms=100)
    for _ in range(10):
        ars.update("a", latency_ms=1000)
    result = ars.compute("a")
    assert result is not None
    assert result.components["latency_health"] < 20


def test_latency_health_insufficient_data() -> None:
    ars = AgentReliabilityScore()
    for _ in range(3):
        ars.update("a", latency_ms=200)
    result = ars.compute("a")
    assert result is not None
    assert result.components["latency_health"] == 50.0


def test_context_stability_uniform() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", token_count=100)
    result = ars.compute("a")
    assert result is not None
    assert result.components["context_stability"] == 100.0


def test_context_stability_high_variance() -> None:
    ars = AgentReliabilityScore()
    for value in [10, 500, 20, 600, 15, 700]:
        ars.update("a", token_count=value)
    result = ars.compute("a")
    assert result is not None
    assert result.components["context_stability"] < 40


def test_termination_quality_all_clean() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", clean_termination=True)
    result = ars.compute("a")
    assert result is not None
    assert result.components["termination_quality"] == 100.0


def test_termination_quality_mixed() -> None:
    ars = AgentReliabilityScore()
    for _ in range(7):
        ars.update("a", clean_termination=True)
    for _ in range(3):
        ars.update("a", clean_termination=False)
    result = ars.compute("a")
    assert result is not None
    assert result.components["termination_quality"] == 70.0


def test_security_compliance_no_threats() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", has_threat=False)
    result = ars.compute("a")
    assert result is not None
    assert result.components["security_compliance"] == 100.0


def test_security_compliance_all_threats() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a", has_threat=True)
    result = ars.compute("a")
    assert result is not None
    assert result.components["security_compliance"] == 0.0


def test_compute_perfect_agent() -> None:
    ars = AgentReliabilityScore()
    for _ in range(300):
        ars.update(
            "a",
            is_session_end=True,
            session_success=True,
            loop_flagged=False,
            cost_usd=0.01,
            latency_ms=50,
            token_count=100,
            clean_termination=True,
            has_threat=False,
        )
    result = ars.compute("a")
    assert result is not None
    assert result.score >= 90


def test_compute_terrible_agent() -> None:
    ars = AgentReliabilityScore()
    for _ in range(300):
        ars.update(
            "a",
            is_session_end=True,
            session_success=False,
            loop_flagged=True,
            cost_usd=5.0,
            latency_ms=8000,
            token_count=1000,
            clean_termination=False,
            has_threat=True,
        )
    result = ars.compute("a")
    assert result is not None
    assert result.score < 40


def test_compute_average_agent() -> None:
    ars = AgentReliabilityScore()
    for i in range(100):
        ars.update(
            "a",
            is_session_end=True,
            session_success=(i % 3 != 0),
            loop_flagged=(i % 10 == 0),
            cost_usd=0.3,
            latency_ms=600,
            token_count=120 + (i % 30),
            clean_termination=(i % 4 != 0),
            has_threat=(i % 6 == 0),
        )
    result = ars.compute("a")
    assert result is not None
    assert 40 <= result.score <= 90


def test_compute_weighted_correctly() -> None:
    weights = {
        "task_completion": 100,
        "loop_freedom": 0,
        "cost_efficiency": 0,
        "latency_health": 0,
        "context_stability": 0,
        "termination_quality": 0,
        "security_compliance": 0,
    }
    ars = AgentReliabilityScore(weights=weights)
    for _ in range(20):
        ars.update("a", is_session_end=True, session_success=True)
    result = ars.compute("a")
    assert result is not None
    assert result.score == result.components["task_completion"]


def test_grade_a() -> None:
    ars = AgentReliabilityScore()
    for _ in range(200):
        ars.update("a", is_session_end=True, session_success=True, latency_ms=100, token_count=100, clean_termination=True)
    result = ars.compute("a")
    assert result is not None
    assert result.grade in {"A", "B"}


def test_grade_b() -> None:
    ars = AgentReliabilityScore()
    for i in range(200):
        ars.update("a", is_session_end=True, session_success=(i % 5 != 0), latency_ms=300, token_count=120, clean_termination=True)
    result = ars.compute("a")
    assert result is not None
    assert result.grade in {"A", "B", "C"}


def test_grade_c() -> None:
    ars = AgentReliabilityScore()
    for i in range(80):
        ars.update("a", is_session_end=True, session_success=(i % 2 == 0), latency_ms=800, token_count=200, clean_termination=(i % 3 != 0))
    result = ars.compute("a")
    assert result is not None
    assert result.grade in {"B", "C", "D"}


def test_grade_d() -> None:
    ars = AgentReliabilityScore()
    for i in range(120):
        ars.update("a", is_session_end=True, session_success=(i % 4 == 0), loop_flagged=True, latency_ms=2000, clean_termination=False, has_threat=True)
    result = ars.compute("a")
    assert result is not None
    assert result.grade in {"D", "F"}


def test_grade_f() -> None:
    ars = AgentReliabilityScore()
    for _ in range(120):
        ars.update("a", is_session_end=True, session_success=False, loop_flagged=True, cost_usd=10, latency_ms=10000, token_count=5000, clean_termination=False, has_threat=True)
    result = ars.compute("a")
    assert result is not None
    assert result.grade == "F"


def test_confidence_low() -> None:
    ars = AgentReliabilityScore()
    for _ in range(10):
        ars.update("a")
    result = ars.compute("a")
    assert result is not None
    assert result.confidence == "low"


def test_confidence_medium() -> None:
    ars = AgentReliabilityScore()
    for _ in range(60):
        ars.update("a")
    result = ars.compute("a")
    assert result is not None
    assert result.confidence == "medium"


def test_confidence_high() -> None:
    ars = AgentReliabilityScore()
    for _ in range(220):
        ars.update("a")
    result = ars.compute("a")
    assert result is not None
    assert result.confidence == "high"


def test_compute_all_multiple_agents() -> None:
    ars = AgentReliabilityScore()
    for _ in range(20):
        ars.update("a", is_session_end=True, session_success=True)
    for _ in range(20):
        ars.update("b", is_session_end=True, session_success=False)
    results = ars.compute_all()
    assert len(results) == 2


def test_update_unknown_agent_creates() -> None:
    ars = AgentReliabilityScore()
    ars.update("new_agent")
    result = ars.compute("new_agent")
    assert result is not None


def test_disabled_returns_none() -> None:
    ars = AgentReliabilityScore(enabled=False)
    ars.update("a")
    assert ars.compute("a") is None


def test_empty_agent_id_ignored() -> None:
    ars = AgentReliabilityScore()
    ars.update("")
    assert ars.compute_all() == []


def test_concurrent_updates() -> None:
    ars = AgentReliabilityScore()

    def _worker() -> None:
        for _ in range(200):
            ars.update("a", latency_ms=200, token_count=100, has_threat=False)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = ars.compute("a")
    assert result is not None
    assert result.sample_size == 1600


def test_stats_tracking() -> None:
    ars = AgentReliabilityScore()
    ars.update("a")
    ars.update("a")
    _ = ars.compute("a")
    stats = ars.stats
    assert stats["total_updates"] == 2
    assert stats["total_computes"] == 1
    assert stats["agents_tracked"] == 1
