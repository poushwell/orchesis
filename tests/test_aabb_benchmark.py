from __future__ import annotations

from orchesis.aabb.benchmark import AABBBenchmark


def test_suite_returns_scores() -> None:
    bench = AABBBenchmark()
    result = bench.run_suite("agent-a", "http://localhost:8080")
    assert result["agent_id"] == "agent-a"
    assert 0.0 <= result["overall_score"] <= 100.0
    assert isinstance(result["category_scores"], dict)


def test_category_scores_sum_correctly() -> None:
    bench = AABBBenchmark()
    result = bench.run_suite("agent-a", "http://localhost:8080")
    cat_scores = list(result["category_scores"].values())
    expected = round(sum(float(x) for x in cat_scores) / len(cat_scores), 2)
    assert result["overall_score"] == expected


def test_leaderboard_ranked() -> None:
    bench = AABBBenchmark()
    bench.run_suite("agent-a", "http://localhost:8080")
    bench.run_suite("agent-b", "http://localhost:8080")
    board = bench.get_leaderboard()
    assert len(board) >= 2
    assert board[0]["overall_score"] >= board[1]["overall_score"]
    assert board[0]["rank"] == 1


def test_compare_agents_returns_diff() -> None:
    bench = AABBBenchmark()
    bench.run_suite("agent-a", "http://localhost:8080")
    bench.run_suite("agent-b", "http://localhost:8080")
    diff = bench.compare_agents("agent-a", "agent-b")
    assert "diff" in diff
    assert "winner" in diff
    assert isinstance(diff["category_diff"], dict)


def test_benchmark_stats_tracked() -> None:
    bench = AABBBenchmark()
    bench.run_suite("agent-a", "http://localhost:8080")
    bench.run_suite("agent-b", "http://localhost:8080")
    stats = bench.get_benchmark_stats()
    assert stats["total_runs"] == 2
    assert stats["unique_agents"] == 2
    assert 0.0 <= stats["avg_score"] <= 100.0


def test_reliability_category_runs() -> None:
    bench = AABBBenchmark()
    result = bench.run_category("agent-a", "reliability")
    assert result["category"] == "reliability"
    assert len(result["checks"]) == 4


def test_security_category_runs() -> None:
    bench = AABBBenchmark()
    result = bench.run_category("agent-a", "security")
    assert result["category"] == "security"
    assert len(result["checks"]) == 4


def test_all_categories_covered() -> None:
    bench = AABBBenchmark()
    result = bench.run_suite("agent-a", "http://localhost:8080")
    assert set(result["category_scores"].keys()) == set(bench.BENCHMARK_CATEGORIES.keys())
