from __future__ import annotations

from orchesis.carnot_efficiency import CarnotEfficiencyCalculator


def test_entropy_computed() -> None:
    calc = CarnotEfficiencyCalculator()
    entropy = calc.compute_entropy([10, 10, 10, 10])
    assert entropy > 1.0


def test_carnot_limit_formula() -> None:
    calc = CarnotEfficiencyCalculator()
    limit = calc.compute_carnot_limit(2.0, 8.0)
    assert limit == 0.75


def test_actual_efficiency_below_carnot() -> None:
    calc = CarnotEfficiencyCalculator()
    calc.record_session(
        "s1",
        {"semantic_tokens": 120, "total_tokens": 400, "h_min": 1.0, "h_max": 8.0},
    )
    row = calc.compute_actual_efficiency("s1")
    assert row["actual_efficiency"] < row["carnot_limit"]


def test_efficiency_gap_positive() -> None:
    calc = CarnotEfficiencyCalculator()
    calc.record_session(
        "s2",
        {"semantic_tokens": 80, "total_tokens": 400, "h_min": 1.0, "h_max": 8.0},
    )
    row = calc.compute_actual_efficiency("s2")
    assert row["efficiency_gap"] > 0.0


def test_utilization_ratio() -> None:
    calc = CarnotEfficiencyCalculator()
    calc.record_session(
        "s3",
        {"semantic_tokens": 200, "total_tokens": 400, "h_min": 1.0, "h_max": 8.0},
    )
    row = calc.compute_actual_efficiency("s3")
    assert 0.0 < row["utilization"] <= 1.0


def test_global_stats() -> None:
    calc = CarnotEfficiencyCalculator()
    calc.record_session("a", {"semantic_tokens": 100, "total_tokens": 500, "h_min": 1.0, "h_max": 8.0})
    calc.record_session("b", {"semantic_tokens": 200, "total_tokens": 600, "h_min": 2.0, "h_max": 8.0})
    stats = calc.get_global_stats()
    assert stats["sessions"] == 2
    assert stats["avg_carnot_limit"] > 0.0


def test_perfect_efficiency_impossible() -> None:
    calc = CarnotEfficiencyCalculator()
    calc.record_session(
        "s4",
        {"semantic_tokens": 400, "total_tokens": 400, "h_min": 2.0, "h_max": 8.0},
    )
    row = calc.compute_actual_efficiency("s4")
    assert row["actual_efficiency"] > row["carnot_limit"]


def test_zero_entropy_edge_case() -> None:
    calc = CarnotEfficiencyCalculator()
    assert calc.compute_entropy([]) == 0.0
    assert calc.compute_entropy([0, 0, 0]) == 0.0
