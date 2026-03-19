from __future__ import annotations

from orchesis.fitness_landscape import FitnessLandscapeMapper


def test_evaluation_recorded() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"alpha": 0.1, "beta": 0.2}, 0.72)
    stats = mapper.get_stats()
    assert stats["evaluations"] == 1


def test_local_optima_found() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"p": 1}, 0.60)
    mapper.evaluate({"p": 2}, 0.95)
    mapper.evaluate({"p": 3}, 0.90)
    optima = mapper.find_local_optima()
    assert len(optima) >= 2
    assert float(optima[0]["fitness"]) >= float(optima[1]["fitness"])


def test_ruggedness_computed() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"x": 1}, 0.20)
    mapper.evaluate({"x": 2}, 0.80)
    ruggedness = mapper.compute_ruggedness()
    assert ruggedness > 0.0


def test_gradient_ascending() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"k": 1}, 0.95)
    mapper.evaluate({"k": 2}, 0.40)
    mapper.evaluate({"k": 3}, 0.45)
    gradient = mapper.get_gradient({"k": 1})
    assert gradient["gradient"] > 0.0
    assert gradient["direction"] == "ascending"


def test_gradient_at_optimum() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"k": 1}, 0.50)
    gradient = mapper.get_gradient({"k": 1})
    assert gradient["at_optimum"] is True


def test_global_optimum_flagged() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"x": 1}, 0.80)
    mapper.evaluate({"x": 2}, 0.99)
    rows = mapper.find_local_optima()
    assert any(bool(item["global_optimum"]) for item in rows)


def test_empty_landscape_safe() -> None:
    mapper = FitnessLandscapeMapper()
    assert mapper.find_local_optima() == []
    assert mapper.compute_ruggedness() == 0.0
    gradient = mapper.get_gradient({"x": 0})
    assert "gradient" in gradient


def test_stats_returned() -> None:
    mapper = FitnessLandscapeMapper()
    mapper.evaluate({"x": 1}, 0.7)
    mapper.evaluate({"x": 2}, 0.8)
    stats = mapper.get_stats()
    assert set(stats.keys()) == {"evaluations", "ruggedness", "optima_count"}
    assert stats["evaluations"] == 2
