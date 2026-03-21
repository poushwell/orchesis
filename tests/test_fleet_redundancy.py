from __future__ import annotations

from orchesis.fleet.redundancy import FleetRedundancyScorer


def test_model_diversity_single() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", model="gpt-4o")
    scorer.register_agent("a2", model="gpt-4o")
    scorer.register_agent("a3", model="gpt-4o")

    assert scorer.compute().model_diversity == 0.0


def test_model_diversity_perfect() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", model="gpt-4o")
    scorer.register_agent("a2", model="claude-3-sonnet")
    scorer.register_agent("a3", model="gemini-1.5-pro")

    assert scorer.compute().model_diversity > 0.99


def test_provider_diversity_mixed() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", provider="openai")
    scorer.register_agent("a2", provider="openai")
    scorer.register_agent("a3", provider="anthropic")

    score = scorer.compute().provider_diversity
    assert 0.0 < score < 1.0


def test_provider_diversity_all_different() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", provider="openai")
    scorer.register_agent("a2", provider="anthropic")
    scorer.register_agent("a3", provider="google")

    assert scorer.compute().provider_diversity > 0.99


def test_tool_coverage_full() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", tools=["search", "read_file"])
    scorer.register_agent("a2", tools=["search", "read_file"])

    assert scorer.compute().tool_coverage == 1.0


def test_tool_coverage_none() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", tools=["search"])
    scorer.register_agent("a2", tools=["read_file"])
    scorer.register_agent("a3", tools=["write_file"])

    assert scorer.compute().tool_coverage == 0.0


def test_tool_coverage_partial() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", tools=["search", "read_file"])
    scorer.register_agent("a2", tools=["search", "write_file"])
    scorer.register_agent("a3", tools=["delete_file"])

    score = scorer.compute().tool_coverage
    assert 0.0 < score < 1.0


def test_single_points_of_failure() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", tools=["search", "read_file"])
    scorer.register_agent("a2", tools=["search"])

    result = scorer.compute()
    assert "read_file" in result.single_points_of_failure


def test_overall_score_range() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", model="gpt-4o", provider="openai", tools=["search"], capabilities=["search"])
    scorer.register_agent("a2", model="claude", provider="anthropic", tools=["search"], capabilities=["search"])

    score = scorer.compute().overall
    assert 0.0 <= score <= 1.0


def test_overall_single_agent() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent(
        "solo",
        model="gpt-4o",
        provider="openai",
        tools=["search", "read_file"],
        capabilities=["search", "code"],
    )

    assert scorer.compute().overall < 0.3


def test_overall_diverse_fleet() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent(
        "a1",
        model="gpt-4o",
        provider="openai",
        tools=["search", "read_file"],
        capabilities=["search", "code"],
    )
    scorer.register_agent(
        "a2",
        model="claude-3-sonnet",
        provider="anthropic",
        tools=["search", "read_file"],
        capabilities=["search", "code"],
    )
    scorer.register_agent(
        "a3",
        model="gemini-1.5-pro",
        provider="google",
        tools=["search", "read_file"],
        capabilities=["search", "code"],
    )

    assert scorer.compute().overall > 0.9


def test_empty_fleet() -> None:
    result = FleetRedundancyScorer().compute()
    assert result.overall == 0.0
    assert result.fleet_size == 0


def test_summary_format() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", model="gpt-4o", provider="openai")
    summary = scorer.compute().summary()
    assert "Fleet Redundancy Score" in summary
    assert "Fleet size:" in summary


def test_register_remove() -> None:
    scorer = FleetRedundancyScorer()
    scorer.register_agent("a1", model="gpt-4o")
    scorer.remove_agent("a1")
    assert scorer.get_agents() == []
