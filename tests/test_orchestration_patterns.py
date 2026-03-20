from __future__ import annotations

from orchesis.orchestration_patterns import OrchestrationPatternAdvisor, PATTERNS


def test_patterns_listed() -> None:
    advisor = OrchestrationPatternAdvisor()
    rows = advisor.list_patterns()
    assert len(rows) == len(PATTERNS)
    assert all("id" in row for row in rows)


def test_pattern_retrieved() -> None:
    advisor = OrchestrationPatternAdvisor()
    row = advisor.get_pattern("parallel_fan_out")
    assert row is not None
    assert row["name"] == "Parallel Fan-Out"


def test_policy_recommended() -> None:
    advisor = OrchestrationPatternAdvisor()
    assert advisor.recommend_policy("sequential_chain") == "cost_optimized"


def test_risks_returned() -> None:
    advisor = OrchestrationPatternAdvisor()
    risks = advisor.get_risks("tool_use_heavy")
    assert "tool_abuse" in risks


def test_fleet_analysis_quorum() -> None:
    advisor = OrchestrationPatternAdvisor()
    out = advisor.analyze_fleet(16, "parallel_fan_out")
    assert out["quorum_ready"] is True
    assert "quorum_sensing" in out["orchesis_features_needed"]


def test_fleet_analysis_byzantine() -> None:
    advisor = OrchestrationPatternAdvisor()
    out = advisor.analyze_fleet(5, "hierarchical")
    assert out["byzantine_safe"] is True
    assert "byzantine_detector" in out["orchesis_features_needed"]


def test_needed_features_compression() -> None:
    advisor = OrchestrationPatternAdvisor()
    out = advisor.analyze_fleet(2, "reflection_loop")
    assert "uci_compression" in out["orchesis_features_needed"]


def test_all_patterns_have_risks() -> None:
    for item in PATTERNS.values():
        assert isinstance(item.get("risks"), list)
        assert len(item["risks"]) >= 1

