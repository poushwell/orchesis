from __future__ import annotations

from orchesis.token_budget_optimizer import TokenBudgetOptimizer


def test_allocate_within_budget() -> None:
    optimizer = TokenBudgetOptimizer()
    components = {"system": 200, "history": 800, "current": 400, "response": 300}
    out = optimizer.allocate(3000, components)
    assert out == components


def test_allocate_over_budget_prioritizes() -> None:
    optimizer = TokenBudgetOptimizer()
    components = {"system": 500, "history": 1000, "current": 400, "response": 300}
    out = optimizer.allocate(900, components)
    assert out["system"] == 500
    assert out["current"] == 400
    assert out["response"] == 0
    assert out["history"] == 0


def test_savings_computed() -> None:
    optimizer = TokenBudgetOptimizer()
    before = {"system": 300, "history": 2000, "current": 500, "response": 500}
    after = {"system": 300, "history": 700, "current": 500, "response": 500}
    out = optimizer.compute_savings(before, after)
    assert out["before_tokens"] == 3300
    assert out["after_tokens"] == 2000
    assert out["saved"] == 1300
    assert out["savings_rate"] > 0.0


def test_model_recommendation() -> None:
    optimizer = TokenBudgetOptimizer()
    out = optimizer.recommend_model(4000)
    assert out["recommended"] == "gpt-4o-mini"
    assert out["fits"] is True


def test_utilization_computed() -> None:
    optimizer = TokenBudgetOptimizer({"total_budget": 1000})
    out = optimizer.get_utilization(250)
    assert out["used"] == 250
    assert out["total"] == 1000
    assert out["utilization"] == 0.25
    assert out["remaining"] == 750


def test_priority_order_respected() -> None:
    optimizer = TokenBudgetOptimizer()
    components = {"history": 700, "response": 300, "current": 250, "system": 200}
    out = optimizer.allocate(600, components)
    assert out["system"] == 200
    assert out["current"] == 250
    assert out["response"] == 150
    assert out["history"] == 0


def test_empty_components_safe() -> None:
    optimizer = TokenBudgetOptimizer()
    out = optimizer.allocate(1000, {})
    assert out == {}


def test_allocation_sums_to_budget() -> None:
    optimizer = TokenBudgetOptimizer()
    components = {"system": 400, "history": 1000, "current": 300, "response": 300}
    out = optimizer.allocate(1200, components)
    assert sum(out.values()) == 1200
