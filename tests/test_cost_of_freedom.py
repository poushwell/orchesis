from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cost_of_freedom import CostOfFreedomCalculator


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_calculation_returns_all_fields() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    for key in (
        "daily_requests",
        "daily_tokens",
        "wasted_tokens_daily",
        "wasted_cost_daily",
        "retry_savings_daily",
        "total_daily_savings",
        "total_monthly_savings",
        "attacks_missed_daily",
        "overhead_cost_daily",
        "roi",
    ):
        assert key in row


def test_monthly_savings_is_30x_daily() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    assert row["total_monthly_savings"] == round(row["total_daily_savings"] * 30, 2)


def test_roi_positive() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    assert row["roi"] > 0


def test_overhead_minimal() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    assert row["overhead_cost_daily"] < row["wasted_cost_daily"]


def test_wasted_tokens_22pct() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    ratio = row["wasted_tokens_daily"] / row["daily_tokens"]
    assert 0.22 < ratio < 0.23


def test_summary_text_generated() -> None:
    calc = CostOfFreedomCalculator()
    row = calc.calculate({})
    text = calc.get_summary_text(row)
    assert "Without Orchesis you waste $" in text
    assert "ROI:" in text


def test_api_calculate_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/v1/cost-of-freedom/calculate",
        headers={"Authorization": "Bearer test-token"},
        json={"daily_requests": 1500, "avg_tokens_per_request": 2500, "cost_per_ktok": 0.01},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "total_daily_savings" in payload
    assert "summary" in payload


def test_benchmarks_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get(
        "/api/v1/cost-of-freedom/benchmarks",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "benchmarks" in payload
    assert "redundancy_rate" in payload["benchmarks"]
