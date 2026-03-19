from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.policy_impact_analyzer import PolicyImpactAnalyzer


def _sample_requests() -> list[dict]:
    return [{"id": f"r{i}", "cost": float(i)} for i in range(10)]


def test_simulation_returns_result() -> None:
    analyzer = PolicyImpactAnalyzer()
    out = analyzer.simulate({"budgets": {"daily": 5}}, {"budgets": {"daily": 3}}, _sample_requests())
    assert "changes_detected" in out
    assert "impacted_requests" in out


def test_changes_detected() -> None:
    analyzer = PolicyImpactAnalyzer()
    out = analyzer.simulate({"budgets": {"daily": 5}}, {"budgets": {"daily": 4}}, _sample_requests())
    assert any("budgets" in row for row in out["changes_detected"])


def test_impact_rate_computed() -> None:
    analyzer = PolicyImpactAnalyzer()
    out = analyzer.simulate({"budgets": {"daily": 5}}, {"budgets": {"daily": 2}}, _sample_requests())
    assert 0.0 <= out["impact_rate"] <= 1.0


def test_safe_to_apply_flag() -> None:
    analyzer = PolicyImpactAnalyzer()
    safe = analyzer.simulate({"budgets": {"daily": 5}}, {"budgets": {"daily": 4.9}}, _sample_requests())
    unsafe = analyzer.simulate({"budgets": {"daily": 9}}, {"budgets": {"daily": 1}}, _sample_requests())
    assert safe["safe_to_apply"] is True
    assert unsafe["safe_to_apply"] is False


def test_new_blocks_counted() -> None:
    analyzer = PolicyImpactAnalyzer()
    out = analyzer.simulate({"budgets": {"daily": 9}}, {"budgets": {"daily": 2}}, _sample_requests())
    assert out["new_blocks"] > 0


def test_new_allows_counted() -> None:
    analyzer = PolicyImpactAnalyzer()
    out = analyzer.simulate({"budgets": {"daily": 2}}, {"budgets": {"daily": 9}}, _sample_requests())
    assert out["new_allows"] > 0


def test_api_simulate_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/policy/simulate-impact",
        json={
            "current_policy": {"budgets": {"daily": 5}},
            "new_policy": {"budgets": {"daily": 3}},
            "sample_requests": _sample_requests(),
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "impacted_requests" in payload


def test_stats_tracked() -> None:
    analyzer = PolicyImpactAnalyzer()
    analyzer.simulate({"budgets": {"daily": 5}}, {"budgets": {"daily": 3}}, _sample_requests())
    stats = analyzer.get_stats()
    assert stats["simulations"] == 1

