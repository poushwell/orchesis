from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.agent_compare import AgentComparer
from orchesis.api import create_api_app


def test_metric_recorded() -> None:
    comparer = AgentComparer()
    comparer.record_metric("agent-a", "token_yield", 0.7)
    stats = comparer.get_stats()
    assert stats["agents_tracked"] == 1


def test_compare_returns_winner() -> None:
    comparer = AgentComparer()
    comparer.record_metric("a", "token_yield", 0.8)
    comparer.record_metric("b", "token_yield", 0.2)
    result = comparer.compare("a", "b")
    assert result["metrics"]["token_yield"]["winner"] == "a"


def test_all_metrics_compared() -> None:
    comparer = AgentComparer()
    result = comparer.compare("a", "b")
    assert set(result["metrics"].keys()) == set(AgentComparer.METRICS)


def test_overall_winner_determined() -> None:
    comparer = AgentComparer()
    for metric in AgentComparer.METRICS:
        comparer.record_metric("a", metric, 0.9)
        comparer.record_metric("b", metric, 0.4)
    result = comparer.compare("a", "b")
    assert result["overall_winner"] == "a"
    assert result["metrics_won_a"] >= result["metrics_won_b"]


def test_rank_all_returns_sorted() -> None:
    comparer = AgentComparer()
    comparer.record_metric("a", "token_yield", 0.9)
    comparer.record_metric("b", "token_yield", 0.1)
    ranking = comparer.rank_all()
    assert len(ranking) == 2
    assert ranking[0]["score"] >= ranking[1]["score"]


def test_empty_profile_safe() -> None:
    comparer = AgentComparer()
    result = comparer.compare("left", "right")
    assert result["agent_a"] == "left"
    assert result["agent_b"] == "right"
    assert set(result["metrics"].keys()) == set(AgentComparer.METRICS)


def test_api_compare_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    for metric in AgentComparer.METRICS:
        _ = client.post(
            "/api/v1/compare/metric",
            json={"agent_id": "a", "metric": metric, "value": 0.8},
            headers=headers,
        )
        _ = client.post(
            "/api/v1/compare/metric",
            json={"agent_id": "b", "metric": metric, "value": 0.3},
            headers=headers,
        )
    response = client.get("/api/v1/compare/a/b", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["overall_winner"] == "a"


def test_api_ranking_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    _ = client.post(
        "/api/v1/compare/metric",
        json={"agent_id": "x", "metric": "token_yield", "value": 0.6},
        headers=headers,
    )
    response = client.get("/api/v1/compare/ranking", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert "ranking" in payload
    assert payload["total"] >= 1
