from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.monitoring.parsers import SocialMonitoringParsers


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_parse_hn_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.request(
        "GET",
        "/api/v1/monitoring/parse-hn",
        headers={"Authorization": "Bearer test-token"},
        json={"item": {"id": 123, "title": "How to secure AI agent prompts?", "score": 42}},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "parsed" in payload
    assert payload["parsed"]["id"] == "123"
    assert "relevance_score" in payload["parsed"]


def test_score_relevance_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/v1/monitoring/score-relevance",
        headers={"Authorization": "Bearer test-token"},
        json={"text": "LLM proxy security and prompt injection mitigation"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["relevance_score"] > 0.0


def test_opportunities_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    _ = client.request(
        "GET",
        "/api/v1/monitoring/parse-hn",
        headers={"Authorization": "Bearer test-token"},
        json={
            "item": {
                "id": "q1",
                "title": "AI agent security: LLM proxy prompt injection and EU AI Act MCP server guidance",
            }
        },
    )
    response = client.get(
        "/api/v1/monitoring/opportunities",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "opportunities" in payload
    assert payload["count"] >= 1


def test_weekly_report_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get(
        "/api/v1/monitoring/weekly-report",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "week" in payload
    assert "highlights" in payload
    assert "actions" in payload


def test_competitive_monitor_initialized(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    assert hasattr(app.state, "competitive_monitor")


def test_social_parsers_initialized(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    assert hasattr(app.state, "social_parsers")
    assert isinstance(app.state.social_parsers, SocialMonitoringParsers)
