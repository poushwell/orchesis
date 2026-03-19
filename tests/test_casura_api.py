from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.casura.incident_db import CASURAIncidentDB
from orchesis.casura.intelligence import IncidentIntelligence


def _app_with_casura(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.casura_db = CASURAIncidentDB(storage_path=str(tmp_path / "casura-db"))
    app.state.casura_intel = IncidentIntelligence()
    return app


def _create_incident(client: TestClient, title: str = "Prompt injection incident") -> dict:
    response = client.post(
        "/api/v1/casura/incidents",
        json={
            "title": title,
            "description": "Detected prompt injection attempt against MCP server",
            "tags": ["prompt", "injection"],
            "factors": {"attack_vector": 0.9, "impact": 0.8, "exploitability": 0.7},
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    return response.json()


def test_create_incident_via_api(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    payload = _create_incident(client)
    assert payload["incident_id"].startswith("CASURA-")
    assert "aiss_score" in payload


def test_list_incidents_via_api(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    _create_incident(client)
    res = client.get("/api/v1/casura/incidents", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert isinstance(body["incidents"], list)


def test_get_incident_by_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    created = _create_incident(client)
    incident_id = created["incident_id"]
    res = client.get(f"/api/v1/casura/incidents/{incident_id}", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    assert res.json()["incident_id"] == incident_id


def test_search_incidents(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    _create_incident(client, title="Credential leakage")
    res = client.post(
        "/api/v1/casura/incidents/search",
        json={"query": "credential"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert res.status_code == 200
    assert res.json()["total"] >= 1


def test_incident_stats_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    _create_incident(client)
    res = client.get("/api/v1/casura/incidents/stats", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["total_incidents"] >= 1
    assert "by_severity" in payload


def test_intelligence_patterns_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    _create_incident(client)
    res = client.get("/api/v1/casura/intelligence/patterns", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    payload = res.json()
    assert "top_attack_vectors" in payload
    assert "framework_heatmap" in payload


def test_mitre_coverage_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_casura(tmp_path))
    _create_incident(client)
    res = client.get("/api/v1/casura/intelligence/mitre-coverage", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    payload = res.json()
    assert "total_mitre_mappings" in payload
    assert "coverage" in payload
