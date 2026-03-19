from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_nlce_metrics_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/v1/nlce/metrics", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"] == "NLCE v2.0"


def test_confirmed_results_present(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = client.get("/api/v1/nlce/metrics", headers={"Authorization": "Bearer test-token"}).json()
    confirmed = payload["confirmed_results"]
    assert "zipf_alpha" in confirmed
    assert "zipf_r2" in confirmed
    assert "n_star" in confirmed
    assert "proxy_overhead" in confirmed
    assert "context_collapse_factor" in confirmed
    assert "retry_reduction" in confirmed


def test_impossibility_theorems_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get(
        "/api/v1/nlce/impossibility-theorems",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload.get("theorems"), list)


def test_all_five_theorems_listed(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = client.get(
        "/api/v1/nlce/impossibility-theorems",
        headers={"Authorization": "Bearer test-token"},
    ).json()
    theorem_ids = {item.get("id") for item in payload["theorems"]}
    assert len(payload["theorems"]) == 5
    assert theorem_ids == {"T1", "T2", "T3", "T4", "T5"}


def test_zipf_alpha_correct(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = client.get("/api/v1/nlce/metrics", headers={"Authorization": "Bearer test-token"}).json()
    assert payload["confirmed_results"]["zipf_alpha"] == 1.672


def test_n_star_correct(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = client.get("/api/v1/nlce/metrics", headers={"Authorization": "Bearer test-token"}).json()
    assert payload["confirmed_results"]["n_star"] == 16


def test_pipeline_state_included(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    payload = client.get("/api/v1/nlce/metrics", headers={"Authorization": "Bearer test-token"}).json()
    state = payload["pipeline_state"]
    assert state["phases"] == 17
    assert isinstance(state["active_modules"], list)
    assert isinstance(state["crystallinity_psi"], float)
    assert isinstance(state["current_phase"], str)
