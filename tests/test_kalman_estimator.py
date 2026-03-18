from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.kalman_estimator import KalmanStateEstimator


def test_state_initialized() -> None:
    estimator = KalmanStateEstimator()
    state = estimator.initialize("sess-1")
    assert state["cognitive_load"] == 0.5
    assert state["context_quality"] == 1.0
    assert state["coherence"] == 1.0
    assert state["uncertainty"] == 1.0


def test_predict_increases_uncertainty() -> None:
    estimator = KalmanStateEstimator({"process_noise": 0.2})
    estimator.initialize("sess-1")
    before = estimator.get_state("sess-1")["uncertainty"]
    after = estimator.predict("sess-1")["uncertainty"]
    assert after > before


def test_update_with_observation() -> None:
    estimator = KalmanStateEstimator({"observation_noise": 0.2})
    estimator.initialize("sess-1")
    estimator.predict("sess-1")
    before = estimator.get_state("sess-1")
    after = estimator.update(
        "sess-1",
        {"tokens_used": 7200, "response_quality": 0.35, "latency_ms": 2200},
    )
    assert after["cognitive_load"] > before["cognitive_load"]
    assert after["context_quality"] < before["context_quality"]
    assert after["uncertainty"] < before["uncertainty"]


def test_alert_level_green_normal() -> None:
    estimator = KalmanStateEstimator()
    estimator.initialize("sess-green")
    alert = estimator.get_alert_level("sess-green")
    assert alert == "green"


def test_alert_level_red_overloaded() -> None:
    estimator = KalmanStateEstimator()
    estimator.initialize("sess-red")
    estimator.predict("sess-red")
    estimator.update(
        "sess-red",
        {"tokens_used": 16000, "response_quality": 0.1, "latency_ms": 5000},
    )
    alert = estimator.get_alert_level("sess-red")
    assert alert == "red"


def test_multiple_sessions_independent() -> None:
    estimator = KalmanStateEstimator()
    estimator.initialize("a")
    estimator.initialize("b")
    estimator.predict("a")
    estimator.update("a", {"tokens_used": 12000, "response_quality": 0.3, "latency_ms": 4000})
    estimator.predict("b")
    estimator.update("b", {"tokens_used": 1000, "response_quality": 0.95, "latency_ms": 120})
    a_state = estimator.get_state("a")
    b_state = estimator.get_state("b")
    assert a_state["cognitive_load"] != b_state["cognitive_load"]
    assert a_state["context_quality"] != b_state["context_quality"]


def test_api_update_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/kalman/sess-api/update",
        json={"tokens_used": 4000, "response_quality": 0.8, "latency_ms": 500},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "sess-api"
    assert "state" in payload
    assert payload["alert"] in {"green", "yellow", "orange", "red"}


def test_api_state_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    _ = client.post(
        "/api/v1/kalman/sess-2/update",
        json={"tokens_used": 1800, "response_quality": 0.9, "latency_ms": 220},
        headers=headers,
    )
    response = client.get("/api/v1/kalman/sess-2/state", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "sess-2"
    assert payload["state"]["uncertainty"] >= 0.0
