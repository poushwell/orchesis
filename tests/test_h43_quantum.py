from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.h43_quantum import H43QuantumMVE


def test_trial_recorded() -> None:
    model = H43QuantumMVE()
    trial = model.record_trial("security_first", 0.8, 0.6)
    assert trial["order"] == "security_first"
    assert trial["delta"] == 0.2


def test_delta_bar_computed() -> None:
    model = H43QuantumMVE()
    _ = model.record_trial("security_first", 0.8, 0.7)  # 0.1
    _ = model.record_trial("task_first", 0.9, 0.4)  # 0.5
    result = model.compute_delta_bar()
    assert "delta_bar" in result
    assert result["n_total"] == 2


def test_rejected_below_0_05() -> None:
    model = H43QuantumMVE()
    _ = model.record_trial("security_first", 0.60, 0.55)  # 0.05
    _ = model.record_trial("security_first", 0.61, 0.56)  # 0.05
    _ = model.record_trial("task_first", 0.62, 0.58)  # 0.04
    _ = model.record_trial("task_first", 0.63, 0.59)  # 0.04
    result = model.compute_delta_bar()
    assert result["delta_bar"] < 0.05
    assert result["status"] == "REJECTED"


def test_confirmed_above_0_10() -> None:
    model = H43QuantumMVE()
    _ = model.record_trial("security_first", 0.95, 0.75)  # 0.20
    _ = model.record_trial("security_first", 0.90, 0.70)  # 0.20 -> mean 0.20
    _ = model.record_trial("task_first", 0.55, 0.52)  # 0.03
    _ = model.record_trial("task_first", 0.54, 0.51)  # 0.03 -> mean 0.03
    result = model.compute_delta_bar()
    assert result["delta_bar"] > 0.10
    assert result["status"] == "CONFIRMED"


def test_inconclusive_between() -> None:
    model = H43QuantumMVE()
    _ = model.record_trial("security_first", 0.80, 0.71)  # 0.09
    _ = model.record_trial("task_first", 0.80, 0.78)  # 0.02
    result = model.compute_delta_bar()
    assert 0.05 <= result["delta_bar"] <= 0.10
    assert result["status"] == "INCONCLUSIVE"


def test_insufficient_data_safe() -> None:
    model = H43QuantumMVE()
    result = model.compute_delta_bar()
    assert result["status"] == "insufficient_data"
    assert result["delta_bar"] == 0.0


def test_order_types_tracked() -> None:
    model = H43QuantumMVE()
    _ = model.record_trial("security_first", 0.7, 0.6)
    _ = model.record_trial("task_first", 0.7, 0.5)
    result = model.compute_delta_bar()
    assert result["n_security_first"] == 1
    assert result["n_task_first"] == 1


def _client(tmp_path: Path) -> TestClient:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_api_trial_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/h43/trial",
        headers={"Authorization": "Bearer test-token"},
        json={"order": "security_first", "security_score": 0.83, "task_score": 0.62},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["trial"]["order"] == "security_first"


def test_api_results_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _ = client.post(
        "/api/v1/h43/trial",
        headers={"Authorization": "Bearer test-token"},
        json={"order": "security_first", "security_score": 0.8, "task_score": 0.6},
    )
    _ = client.post(
        "/api/v1/h43/trial",
        headers={"Authorization": "Bearer test-token"},
        json={"order": "task_first", "security_score": 0.8, "task_score": 0.7},
    )
    response = client.get("/api/v1/h43/results", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert "delta_bar" in payload
    assert payload["n_total"] == 2
