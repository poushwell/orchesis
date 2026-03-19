from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.criticality_control import CriticalityController


def test_lqr_control_crystal_phase() -> None:
    controller = CriticalityController()
    out = controller.compute_control(0.85)
    assert out["action"] == "thaw"
    assert out["error"] < 0.0


def test_lqr_control_gas_phase() -> None:
    controller = CriticalityController()
    out = controller.compute_control(0.2)
    assert out["action"] == "crystallize"
    assert out["error"] > 0.0


def test_lqr_control_optimal_range() -> None:
    controller = CriticalityController()
    out = controller.compute_control(0.5)
    assert out["in_optimal_range"] is True
    assert out["action"] == "maintain"


def test_action_thaw_for_crystal() -> None:
    controller = CriticalityController()
    assert controller._select_action(0.9, -0.1) == "thaw"


def test_action_crystallize_for_gas() -> None:
    controller = CriticalityController()
    assert controller._select_action(0.1, 0.2) == "crystallize"


def test_mrac_updates_gain() -> None:
    controller = CriticalityController({"adaptive_gain": 0.1})
    updated = controller.mrac_update(psi_actual=0.7, psi_predicted=0.5)
    assert updated > 0.1


def test_stats_tracked() -> None:
    controller = CriticalityController()
    controller.compute_control(0.45)
    controller.compute_control(0.55)
    stats = controller.get_stats()
    assert stats["observations"] == 2
    assert "in_optimal_range_rate" in stats


def test_api_control_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/criticality/control",
        json={"psi": 0.85},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "thaw"

