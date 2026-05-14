from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.state_balancer import StateBalancer


def test_in_band_no_intervention() -> None:
    controller = StateBalancer()
    out = controller.measure(0.75)
    assert out["in_band"] is True
    assert out["intervention_needed"] is False
    assert out["response"]["action"] == "maintain"


def test_high_cqs_reduce_injection() -> None:
    controller = StateBalancer()
    out = controller.measure(0.95)
    assert out["response"]["action"] == "reduce_injection"


def test_low_cqs_increase_injection() -> None:
    controller = StateBalancer()
    out = controller.measure(0.45)
    assert out["response"]["action"] == "increase_injection"


def test_negative_feedback_direction() -> None:
    controller = StateBalancer()
    high = controller.measure(0.9)
    low = controller.measure(0.5)
    assert high["response"]["direction"] == "reduce"
    assert low["response"]["direction"] == "increase"


def test_correction_proportional() -> None:
    controller = StateBalancer({"gain": 0.3})
    a = controller.measure(0.8)["response"]["correction"]
    b = controller.measure(0.9)["response"]["correction"]
    assert abs(b) > abs(a)


def test_equilibrium_stats() -> None:
    controller = StateBalancer()
    controller.measure(0.75)
    controller.measure(0.85)
    stats = controller.get_equilibrium_stats()
    assert stats["measurements"] == 2
    assert "avg_quality" in stats


def test_in_band_rate_tracked() -> None:
    controller = StateBalancer()
    controller.measure(0.75)
    controller.measure(0.76)
    controller.measure(0.30)
    stats = controller.get_equilibrium_stats()
    assert stats["in_band_rate"] == 0.6667


def test_api_measure_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl")
    )
    client = TestClient(app)
    response = client.post(
        "/api/v1/state_balancer/measure",
        json={"quality_score": 0.9},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["response"]["action"] == "reduce_injection"
