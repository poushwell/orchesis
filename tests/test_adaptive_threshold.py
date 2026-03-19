from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.adaptive_threshold import AdaptiveThresholdManager
from orchesis.api import create_api_app


def test_default_threshold_returned() -> None:
    manager = AdaptiveThresholdManager()
    assert manager.get_threshold("det-a") == 0.5


def test_feedback_recorded() -> None:
    manager = AdaptiveThresholdManager()
    manager.record_feedback("det-a", predicted=True, actual=False)
    assert len(manager._feedback["det-a"]) == 1


def test_threshold_increases_on_high_fpr() -> None:
    manager = AdaptiveThresholdManager({"alpha": 0.1, "fpr_target": 0.05})
    for _ in range(12):
        manager.record_feedback("det-a", predicted=True, actual=False)  # FP
    result = manager.adapt("det-a")
    assert result["adapted"] is True
    assert result["new_threshold"] > result["old_threshold"]


def test_threshold_decreases_on_high_fnr() -> None:
    manager = AdaptiveThresholdManager({"alpha": 0.1, "fpr_target": 0.05})
    for _ in range(12):
        manager.record_feedback("det-a", predicted=False, actual=True)  # FN
    result = manager.adapt("det-a")
    assert result["adapted"] is True
    assert result["new_threshold"] < result["old_threshold"]


def test_insufficient_data_no_adapt() -> None:
    manager = AdaptiveThresholdManager()
    for _ in range(5):
        manager.record_feedback("det-a", predicted=True, actual=True)
    result = manager.adapt("det-a")
    assert result["adapted"] is False
    assert result["reason"] == "insufficient_data"


def test_threshold_bounded_0_to_1() -> None:
    manager = AdaptiveThresholdManager({"alpha": 0.5, "fpr_target": 0.0})
    for _ in range(50):
        manager.record_feedback("det-a", predicted=True, actual=False)
    for _ in range(10):
        manager.adapt("det-a")
    value = manager.get_threshold("det-a")
    assert 0.0 <= value <= 1.0


def test_stats_returned() -> None:
    manager = AdaptiveThresholdManager()
    for _ in range(12):
        manager.record_feedback("det-a", predicted=True, actual=False)
    manager.adapt("det-a")
    stats = manager.get_stats()
    assert stats["detectors"] >= 1
    assert "det-a" in stats["thresholds"]


def test_api_adapt_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    for _ in range(12):
        fb = client.post(
            "/api/v1/threshold/feedback",
            json={"detector": "det-a", "predicted": True, "actual": False},
            headers=headers,
        )
        assert fb.status_code == 200

    response = client.post("/api/v1/threshold/adapt/det-a", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["detector"] == "det-a"
    assert "new_threshold" in payload

