from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.context_timeline import ContextTimeline


def test_snapshot_recorded() -> None:
    timeline = ContextTimeline()
    timeline.record("s1", {"phase": "LIQUID", "psi": 0.5})
    points = timeline.get_timeline("s1")
    assert len(points) == 1
    assert points[0]["seq"] == 0


def test_timeline_retrieved() -> None:
    timeline = ContextTimeline()
    timeline.record("s1", {"phase": "LIQUID"})
    timeline.record("s1", {"phase": "SOLID"})
    points = timeline.get_timeline("s1")
    assert len(points) == 2


def test_phase_transitions_detected() -> None:
    timeline = ContextTimeline()
    timeline.record("s1", {"phase": "LIQUID", "psi": 0.4})
    timeline.record("s1", {"phase": "LIQUID", "psi": 0.5})
    timeline.record("s1", {"phase": "SOLID", "psi": 0.6})
    transitions = timeline.get_phase_transitions("s1")
    assert len(transitions) == 2
    assert transitions[0]["to"] == "LIQUID"
    assert transitions[1]["to"] == "SOLID"


def test_collapse_events_found() -> None:
    timeline = ContextTimeline()
    timeline.record("s1", {"phase": "LIQUID", "slope_alert": True})
    timeline.record("s1", {"phase": "SOLID", "context_collapse": True})
    events = timeline.get_collapse_events("s1")
    assert len(events) == 2


def test_summary_computed() -> None:
    timeline = ContextTimeline()
    timeline.record("s1", {"phase": "LIQUID", "psi": 0.4})
    timeline.record("s1", {"phase": "SOLID", "psi": 0.6, "context_collapse": True})
    summary = timeline.summarize("s1")
    assert summary["points"] == 2
    assert summary["collapse_events"] == 1
    assert "avg_psi" in summary


def test_bounded_at_1000() -> None:
    timeline = ContextTimeline()
    for idx in range(1200):
        timeline.record("s1", {"phase": "LIQUID", "psi": 0.5, "i": idx})
    points = timeline.get_timeline("s1")
    assert len(points) == 1000
    assert points[0]["seq"] == 200


def test_api_record_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/timeline/sess-1/record",
        json={"phase": "LIQUID", "psi": 0.45},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "sess-1"
    assert payload["points"] == 1


def test_api_summary_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    _ = client.post(
        "/api/v1/timeline/sess-2/record",
        json={"phase": "LIQUID", "psi": 0.4},
        headers=headers,
    )
    _ = client.post(
        "/api/v1/timeline/sess-2/record",
        json={"phase": "SOLID", "psi": 0.6, "context_collapse": True},
        headers=headers,
    )
    response = client.get("/api/v1/timeline/sess-2/summary", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "sess-2"
    assert payload["points"] == 2
    assert payload["collapse_events"] == 1
