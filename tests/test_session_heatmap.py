from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.session_heatmap import SessionHeatmap


def _event(*, hours_ago: int, cost: float, decision: str = "ALLOW") -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": f"evt-{hours_ago}-{decision}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-a",
        "tool": "shell.exec",
        "params_hash": "abc",
        "cost": float(cost),
        "decision": decision,
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"session_id": "s1", "model": "gpt-4o-mini"},
    }


def test_heatmap_cells_generated() -> None:
    events = [_event(hours_ago=i, cost=0.1) for i in range(12)]
    payload = SessionHeatmap().compute(events, days=7)
    assert payload["days"] == 7
    assert len(payload["cells"]) == 7 * 24


def test_intensity_normalized() -> None:
    events = []
    events.extend(_event(hours_ago=1, cost=0.2) for _ in range(4))
    events.extend(_event(hours_ago=2, cost=0.2) for _ in range(2))
    payload = SessionHeatmap().compute(events, days=7)
    intensities = [float(cell["intensity"]) for cell in payload["cells"]]
    assert all(0.0 <= value <= 1.0 for value in intensities)
    assert max(intensities) == 1.0


def test_peak_identified() -> None:
    events = []
    events.extend(_event(hours_ago=1, cost=0.1) for _ in range(6))
    events.extend(_event(hours_ago=20, cost=0.1) for _ in range(2))
    payload = SessionHeatmap().compute(events, days=7)
    peak = payload["peak"]
    assert int(peak["count"]) == 6
    assert 0 <= int(peak["hour"]) <= 23


def test_daily_summary_length() -> None:
    events = [_event(hours_ago=i, cost=0.1, decision="DENY" if i % 3 == 0 else "ALLOW") for i in range(60)]
    summary = SessionHeatmap().get_daily_summary(events)
    assert len(summary) == 7
    assert all("count" in row and "cost" in row and "blocked" in row for row in summary)


def test_api_heatmap_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    events = [
        _event(hours_ago=1, cost=0.2, decision="ALLOW"),
        _event(hours_ago=2, cost=0.4, decision="DENY"),
        _event(hours_ago=25, cost=0.3, decision="ALLOW"),
    ]
    decisions_log.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)

    response = client.get("/api/v1/heatmap?days=7", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["days"] == 7
    assert isinstance(payload["cells"], list)
    assert "peak" in payload and "quiet" in payload

    daily = client.get("/api/v1/heatmap/daily", headers={"Authorization": "Bearer test-token"})
    assert daily.status_code == 200
    body = daily.json()
    assert body["days"] == 7
    assert isinstance(body["summary"], list)
