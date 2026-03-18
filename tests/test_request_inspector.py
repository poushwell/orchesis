from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.request_inspector import PHASE_ORDER, RequestInspector


def _event(
    *,
    event_id: str,
    decision: str = "ALLOW",
    evaluation_order: list[str] | None = None,
    reasons: list[str] | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-x",
        "tool": "web_search",
        "params_hash": "abc123",
        "cost": 0.12,
        "decision": decision,
        "reasons": reasons or [],
        "rules_checked": ["rule-a"],
        "rules_triggered": ["rule-a"] if decision == "DENY" else [],
        "evaluation_order": evaluation_order if evaluation_order is not None else list(PHASE_ORDER),
        "evaluation_duration_us": 1700,
        "policy_version": "v1",
        "state_snapshot": {"session_id": "sess-1"},
    }


def test_inspect_returns_all_phases() -> None:
    inspector = RequestInspector()
    inspection = inspector.inspect("req-1", [_event(event_id="req-1")])
    assert inspection["request_id"] == "req-1"
    assert len(inspection["phases"]) == 17
    assert inspection["phases"][0]["phase_number"] == 1


def test_blocking_phase_identified() -> None:
    inspector = RequestInspector()
    inspection = inspector.inspect(
        "req-2",
        [_event(event_id="req-2", decision="DENY", evaluation_order=["parse", "policy"], reasons=["policy:block"])],
    )
    blocked = inspector.find_blocking_phase(inspection)
    assert blocked is not None
    assert blocked["phase_name"] == "policy"
    assert blocked["result"] == "block"


def test_timeline_generated() -> None:
    inspector = RequestInspector()
    inspection = inspector.inspect("req-3", [_event(event_id="req-3", evaluation_order=["parse", "policy", "send"])])
    timeline = inspector.get_timeline(inspection)
    assert len(timeline) == 17
    assert timeline[0]["start_us"] == 0
    assert timeline[-1]["end_us"] >= timeline[-1]["start_us"]


def test_api_inspect_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    decisions.write_text(json.dumps(_event(event_id="req-api"), ensure_ascii=False) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.get("/api/v1/requests/req-api/inspect", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "req-api"
    assert len(payload["phases"]) == 17


def test_api_recent_requests(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    rows = [json.dumps(_event(event_id="req-a"), ensure_ascii=False), json.dumps(_event(event_id="req-b"), ensure_ascii=False)]
    decisions.write_text("\n".join(rows) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.get("/api/v1/requests/recent?limit=20", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] >= 2
    assert isinstance(payload["requests"], list)
    assert payload["requests"][0]["request_id"] in {"req-a", "req-b"}
