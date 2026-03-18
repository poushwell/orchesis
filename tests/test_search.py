from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app


def _event(
    *,
    event_id: str,
    agent_id: str,
    session_id: str,
    decision: str,
    reason: str,
    hours_ago: int = 1,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": event_id,
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": "web.fetch",
        "params_hash": "abc",
        "cost": 0.1,
        "decision": decision,
        "reasons": [reason] if reason else [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"session_id": session_id, "model": "gpt-4o-mini"},
    }


def _make_client(tmp_path: Path) -> TestClient:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    rows = [
        _event(
            event_id="evt-research",
            agent_id="research_01",
            session_id="sess-123",
            decision="ALLOW",
            reason="",
            hours_ago=1,
        ),
        _event(
            event_id="evt-threat",
            agent_id="ops_02",
            session_id="sess-456",
            decision="DENY",
            reason="prompt_injection: blocked request",
            hours_ago=1,
        ),
    ]
    decisions.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in rows) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    return TestClient(app)


def test_search_endpoint_returns_results(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/search?q=research", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["query"] == "research"
    assert "results" in payload
    assert "agents" in payload["results"]


def test_search_filters_by_query(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/search?q=prompt_injection", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["results"]["agents"] == []
    assert payload["results"]["threats"]


def test_search_empty_query_returns_empty(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/search?q=", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 0
    assert payload["results"]["agents"] == []
    assert payload["results"]["sessions"] == []
    assert payload["results"]["threats"] == []


def test_search_agents_matched(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/search?q=research_01", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    agents = resp.json()["results"]["agents"]
    assert any(item["id"] == "research_01" for item in agents)


def test_search_threats_matched(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/search?q=prompt_injection", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    threats = resp.json()["results"]["threats"]
    assert threats
    assert threats[0]["type"] == "prompt_injection"
