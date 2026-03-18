from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.session_groups import SessionGroupManager


def _event(*, session_id: str, cost: float, decision: str = "ALLOW", reasons: list[str] | None = None) -> dict:
    return {
        "event_id": f"evt-{session_id}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-a",
        "tool": "shell.exec",
        "params_hash": "abc",
        "cost": float(cost),
        "decision": decision,
        "reasons": list(reasons or []),
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"session_id": session_id, "model": "gpt-4o-mini"},
    }


def test_create_group(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    group = manager.create_group("Deploy flow", "workflow")
    assert group["name"] == "Deploy flow"
    assert isinstance(group["group_id"], str) and group["group_id"]


def test_add_session_to_group(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    group = manager.create_group("Ops")
    ok = manager.add_session(group["group_id"], "session-1")
    assert ok is True
    rows = manager.list_groups()
    assert "session-1" in rows[0]["sessions"]


def test_remove_session_from_group(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    group = manager.create_group("Ops")
    manager.add_session(group["group_id"], "session-1")
    ok = manager.remove_session(group["group_id"], "session-1")
    assert ok is True
    rows = manager.list_groups()
    assert "session-1" not in rows[0]["sessions"]


def test_group_stats_aggregated(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    group = manager.create_group("Flow")
    manager.add_session(group["group_id"], "s-1")
    manager.add_session(group["group_id"], "s-2")
    events = [
        _event(session_id="s-1", cost=0.2, decision="ALLOW"),
        _event(session_id="s-2", cost=0.5, decision="DENY", reasons=["threat"]),
        _event(session_id="s-x", cost=1.0, decision="ALLOW"),
    ]
    stats = manager.get_group_stats(group["group_id"], events)
    assert stats["total_requests"] == 2
    assert stats["total_cost"] == 0.7
    assert stats["threats"] == 1


def test_list_groups(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    manager.create_group("A")
    manager.create_group("B")
    rows = manager.list_groups()
    assert len(rows) == 2


def test_delete_group(tmp_path: Path) -> None:
    manager = SessionGroupManager(str(tmp_path / "groups.json"))
    group = manager.create_group("A")
    ok = manager.delete_group(group["group_id"])
    assert ok is True
    assert manager.list_groups() == []


def test_api_endpoints(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    events = [
        _event(session_id="s-1", cost=0.2),
        _event(session_id="s-2", cost=0.4, decision="DENY", reasons=["threat"]),
    ]
    decisions_log.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    created = client.post("/api/v1/session-groups", json={"name": "Workflow A", "description": "test"}, headers=headers)
    assert created.status_code == 200
    group = created.json()
    group_id = group["group_id"]

    add_one = client.post(f"/api/v1/session-groups/{group_id}/sessions", json={"session_id": "s-1"}, headers=headers)
    assert add_one.status_code == 200
    add_two = client.post(f"/api/v1/session-groups/{group_id}/sessions", json={"session_id": "s-2"}, headers=headers)
    assert add_two.status_code == 200

    listed = client.get("/api/v1/session-groups", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()["groups"]) >= 1

    fetched = client.get(f"/api/v1/session-groups/{group_id}", headers=headers)
    assert fetched.status_code == 200
    payload = fetched.json()
    assert payload["total_requests"] == 2
    assert payload["total_cost"] == 0.6

    removed = client.delete(f"/api/v1/session-groups/{group_id}/sessions/s-2", headers=headers)
    assert removed.status_code == 200

    deleted = client.delete(f"/api/v1/session-groups/{group_id}", headers=headers)
    assert deleted.status_code == 200
