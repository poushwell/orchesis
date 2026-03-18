from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.incident_manager import IncidentManager


def _threat(*, severity: str = "high", threat_type: str = "prompt_injection") -> dict:
    return {
        "severity": severity,
        "type": threat_type,
        "description": f"Detected {threat_type}",
    }


def test_create_incident() -> None:
    mgr = IncidentManager()
    row = mgr.create(_threat(), agent_id="agent-alpha")
    assert row["incident_id"].startswith("inc-")
    assert row["status"] == "open"
    assert row["severity"] == "high"
    assert row["agent_id"] == "agent-alpha"


def test_update_status() -> None:
    mgr = IncidentManager()
    row = mgr.create(_threat(), agent_id="agent-alpha")
    ok = mgr.update_status(row["incident_id"], "investigating", note="triaged")
    assert ok is True
    updated = mgr.get_incident(row["incident_id"])
    assert updated is not None
    assert updated["status"] == "investigating"


def test_add_mitigation() -> None:
    mgr = IncidentManager()
    row = mgr.create(_threat(), agent_id="agent-alpha")
    ok = mgr.add_mitigation(row["incident_id"], "blocked source IP")
    assert ok is True
    updated = mgr.get_incident(row["incident_id"])
    assert updated is not None
    assert "blocked source IP" in updated["mitigations"]


def test_list_filtered_by_severity() -> None:
    mgr = IncidentManager()
    mgr.create(_threat(severity="low"), agent_id="agent-a")
    mgr.create(_threat(severity="critical"), agent_id="agent-b")
    items = mgr.list_incidents(severity="critical")
    assert len(items) == 1
    assert items[0]["severity"] == "critical"


def test_list_filtered_by_status() -> None:
    mgr = IncidentManager()
    one = mgr.create(_threat(), agent_id="agent-a")
    two = mgr.create(_threat(), agent_id="agent-b")
    mgr.update_status(two["incident_id"], "resolved")
    items = mgr.list_incidents(status="resolved")
    assert len(items) == 1
    assert items[0]["incident_id"] == two["incident_id"]
    assert all(item["incident_id"] != one["incident_id"] for item in items)


def test_metrics_computed() -> None:
    mgr = IncidentManager()
    first = mgr.create(_threat(severity="critical"), agent_id="agent-a")
    second = mgr.create(_threat(severity="low"), agent_id="agent-b")
    mgr.update_status(first["incident_id"], "false_positive")
    mgr.update_status(second["incident_id"], "investigating")
    metrics = mgr.get_metrics()
    assert metrics["total"] == 2
    assert metrics["by_severity"]["critical"] == 1
    assert metrics["false_positive_rate"] == 50.0


def test_mttr_calculated() -> None:
    mgr = IncidentManager()
    row = mgr.create(_threat(), agent_id="agent-a")
    incident_id = row["incident_id"]
    started = datetime.now(timezone.utc) - timedelta(hours=4)
    stored = mgr._incidents[incident_id]
    stored["created_at"] = started.isoformat()
    mgr.update_status(incident_id, "resolved")
    resolved = datetime.fromisoformat(stored["resolved_at"])
    stored["resolved_at"] = (resolved + timedelta(hours=2)).isoformat()
    metrics = mgr.get_metrics()
    assert metrics["mttr_hours"] >= 5.9


def test_api_incidents_endpoints(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    created = client.post(
        "/api/v1/incidents",
        json={"agent_id": "agent-api", "threat": _threat(severity="critical", threat_type="jailbreak")},
        headers=headers,
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_id"]

    listed = client.get("/api/v1/incidents", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1

    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["incident_id"] == incident_id

    update = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "investigating", "note": "triage started"},
        headers=headers,
    )
    assert update.status_code == 200

    mitigation = client.post(
        f"/api/v1/incidents/{incident_id}/mitigations",
        json={"action": "disable compromised key"},
        headers=headers,
    )
    assert mitigation.status_code == 200

    metrics = client.get("/api/v1/incidents/metrics", headers=headers)
    assert metrics.status_code == 200
    assert metrics.json()["total"] >= 1
