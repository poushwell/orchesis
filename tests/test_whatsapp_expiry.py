from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.whatsapp_expiry import WhatsAppExpiryTracker


def _days_ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def test_session_registered() -> None:
    tracker = WhatsAppExpiryTracker()
    session = tracker.register_session("wa-1")
    assert session["session_id"] == "wa-1"
    assert session["status"] == "active"


def test_age_computed() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(2.0))
    age = tracker.get_age_days("wa-1")
    assert 1.9 <= age <= 2.1


def test_status_ok_fresh_session() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(1.0))
    result = tracker.check_expiry("wa-1")
    assert result["status"] == "OK"
    assert result["should_alert"] is False


def test_warning_at_12_days() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(12.0))
    result = tracker.check_expiry("wa-1")
    assert result["status"] == "WARNING"
    assert result["severity"] == "HIGH"


def test_critical_at_13_5_days() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(13.5))
    result = tracker.check_expiry("wa-1")
    assert result["status"] == "CRITICAL"
    assert result["severity"] == "CRITICAL"


def test_expired_at_14_days() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(14.0))
    result = tracker.check_expiry("wa-1")
    assert result["status"] == "EXPIRED"
    assert result["should_alert"] is True


def test_days_remaining_computed() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(12.0))
    result = tracker.check_expiry("wa-1")
    assert 1.8 <= result["days_remaining"] <= 2.1


def test_all_sessions_checked() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("fresh", started_at=_days_ago(1.0))
    tracker.register_session("old", started_at=_days_ago(12.0))
    results = tracker.check_all_sessions()
    assert len(results) == 2
    assert {item["session_id"] for item in results} == {"fresh", "old"}


def test_alert_dedup_same_status() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("wa-1", started_at=_days_ago(12.0))
    first = tracker.get_sessions_needing_alert()
    second = tracker.get_sessions_needing_alert()
    assert len(first) == 1
    assert second == []


def test_api_register_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/whatsapp/session",
        json={"session_id": "wa-1", "started_at": _days_ago(1.0)},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "wa-1"


def test_api_at_risk_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    response = client.post(
        "/api/v1/whatsapp/session",
        json={"session_id": "wa-risk", "started_at": _days_ago(13.5)},
        headers=headers,
    )
    assert response.status_code == 200
    response = client.get("/api/v1/whatsapp/sessions/at-risk", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["sessions"][0]["session_id"] == "wa-risk"


def test_stats_returned() -> None:
    tracker = WhatsAppExpiryTracker()
    tracker.register_session("ok", started_at=_days_ago(1.0))
    tracker.register_session("warn", started_at=_days_ago(12.0))
    tracker.register_session("crit", started_at=_days_ago(13.5))
    tracker.register_session("expired", started_at=_days_ago(14.0))
    stats = tracker.get_stats()
    assert stats["total_sessions"] == 4
    assert stats["healthy"] == 1
    assert stats["warning"] == 1
    assert stats["critical"] == 1
    assert stats["expired"] == 1
