from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.webchat_inject import WebChatInjector


def test_alert_queued() -> None:
    injector = WebChatInjector()
    alert = injector.queue_alert("s1", "security", "Prompt injection detected in this session")
    assert alert["session_id"] == "s1"
    assert alert["type"] == "security"
    assert alert["injected"] is False


def test_pending_alerts_returned() -> None:
    injector = WebChatInjector()
    injector.queue_alert("s1", "budget", "You've used 80% of daily budget")
    pending = injector.get_pending("s1")
    assert len(pending) == 1
    assert pending[0]["injected"] is True


def test_pending_cleared_after_get() -> None:
    injector = WebChatInjector()
    injector.queue_alert("s1", "context", "Context quality degraded")
    _ = injector.get_pending("s1")
    assert injector.get_pending("s1") == []


def test_inject_prepends_to_response() -> None:
    injector = WebChatInjector()
    injector.queue_alert("s1", "security", "Prompt injection detected")
    response = {"content": "LLM answer here"}
    out = injector.inject_into_response("s1", response)
    assert out["content"].startswith("⚠️ Security Alert: Prompt injection detected")
    assert out["_alerts_injected"] == 1


def test_no_alerts_response_unchanged() -> None:
    injector = WebChatInjector()
    response = {"content": "No alerts"}
    out = injector.inject_into_response("s1", response)
    assert out["content"] == "No alerts"
    assert "_alerts_injected" not in out


def test_all_alert_types_formatted() -> None:
    injector = WebChatInjector()
    for alert_type in ("security", "budget", "context", "expiry", "zenity"):
        alert = injector.queue_alert("s1", alert_type, "hello")
        assert "hello" in alert["message"]


def test_zenity_critical_format() -> None:
    injector = WebChatInjector()
    alert = injector.queue_alert("s1", "zenity", "Immediate action required")
    assert alert["message"].startswith("🔴 CRITICAL: ")


def test_stats_tracked() -> None:
    injector = WebChatInjector()
    injector.queue_alert("s1", "security", "a")
    injector.queue_alert("s2", "budget", "b")
    before = injector.get_stats()
    assert before["pending_alerts"] == 2
    assert before["active_sessions"] == 2
    _ = injector.get_pending("s1")
    after = injector.get_stats()
    assert after["pending_alerts"] == 1
    assert after["total_injected"] == 1


def _client(tmp_path: Path) -> TestClient:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_api_queue_alert_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path)
    res = client.post(
        "/api/v1/webchat/alert/sess-1",
        headers={"Authorization": "Bearer test-token"},
        json={"alert_type": "security", "message": "Prompt injection detected in this session"},
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["queued"] is True
    assert payload["alert"]["session_id"] == "sess-1"


def test_api_pending_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _ = client.post(
        "/api/v1/webchat/alert/sess-42",
        headers={"Authorization": "Bearer test-token"},
        json={"alert_type": "budget", "message": "You've used 80% of daily budget"},
    )
    res = client.get("/api/v1/webchat/sess-42/pending", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["session_id"] == "sess-42"
    assert payload["count"] == 1
    assert payload["pending"][0]["injected"] is True
