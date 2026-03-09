from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any

from orchesis.alerting import AlertConfig, AlertEvent, AlertManager, AlertSeverity
from orchesis.config import load_policy


class _DummyResponse:
    def __enter__(self) -> _DummyResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False

    def read(self) -> bytes:
        return b"ok"


def _event(
    *,
    severity: AlertSeverity = AlertSeverity.WARNING,
    event_type: str = "threat_blocked",
    title: str = "title",
    details: str = "details",
) -> AlertEvent:
    return AlertEvent(severity=severity, event_type=event_type, title=title, details=details)


def test_alert_disabled_drops() -> None:
    manager = AlertManager(AlertConfig(enabled=False))
    assert manager.alert(_event()) is False


def test_alert_severity_filter() -> None:
    manager = AlertManager(AlertConfig(enabled=False, min_severity="critical"))
    manager._config.enabled = True
    assert manager.alert(_event(severity=AlertSeverity.WARNING)) is False
    assert manager.stats["dropped_severity"] == 1


def test_alert_event_type_filter() -> None:
    manager = AlertManager(AlertConfig(enabled=False, notify_on=["budget_exceeded"]))
    manager._config.enabled = True
    assert manager.alert(_event(event_type="threat_blocked")) is False


def test_alert_cooldown_rate_limit() -> None:
    manager = AlertManager(AlertConfig(enabled=False, cooldown_seconds=60, notify_on=["threat_blocked"]))
    manager._config.enabled = True
    assert manager.alert(_event(event_type="threat_blocked")) is True
    assert manager.alert(_event(event_type="threat_blocked")) is False
    assert manager.stats["dropped_rate_limit"] == 1


def test_alert_max_per_hour() -> None:
    manager = AlertManager(AlertConfig(enabled=False, max_per_hour=1, cooldown_seconds=0, notify_on=["a", "b"]))
    manager._config.enabled = True
    assert manager.alert(_event(event_type="a")) is True
    assert manager.alert(_event(event_type="b")) is False
    assert manager.stats["dropped_rate_limit"] == 1


def test_alert_queued_when_enabled() -> None:
    manager = AlertManager(AlertConfig(enabled=False, cooldown_seconds=0))
    manager._config.enabled = True
    assert manager.alert(_event()) is True


def test_telegram_message_format(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_urlopen(req: Any, timeout: float = 10) -> _DummyResponse:
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _DummyResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    cfg = AlertConfig(enabled=False, telegram_bot_token="123:abc", telegram_chat_id="42")
    manager = AlertManager(cfg)
    manager._send_telegram(_event(severity=AlertSeverity.CRITICAL, title="Blocked", details="Danger"))
    assert "api.telegram.org/bot123:abc/sendMessage" in captured["url"]
    assert captured["data"]["chat_id"] == "42"
    assert "Orchesis Alert" in captured["data"]["text"]
    assert "Blocked" in captured["data"]["text"]


def test_webhook_payload_format(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_urlopen(req: Any, timeout: float = 10) -> _DummyResponse:
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode("utf-8"))
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        captured["timeout"] = timeout
        return _DummyResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    cfg = AlertConfig(enabled=False, webhook_url="https://example.com/hook", webhook_headers={"Authorization": "Bearer x"})
    manager = AlertManager(cfg)
    manager._send_webhook(_event(event_type="budget_exceeded"))
    assert captured["url"] == "https://example.com/hook"
    assert captured["data"]["event_type"] == "budget_exceeded"
    assert captured["data"]["source"] == "orchesis"
    assert captured["headers"].get("authorization") == "Bearer x"


def test_stats_tracking(monkeypatch: Any) -> None:
    def _raise_urlopen(req: Any, timeout: float = 10) -> _DummyResponse:
        raise RuntimeError("boom")

    monkeypatch.setattr("urllib.request.urlopen", _raise_urlopen)
    cfg = AlertConfig(enabled=False, telegram_bot_token="x", telegram_chat_id="y")
    manager = AlertManager(cfg)
    manager._send_telegram(_event())
    assert manager.stats["errors"] == 1


def test_stop_sender_thread() -> None:
    manager = AlertManager(AlertConfig(enabled=True))
    assert manager._thread is not None
    manager.stop()
    assert manager._running is False


def test_alert_with_session_and_cost(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _fake_urlopen(req: Any, timeout: float = 10) -> _DummyResponse:
        captured["data"] = json.loads(req.data.decode("utf-8"))
        return _DummyResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    cfg = AlertConfig(enabled=False, telegram_bot_token="1:2", telegram_chat_id="chat")
    manager = AlertManager(cfg)
    manager._send_telegram(
        AlertEvent(
            severity=AlertSeverity.WARNING,
            event_type="spend_rate_exceeded",
            title="Spend rate exceeded",
            details="Too fast",
            session_id="sess-1",
            request_cost=0.1234,
        )
    )
    text = captured["data"]["text"]
    assert "Session: `sess-1`" in text
    assert "Cost: $0.1234" in text


def test_config_defaults() -> None:
    cfg = AlertConfig()
    assert cfg.enabled is False
    assert cfg.min_severity == "warning"
    assert cfg.cooldown_seconds == 60
    assert cfg.max_per_hour == 20


def test_config_from_policy_yaml() -> None:
    content = """
alerts:
  enabled: true
  telegram:
    bot_token: "123:abc"
    chat_id: "-1001"
  webhook:
    url: "https://hooks.example.com"
    headers:
      Authorization: "Bearer xyz"
  notify_on:
    - threat_blocked
    - budget_exceeded
  min_severity: warning
  cooldown_seconds: 33
  max_per_hour: 9
"""
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        policy = load_policy(path)
        cfg = AlertConfig.from_policy_dict(policy.get("alerts"))
    finally:
        if isinstance(path, str) and os.path.exists(path):
            os.unlink(path)
    assert cfg.enabled is True
    assert cfg.telegram_bot_token == "123:abc"
    assert cfg.telegram_chat_id == "-1001"
    assert cfg.webhook_url == "https://hooks.example.com"
    assert cfg.webhook_headers["Authorization"] == "Bearer xyz"
    assert cfg.cooldown_seconds == 33
    assert cfg.max_per_hour == 9


def test_multiple_channels(monkeypatch: Any) -> None:
    calls: list[str] = []

    def _fake_urlopen(req: Any, timeout: float = 10) -> _DummyResponse:
        calls.append(req.full_url)
        return _DummyResponse()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    cfg = AlertConfig(
        enabled=False,
        telegram_bot_token="1:2",
        telegram_chat_id="chat",
        webhook_url="https://example.com/hook",
    )
    manager = AlertManager(cfg)
    manager._deliver(_event())
    assert len(calls) == 2
    assert any("api.telegram.org" in url for url in calls)
    assert any("example.com/hook" in url for url in calls)


def test_hourly_counter_reset() -> None:
    manager = AlertManager(AlertConfig(enabled=False, max_per_hour=1, cooldown_seconds=0, notify_on=["a"]))
    manager._config.enabled = True
    manager._hour_count = 1
    manager._hour_start = time.time() - 3700
    assert manager.alert(_event(event_type="a")) is True


def test_daily_digest_defaults() -> None:
    cfg = AlertConfig()
    assert cfg.daily_digest_enabled is False
    assert cfg.daily_digest_hour == 9
