from __future__ import annotations

import asyncio
import json
from typing import Any

from orchesis.integrations.alert_manager import AlertManager
from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.integrations.discord import DiscordIntegration, format_blocked_embed
from orchesis.integrations.github import GitHubIntegration
from orchesis.integrations.slack import SlackIntegration, format_blocked_message, format_budget_message
from orchesis.integrations.telegram import TelegramBot, TelegramIntegration
from orchesis.integrations.webhook import WebhookIntegration
from orchesis.integrations import webhook as webhook_module


def _event(
    *,
    action: str = "blocked",
    severity: str = "high",
    agent_id: str = "openclaw_01",
    rule_id: str = "ORCH-PI-001",
    pattern: str = "ignore previous instructions",
    description: str = "prompt injection detected",
    remediation: str = "sanitize user prompt",
    metadata: dict[str, Any] | None = None,
) -> AlertEvent:
    return AlertEvent(
        action=action,
        severity=severity,
        agent_id=agent_id,
        rule_id=rule_id,
        pattern=pattern,
        description=description,
        remediation=remediation,
        timestamp="2026-03-16T09:14:32+00:00",
        metadata=metadata or {},
    )


def test_alert_manager_dispatch_to_telegram(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(TelegramIntegration, "send", lambda self, event: sent.append(event.action) or True)
    manager = AlertManager({"alerts": {"telegram": {"enabled": True, "token": "t", "chat_id": "c", "on": ["blocked"]}}})
    manager.dispatch(_event(action="blocked"))
    assert sent == ["blocked"]


def test_alert_manager_dispatch_to_slack(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(SlackIntegration, "send", lambda self, event: sent.append(event.action) or True)
    manager = AlertManager(
        {"alerts": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x", "on": ["blocked"]}}}
    )
    manager.dispatch(_event(action="blocked"))
    assert sent == ["blocked"]


def test_alert_manager_dispatch_to_discord(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(DiscordIntegration, "send", lambda self, event: sent.append(event.action) or True)
    manager = AlertManager(
        {"alerts": {"discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/x", "on": ["blocked"]}}}
    )
    manager.dispatch(_event(action="blocked"))
    assert sent == ["blocked"]


def test_alert_manager_skip_disabled_integration(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(SlackIntegration, "send", lambda self, event: sent.append(event.action) or True)
    manager = AlertManager(
        {"alerts": {"slack": {"enabled": False, "webhook_url": "https://hooks.slack.com/x", "on": ["blocked"]}}}
    )
    manager.dispatch(_event(action="blocked"))
    assert sent == []


def test_alert_manager_filter_by_severity(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(SlackIntegration, "send", lambda self, event: sent.append(event.severity) or True)
    manager = AlertManager(
        {
            "alerts": {
                "slack": {
                    "enabled": True,
                    "webhook_url": "https://hooks.slack.com/x",
                    "on": ["blocked"],
                    "min_severity": "high",
                }
            }
        }
    )
    manager.dispatch(_event(action="blocked", severity="medium"))
    manager.dispatch(_event(action="blocked", severity="critical"))
    assert sent == ["critical"]


def test_alert_manager_filter_by_event_type(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []
    monkeypatch.setattr(SlackIntegration, "send", lambda self, event: sent.append(event.action) or True)
    manager = AlertManager(
        {"alerts": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x", "on": ["budget_exceeded"]}}}
    )
    manager.dispatch(_event(action="blocked"))
    manager.dispatch(_event(action="budget_exceeded"))
    assert sent == ["budget_exceeded"]


def test_alert_manager_never_crashes_proxy(monkeypatch) -> None:  # noqa: ANN001
    def _boom(self, event):  # noqa: ANN001
        raise RuntimeError("network down")

    monkeypatch.setattr(SlackIntegration, "send", _boom)
    manager = AlertManager(
        {"alerts": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x", "on": ["blocked"]}}}
    )
    manager.dispatch(_event(action="blocked"))


def test_telegram_format_blocked() -> None:
    integration = TelegramIntegration({"enabled": True, "token": "t", "chat_id": "c"})
    text = integration.format_event(_event(action="blocked", severity="high"))
    assert "BLOCKED" in text
    assert "Agent: openclaw_01" in text
    assert "Rule: ORCH-PI-001" in text


def test_telegram_format_budget() -> None:
    integration = TelegramIntegration({"enabled": True, "token": "t", "chat_id": "c"})
    text = integration.format_event(
        _event(
            action="budget_exceeded",
            metadata={"spent_usd": 4.23, "limit_usd": 5.0, "rate_per_hour": 0.18, "projected_24h": 5.0, "eta": "27 min"},
        )
    )
    assert "BUDGET WARNING" in text
    assert "$4.23 / $5.00" in text


def test_telegram_command_status(monkeypatch) -> None:  # noqa: ANN001
    class _Proxy:
        def get_status_snapshot(self):
            return {"uptime_seconds": 3600, "requests": 1847, "blocked": 3, "saved_usd": 2.41}

    bot = TelegramBot("token", "chat", _Proxy())
    sent: list[str] = []
    monkeypatch.setattr(bot, "send", lambda text: sent.append(text) or asyncio.sleep(0))
    asyncio.run(bot._handle_command({"update_id": 1, "message": {"text": "/status"}}))
    assert sent and "ALL CLEAR" in sent[0]


def test_telegram_command_block_pattern(monkeypatch) -> None:  # noqa: ANN001
    class _Proxy:
        def __init__(self):
            self.value = ""

        def add_block_pattern(self, pattern: str):
            self.value = pattern

    proxy = _Proxy()
    bot = TelegramBot("token", "chat", proxy)
    sent: list[str] = []
    monkeypatch.setattr(bot, "send", lambda text: sent.append(text) or asyncio.sleep(0))
    asyncio.run(bot._handle_command({"update_id": 2, "message": {"text": "/block rm -rf"}}))
    assert proxy.value == "rm -rf"
    assert sent and "Blocked: rm -rf" in sent[0]


def test_telegram_command_pause_resume(monkeypatch) -> None:  # noqa: ANN001
    class _Proxy:
        def __init__(self):
            self.monitor = False

        def set_monitoring_only(self, value: bool):
            self.monitor = bool(value)

    proxy = _Proxy()
    bot = TelegramBot("token", "chat", proxy)
    sent: list[str] = []
    monkeypatch.setattr(bot, "send", lambda text: sent.append(text) or asyncio.sleep(0))
    asyncio.run(bot._handle_command({"update_id": 3, "message": {"text": "/pause"}}))
    assert proxy.monitor is True
    asyncio.run(bot._handle_command({"update_id": 4, "message": {"text": "/resume"}}))
    assert proxy.monitor is False
    assert any("paused" in item.lower() for item in sent)
    assert any("resumed" in item.lower() for item in sent)


def test_slack_format_blocked_message() -> None:
    payload = format_blocked_message(_event(action="BLOCKED", severity="high"))
    assert payload["blocks"][0]["text"]["text"].startswith("🚨 HIGH")
    fields = payload["blocks"][1]["fields"]
    assert any("Agent" in field["text"] for field in fields)


def test_slack_format_budget_message() -> None:
    payload = format_budget_message(
        _event(action="BUDGET_EXCEEDED", metadata={"spent": 2.0, "limit": 5.0, "projection_24h": 10.0})
    )
    text = payload["blocks"][0]["text"]["text"]
    assert "BUDGET_EXCEEDED" in text


def test_discord_format_embed_colors() -> None:
    high_payload = format_blocked_embed(_event(severity="high", action="BLOCKED"))
    critical_payload = format_blocked_embed(_event(severity="critical", action="BLOCKED"))
    assert high_payload["embeds"][0]["color"] == 0xFF6600
    assert critical_payload["embeds"][0]["color"] == 0xFF0000


def test_github_create_issue_format(monkeypatch) -> None:  # noqa: ANN001
    captured: dict[str, Any] = {}

    def _fake_api_post(self, path: str, payload: dict[str, Any]):  # noqa: ANN001
        captured["path"] = path
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(GitHubIntegration, "_api_post", _fake_api_post)
    integration = GitHubIntegration({"enabled": True, "token": "ghp_x", "repo": "owner/repo"})
    integration.create_security_issue(_event(severity="critical"))
    assert captured["path"] == "/issues"
    assert "Security Alert from Orchesis" in captured["payload"]["body"]
    assert "severity:critical" in captured["payload"]["labels"]


def test_webhook_hmac_signature() -> None:
    integration = WebhookIntegration({"enabled": True, "url": "https://example.com/hook", "secret": "s3cr3t"})
    payload = integration.build_payload(_event())
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = integration._signature(body)
    assert signature.startswith("sha256=")


def test_webhook_payload_format() -> None:
    integration = WebhookIntegration({"enabled": True, "url": "https://example.com/hook"})
    payload = integration.build_payload(_event(action="anomaly", severity="medium"))
    assert payload["source"] == "orchesis"
    assert payload["action"] == "anomaly"
    assert payload["severity"] == "medium"


def test_base_should_alert_severity_filter() -> None:
    base = BaseIntegration({"enabled": True, "on": ["blocked"], "min_severity": "high"})
    assert base.should_alert(_event(action="blocked", severity="medium"), base.config) is False
    assert base.should_alert(_event(action="blocked", severity="critical"), base.config) is True


def test_base_should_alert_event_filter() -> None:
    base = BaseIntegration({"enabled": True, "on": ["budget_exceeded"], "min_severity": "low"})
    assert base.should_alert(_event(action="blocked"), base.config) is False
    assert base.should_alert(_event(action="budget_exceeded"), base.config) is True


def test_webhook_send_uses_signature_header(monkeypatch) -> None:  # noqa: ANN001
    captured: dict[str, Any] = {}

    class _Resp:
        status = 200

        def __enter__(self):  # noqa: ANN001
            return self

        def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
            return False

    def _fake_urlopen(req, timeout: float):  # noqa: ANN001
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(webhook_module, "urlopen", _fake_urlopen)
    integration = WebhookIntegration(
        {"enabled": True, "url": "https://example.com/hook", "secret": "abc", "timeout_seconds": 3}
    )
    assert integration.send(_event()) is True
    assert "x-orchesis-signature" in captured["headers"]
    assert captured["timeout"] == 3

