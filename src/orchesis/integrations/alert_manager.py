"""Dispatch alert events to configured integrations.

This module also provides legacy alerting compatibility exports used by
`proxy.py` and older call sites.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
import threading
import time
from typing import Any

from orchesis.integrations.base import AlertEvent as IntegrationAlertEvent, BaseIntegration
from orchesis.integrations.discord import DiscordIntegration
from orchesis.integrations.github import GitHubIntegration
from orchesis.integrations.slack import SlackIntegration
from orchesis.integrations.telegram import TelegramIntegration
from orchesis.integrations.webhook import WebhookIntegration

logger = logging.getLogger("orchesis.integrations.alert_manager")


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AlertEvent:
    """Legacy alert event shape used by proxy alerting."""

    severity: AlertSeverity
    event_type: str
    title: str
    details: str
    timestamp: float = 0.0
    session_id: str = ""
    agent_id: str = ""
    request_cost: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertConfig:
    """Legacy alert config shape used by proxy alerting."""

    enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)
    notify_on: list[str] = field(default_factory=lambda: ["threat_blocked", "budget_exceeded", "circuit_open"])
    min_severity: str = "warning"
    cooldown_seconds: int = 60
    max_per_hour: int = 20
    daily_digest_enabled: bool = False
    daily_digest_hour: int = 9

    @classmethod
    def from_policy_dict(cls, alerts_cfg: Any) -> "AlertConfig":
        cfg = alerts_cfg if isinstance(alerts_cfg, dict) else {}
        telegram = cfg.get("telegram") if isinstance(cfg.get("telegram"), dict) else {}
        webhook = cfg.get("webhook") if isinstance(cfg.get("webhook"), dict) else {}
        notify_on = cfg.get("notify_on") if isinstance(cfg.get("notify_on"), list) else None
        headers = webhook.get("headers") if isinstance(webhook.get("headers"), dict) else {}
        return cls(
            enabled=bool(cfg.get("enabled", False)),
            telegram_bot_token=str(telegram.get("bot_token", "")),
            telegram_chat_id=str(telegram.get("chat_id", "")),
            webhook_url=str(webhook.get("url", "")),
            webhook_headers={str(k): str(v) for k, v in headers.items()},
            notify_on=[str(item) for item in notify_on] if notify_on is not None else cls().notify_on,
            min_severity=str(cfg.get("min_severity", "warning")).lower(),
            cooldown_seconds=int(cfg.get("cooldown_seconds", 60)),
            max_per_hour=int(cfg.get("max_per_hour", 20)),
            daily_digest_enabled=bool(cfg.get("daily_digest_enabled", False)),
            daily_digest_hour=int(cfg.get("daily_digest_hour", 9)),
        )


class AlertManager:
    """Multi-integration alert dispatcher."""

    def __init__(self, config: dict[str, Any] | AlertConfig, proxy_instance: Any = None):
        self._legacy_mode = isinstance(config, AlertConfig)
        self._legacy_config = config if isinstance(config, AlertConfig) else AlertConfig()
        self._legacy_lock = threading.Lock()
        self._legacy_last_sent: dict[str, float] = {}
        self._legacy_hour_count = 0
        self._legacy_hour_start = time.time()
        self._integrations: list[BaseIntegration] = []
        if self._legacy_mode:
            self._legacy_stats = {"sent": 0, "dropped_rate_limit": 0, "dropped_severity": 0, "errors": 0}
            return
        self._setup(config.get("alerts", {}), proxy_instance=proxy_instance)

    def _setup(self, alerts_config: dict[str, Any], proxy_instance: Any = None) -> None:
        cfg = alerts_config if isinstance(alerts_config, dict) else {}
        telegram_cfg = cfg.get("telegram", {})
        if isinstance(telegram_cfg, dict) and telegram_cfg.get("enabled"):
            self._integrations.append(TelegramIntegration(telegram_cfg, proxy_instance=proxy_instance))
        slack_cfg = cfg.get("slack", {})
        if isinstance(slack_cfg, dict) and slack_cfg.get("enabled"):
            self._integrations.append(SlackIntegration(slack_cfg))
        discord_cfg = cfg.get("discord", {})
        if isinstance(discord_cfg, dict) and discord_cfg.get("enabled"):
            self._integrations.append(DiscordIntegration(discord_cfg))
        github_cfg = cfg.get("github", {})
        if isinstance(github_cfg, dict) and github_cfg.get("enabled"):
            self._integrations.append(GitHubIntegration(github_cfg))
        webhook_cfg = cfg.get("webhook", {})
        if isinstance(webhook_cfg, dict) and webhook_cfg.get("enabled"):
            self._integrations.append(WebhookIntegration(webhook_cfg))

    def dispatch(self, event: IntegrationAlertEvent) -> None:
        """Send event to all configured integrations, never raising."""
        if self._legacy_mode:
            return
        for integration in self._integrations:
            try:
                if integration.should_alert(event, integration.config):
                    integration.send(event)
            except Exception as error:  # noqa: BLE001
                logger.warning("Integration %s failed: %s", type(integration).__name__, error)

    @property
    def integrations(self) -> list[BaseIntegration]:
        return list(self._integrations)

    @property
    def enabled(self) -> bool:
        if self._legacy_mode:
            return bool(self._legacy_config.enabled)
        return bool(self._integrations)

    @property
    def stats(self) -> dict[str, Any]:
        if self._legacy_mode:
            with self._legacy_lock:
                return dict(self._legacy_stats)
        return {"sent": 0, "dropped_rate_limit": 0, "dropped_severity": 0, "errors": 0}

    def stop(self) -> None:
        return

    def alert(self, event: AlertEvent) -> bool:
        """Legacy alert API used by proxy alerting code."""
        if not self._legacy_mode:
            translated = IntegrationAlertEvent(
                action=str(event.event_type),
                severity=str(event.severity.value),
                agent_id=str(event.agent_id),
                rule_id="legacy",
                pattern=str(event.title),
                description=str(event.details),
                remediation="",
                metadata={"session_id": event.session_id, "request_cost": event.request_cost, **event.extra},
            )
            self.dispatch(translated)
            return True

        cfg = self._legacy_config
        if not cfg.enabled:
            return False
        if cfg.notify_on and event.event_type not in cfg.notify_on:
            return False

        severity_rank = {"info": 0, "warning": 1, "critical": 2}
        min_rank = severity_rank.get(cfg.min_severity, 1)
        event_rank = severity_rank.get(event.severity.value, 0)
        if event_rank < min_rank:
            with self._legacy_lock:
                self._legacy_stats["dropped_severity"] += 1
            return False

        now = time.time()
        with self._legacy_lock:
            if now - self._legacy_hour_start > 3600:
                self._legacy_hour_count = 0
                self._legacy_hour_start = now
            if self._legacy_hour_count >= cfg.max_per_hour:
                self._legacy_stats["dropped_rate_limit"] += 1
                return False
            last = self._legacy_last_sent.get(event.event_type, 0.0)
            if now - last < cfg.cooldown_seconds:
                self._legacy_stats["dropped_rate_limit"] += 1
                return False
            self._legacy_last_sent[event.event_type] = now
            self._legacy_hour_count += 1
            self._legacy_stats["sent"] += 1
        return True

