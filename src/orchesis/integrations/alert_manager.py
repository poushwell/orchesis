"""Dispatch AlertEvent to configured external integrations."""

from __future__ import annotations

import logging
from typing import Any

from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.integrations.discord import DiscordIntegration
from orchesis.integrations.github import GitHubIntegration
from orchesis.integrations.slack import SlackIntegration
from orchesis.integrations.telegram import TelegramIntegration
from orchesis.integrations.webhook import WebhookIntegration

logger = logging.getLogger("orchesis.integrations.alert_manager")


class AlertManager:
    """Multi-integration alert dispatcher."""

    def __init__(self, config: dict[str, Any], proxy_instance: Any = None):
        self._integrations: list[BaseIntegration] = []
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

    def dispatch(self, event: AlertEvent) -> None:
        """Send event to all configured integrations, never raising."""
        for integration in self._integrations:
            try:
                if integration.should_alert(event, integration.config):
                    integration.send(event)
            except Exception as error:  # noqa: BLE001
                logger.warning("Integration %s failed: %s", type(integration).__name__, error)

    @property
    def integrations(self) -> list[BaseIntegration]:
        return list(self._integrations)

