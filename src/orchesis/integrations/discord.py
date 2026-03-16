"""Discord webhook integration."""

from __future__ import annotations

from typing import Any

from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.structured_log import StructuredLogger


def _get_httpx():
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for Discord integration. "
            "Install with: pip install orchesis[integrations]"
        ) from None


def format_blocked_embed(event: AlertEvent) -> dict[str, Any]:
    """Create Discord embed payload for blocked event."""
    color = {
        "critical": 0xFF0000,
        "high": 0xFF6600,
        "medium": 0xFFAA00,
        "low": 0x00AA00,
    }.get(str(event.severity).lower(), 0x888888)

    return {
        "embeds": [
            {
                "title": f"🚨 {event.action} — {event.severity.upper()}",
                "color": color,
                "fields": [
                    {"name": "Agent", "value": event.agent_id or "unknown", "inline": True},
                    {"name": "Rule", "value": event.rule_id or "n/a", "inline": True},
                    {"name": "Pattern", "value": f"`{(event.pattern or '')[:100]}`", "inline": False},
                ],
                "timestamp": event.timestamp,
                "footer": {"text": "Orchesis Runtime Gateway for AI Agents"},
            }
        ]
    }


class DiscordIntegration(BaseIntegration):
    """Discord incoming webhook integration."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._url = str(self.config.get("webhook_url", "") or "")
        self._logger = StructuredLogger("discord_integration")

    def _post(self, payload: dict[str, Any]) -> bool:
        if not self._url:
            return False
        httpx = _get_httpx()
        try:
            response = httpx.post(self._url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("discord integration failed", error=str(error))
            return False

    def send(self, event: AlertEvent) -> bool:
        if str(event.action).strip().lower() == "blocked":
            return self._post(format_blocked_embed(event))
        payload = {
            "content": f"[{event.severity.upper()}] {event.action}: {event.description or event.rule_id}",
        }
        return self._post(payload)

