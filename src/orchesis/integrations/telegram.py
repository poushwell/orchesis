"""Telegram alert integration for Orchesis events."""

from __future__ import annotations

import httpx

from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import DecisionEvent

DEFAULT_NOTIFY_ON = ["DENY", "ANOMALY"]


def _escape_markdown_v2(value: str) -> str:
    """Escape Telegram MarkdownV2 special characters."""
    chars = r"_*[]()~`>#+-=|{}.!\\"
    escaped = value
    for char in chars:
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


class TelegramNotifier:
    """Send Orchesis alerts to Telegram via Bot API."""

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        notify_on: list[str] | None = None,
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._notify_on = [item.upper() for item in (notify_on or DEFAULT_NOTIFY_ON)]
        self._logger = StructuredLogger("telegram_notifier")

    def format_deny(self, event: DecisionEvent) -> str:
        """Format DENY event as Telegram MarkdownV2 message."""
        reason = event.reasons[0] if event.reasons else "Denied by policy"
        lines = [
            "🚫 *Agent Blocked*",
            f"Agent: `{_escape_markdown_v2(event.agent_id)}`",
            f"Tool: `{_escape_markdown_v2(event.tool)}`",
            f"Reason: {_escape_markdown_v2(reason)}",
            f"Policy: `{_escape_markdown_v2(event.policy_version[:12])}`",
        ]
        return "\n".join(lines)

    def send(self, text: str) -> bool:
        """Send message to Telegram Bot API; fail-silent on errors."""
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
        }
        try:
            response = httpx.post(url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("telegram send failed", error=str(error))
            return False

    def emit(self, event: DecisionEvent) -> None:
        """EventEmitter-compatible interface."""
        if event.decision == "DENY" and "DENY" in self._notify_on:
            self.send(self.format_deny(event))
            return
        if "ANOMALY" in self._notify_on and any(reason.startswith("anomaly:") for reason in event.reasons):
            self.send(_escape_markdown_v2("; ".join(event.reasons)))


class TelegramEmitter:
    """EventBus adapter for Telegram notifications."""

    def __init__(self, notifier: TelegramNotifier) -> None:
        self._notifier = notifier

    def emit(self, event: DecisionEvent) -> None:
        """Forward event to notifier with built-in filtering."""
        self._notifier.emit(event)
