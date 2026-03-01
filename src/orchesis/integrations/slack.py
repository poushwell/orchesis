"""Slack alert integration for Orchesis events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import DecisionEvent

DEFAULT_NOTIFY_ON = ["DENY", "ANOMALY", "BYPASS", "INVARIANT_FAILURE"]


class SlackNotifier:
    """Send Orchesis alerts to Slack via incoming webhook."""

    def __init__(
        self,
        webhook_url: str,
        channel: str | None = None,
        notify_on: list[str] | None = None,
    ) -> None:
        self._url = webhook_url
        self._channel = channel
        self._notify_on = [item.upper() for item in (notify_on or DEFAULT_NOTIFY_ON)]
        self._logger = StructuredLogger("slack_notifier")

    def format_deny(self, event: DecisionEvent) -> dict[str, Any]:
        """Format DENY event as Slack block payload."""
        reason = event.reasons[0] if event.reasons else "Denied by policy"
        ts = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        payload: dict[str, Any] = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Agent Blocked"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:* {event.agent_id}"},
                        {"type": "mrkdwn", "text": f"*Tool:* {event.tool}"},
                        {"type": "mrkdwn", "text": f"*Reason:* {reason}"},
                        {"type": "mrkdwn", "text": f"*Time:* {ts.strftime('%Y-%m-%d %H:%M:%S')}"},
                    ],
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"Policy: {event.policy_version[:12]} | "
                                f"Latency: {event.evaluation_duration_us}us"
                            ),
                        }
                    ],
                },
            ]
        }
        if self._channel:
            payload["channel"] = self._channel
        return payload

    def format_anomaly(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        """Format anomaly payload as Slack message."""
        detail = str(anomaly.get("detail", "unknown anomaly"))
        severity = str(anomaly.get("severity", "medium")).upper()
        payload: dict[str, Any] = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"Anomaly Detected [{severity}]"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": detail},
                },
            ]
        }
        if self._channel:
            payload["channel"] = self._channel
        return payload

    def send(self, payload: dict[str, Any]) -> bool:
        """Post payload to Slack webhook; fail-silent on errors."""
        try:
            response = httpx.post(self._url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("slack send failed", error=str(error))
            return False

    def emit(self, event: DecisionEvent) -> None:
        """EventEmitter-compatible interface for direct subscription."""
        if event.decision == "DENY" and "DENY" in self._notify_on:
            self.send(self.format_deny(event))
            return
        if "ANOMALY" in self._notify_on and any(reason.startswith("anomaly:") for reason in event.reasons):
            self.send(self.format_anomaly({"detail": "; ".join(event.reasons)}))


class SlackEmitter:
    """EventBus adapter for Slack notifications."""

    def __init__(self, notifier: SlackNotifier) -> None:
        self._notifier = notifier

    def emit(self, event: DecisionEvent) -> None:
        """Forward event to notifier with built-in filtering."""
        self._notifier.emit(event)
