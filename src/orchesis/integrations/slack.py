"""Slack alert integration for Orchesis events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import DecisionEvent

DEFAULT_NOTIFY_ON = ["DENY", "ANOMALY", "BYPASS", "INVARIANT_FAILURE"]


def _get_httpx():
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for Slack integration. "
            "Install with: pip install orchesis[integrations]"
        ) from None


def format_blocked_message(event: AlertEvent) -> dict[str, Any]:
    """Format BLOCKED event with Slack blocks."""
    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 {event.severity.upper()} — {event.action}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{event.agent_id or 'unknown'}"},
                    {"type": "mrkdwn", "text": f"*Rule:*\n{event.rule_id or 'n/a'}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{event.timestamp}"},
                    {"type": "mrkdwn", "text": f"*Pattern:*\n`{(event.pattern or '')[:50]}`"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Dashboard"},
                        "url": "http://localhost:8080/dashboard",
                    }
                ],
            },
        ]
    }


def format_budget_message(event: AlertEvent) -> dict[str, Any]:
    """Format BUDGET alert event."""
    metadata = event.metadata if isinstance(event.metadata, dict) else {}
    spent = metadata.get("spent", metadata.get("spent_usd", 0))
    limit = metadata.get("limit", metadata.get("limit_usd", 0))
    projection = metadata.get("projection_24h", 0)
    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"💸 {event.action} — {event.severity.upper()}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Spent:*\n${float(spent):.2f}"},
                    {"type": "mrkdwn", "text": f"*Limit:*\n${float(limit):.2f}"},
                    {"type": "mrkdwn", "text": f"*Projection 24h:*\n${float(projection):.2f}"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n{event.agent_id or 'unknown'}"},
                ],
            },
        ]
    }


class SlackIntegration(BaseIntegration):
    """Slack incoming-webhook integration for AlertEvent."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._url = str(self.config.get("webhook_url", "") or "")
        self._channel = self.config.get("channel")
        self._logger = StructuredLogger("slack_integration")

    def _post(self, payload: dict[str, Any]) -> bool:
        if not self._url:
            return False
        if isinstance(self._channel, str) and self._channel.strip():
            payload = dict(payload)
            payload["channel"] = self._channel
        httpx = _get_httpx()
        try:
            response = httpx.post(self._url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("slack integration failed", error=str(error))
            return False

    def send(self, event: AlertEvent) -> bool:
        action = str(event.action).strip().lower()
        if action == "blocked":
            return self._post(format_blocked_message(event))
        if action == "budget_exceeded":
            return self._post(format_budget_message(event))
        payload = {
            "text": f"[{event.severity.upper()}] {event.action}: {event.description or event.rule_id}",
        }
        return self._post(payload)


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
        httpx = _get_httpx()
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
