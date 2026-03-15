"""Webhook event emitter for real-time notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from orchesis.telemetry import DecisionEvent, EventEmitter


@dataclass
class WebhookConfig:
    url: str
    events: list[str] = field(default_factory=lambda: ["DENY"])
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 5.0
    retry_count: int = 2
    secret: str | None = None


class WebhookEmitter(EventEmitter):
    """Sends decision events to HTTP webhook endpoints."""

    def __init__(self, config: WebhookConfig):
        self._config = config
        self._queue: list[dict[str, Any]] = []
        self._failed: list[dict[str, Any]] = []

    def emit(self, event: DecisionEvent) -> None:
        """Queue event and attempt timeout-protected delivery."""
        if not self._should_send(event):
            return
        payload = self._build_payload(event)
        self._queue.append(payload)
        self.flush()

    def _should_send(self, event: DecisionEvent) -> bool:
        configured = {item.upper() for item in self._config.events}
        if "ALL" in configured:
            return True
        if "ANOMALY" in configured and any(
            reason.startswith("anomaly:") for reason in event.reasons
        ):
            return True
        if event.decision in configured:
            return True
        return False

    def _build_payload(self, event: DecisionEvent) -> dict[str, Any]:
        payload = {
            "event_type": "decision",
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "agent_id": event.agent_id,
            "tool": event.tool,
            "decision": event.decision,
            "reasons": list(event.reasons),
            "policy_version": event.policy_version,
        }
        if self._config.secret:
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            payload["orchesis_signature"] = self._sign_payload(raw)
        return payload

    def _sign_payload(self, payload: bytes) -> str:
        secret = self._config.secret or ""
        digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return f"hmac-sha256={digest}"

    def _send_payload(self, payload: dict[str, Any]) -> bool:
        headers = dict(self._config.headers)
        if self._config.secret and "orchesis_signature" in payload:
            headers["X-Orchesis-Signature"] = str(payload["orchesis_signature"])
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **headers}
        req = Request(self._config.url, data=body, headers=req_headers, method="POST")
        try:
            with urlopen(req, timeout=self._config.timeout_seconds) as response:
                status = int(getattr(response, "status", 200))
                if status >= 400:
                    return False
        except (HTTPError, URLError):
            return False
        return True

    def flush(self) -> None:
        """Force send queued events."""
        pending = list(self._queue)
        self._queue.clear()
        for payload in pending:
            delivered = False
            for _ in range(max(1, self._config.retry_count + 1)):
                try:
                    delivered = self._send_payload(payload)
                    if delivered:
                        break
                except Exception:
                    delivered = False
            if not delivered:
                self._failed.append(payload)

    @property
    def failed_deliveries(self) -> list[dict[str, Any]]:
        return list(self._failed)
