"""Generic webhook integration."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.structured_log import StructuredLogger


class WebhookIntegration(BaseIntegration):
    """Sends AlertEvent payload to arbitrary HTTP endpoint."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._url = str(self.config.get("url", "") or "")
        self._secret = str(self.config.get("secret", "") or "")
        self._timeout = float(self.config.get("timeout_seconds", 5.0) or 5.0)
        self._logger = StructuredLogger("webhook_integration")

    def build_payload(self, event: AlertEvent) -> dict[str, Any]:
        return {
            "source": "orchesis",
            "action": event.action,
            "severity": event.severity,
            "agent_id": event.agent_id,
            "rule_id": event.rule_id,
            "pattern": event.pattern,
            "description": event.description,
            "remediation": event.remediation,
            "timestamp": event.timestamp,
            "metadata": event.metadata if isinstance(event.metadata, dict) else {},
        }

    def _signature(self, body: bytes) -> str:
        digest = hmac.new(self._secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def send(self, event: AlertEvent) -> bool:
        if not self._url:
            return False
        payload = self.build_payload(event)
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-Orchesis-Signature"] = self._signature(body)
        req = Request(self._url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=self._timeout) as response:
                status = int(getattr(response, "status", 200))
                return status < 400
        except (HTTPError, URLError):
            return False
        except Exception as error:  # noqa: BLE001
            self._logger.warn("webhook integration failed", error=str(error))
            return False

