"""Webhook event emitter for real-time notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
import time
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
    min_severity: str = "low"
    agent_ids: list[str] = field(default_factory=list)
    retry: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookRetryConfig:
    max_retries: int = 3
    initial_delay: float = 1.0
    backoff_multiplier: float = 2.0
    max_delay: float = 30.0


class WebhookFilter:
    _SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self, config: dict[str, Any]):
        self.events = list(config.get("events", ["*"])) if isinstance(config.get("events", ["*"]), list) else ["*"]
        self.min_severity = str(config.get("min_severity", "low")).lower()
        self.agent_ids = list(config.get("agent_ids", [])) if isinstance(config.get("agent_ids", []), list) else []

    def matches(self, event: dict[str, Any]) -> bool:
        event_type = str(event.get("event_type", "") or event.get("decision", "")).lower()
        configured = {str(item).lower() for item in self.events}
        if "*" not in configured and "all" not in configured and event_type not in configured:
            return False

        severity = str(event.get("severity", "low")).lower()
        if self._SEVERITY_RANK.get(severity, 0) < self._SEVERITY_RANK.get(self.min_severity, 0):
            return False

        if self.agent_ids:
            agent_id = str(event.get("agent_id", ""))
            if agent_id not in {str(item) for item in self.agent_ids}:
                return False
        return True


class WebhookEmitter(EventEmitter):
    """Sends decision events to HTTP webhook endpoints."""

    def __init__(self, config: WebhookConfig):
        self._config = config
        self._filter = WebhookFilter(
            {
                "events": config.events,
                "min_severity": config.min_severity,
                "agent_ids": config.agent_ids,
            }
        )
        retry_cfg = config.retry if isinstance(config.retry, dict) else {}
        self._retry_config = WebhookRetryConfig(
            max_retries=int(retry_cfg.get("max_retries", max(0, int(config.retry_count)))),
            initial_delay=float(retry_cfg.get("initial_delay", 1.0)),
            backoff_multiplier=float(retry_cfg.get("backoff_multiplier", 2.0)),
            max_delay=float(retry_cfg.get("max_delay", 30.0)),
        )
        self._queue: list[dict[str, Any]] = []
        self._failed: list[dict[str, Any]] = []
        self._stats: dict[str, Any] = {
            "success_count": 0,
            "failure_count": 0,
            "last_sent": None,
            "avg_latency_ms": 0.0,
            "samples": 0,
        }

    def emit(self, event: DecisionEvent) -> None:
        """Queue event and attempt timeout-protected delivery."""
        if not self._should_send(event):
            return
        payload = self._build_payload(event)
        self._queue.append(payload)
        self.flush()

    def _should_send(self, event: DecisionEvent) -> bool:
        event_payload = self._build_payload(event)
        return self._filter.matches(event_payload)

    def _build_payload(self, event: DecisionEvent) -> dict[str, Any]:
        severity = "low"
        if event.decision == "DENY":
            severity = "high"
        if any("critical" in str(reason).lower() for reason in event.reasons):
            severity = "critical"
        payload = {
            "event_type": str(event.decision).lower(),
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "agent_id": event.agent_id,
            "tool": event.tool,
            "decision": event.decision,
            "severity": severity,
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

    def _record_delivery_stat(self, success: bool, latency_ms: float) -> None:
        key = "success_count" if success else "failure_count"
        self._stats[key] = int(self._stats.get(key, 0)) + 1
        self._stats["last_sent"] = time.time()
        samples = int(self._stats.get("samples", 0)) + 1
        prev_avg = float(self._stats.get("avg_latency_ms", 0.0))
        self._stats["avg_latency_ms"] = ((prev_avg * (samples - 1)) + max(0.0, float(latency_ms))) / samples
        self._stats["samples"] = samples

    def _send_with_retry(self, url: str, payload: dict[str, Any], config: WebhookRetryConfig) -> bool:
        """Send webhook with exponential backoff retry."""
        _ = url  # URL is already bound to emitter config.
        delay = max(0.0, float(config.initial_delay))
        attempts = max(0, int(config.max_retries)) + 1
        for attempt in range(attempts):
            started = time.perf_counter()
            ok = self._send_payload(payload)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self._record_delivery_stat(ok, elapsed_ms)
            if ok:
                return True
            if attempt < attempts - 1:
                time.sleep(delay)
                delay = min(float(config.max_delay), max(0.0, delay * float(config.backoff_multiplier)))
        return False

    def flush(self) -> None:
        """Force send queued events."""
        pending = list(self._queue)
        self._queue.clear()
        for payload in pending:
            try:
                delivered = self._send_with_retry(self._config.url, payload, self._retry_config)
            except Exception:
                delivered = False
            if not delivered:
                self._failed.append(payload)

    @property
    def failed_deliveries(self) -> list[dict[str, Any]]:
        return list(self._failed)

    def get_webhook_stats(self) -> dict[str, Any]:
        """Per-webhook: success_count, failure_count, last_sent, avg_latency_ms."""
        return {
            self._config.url: {
                "success_count": int(self._stats.get("success_count", 0)),
                "failure_count": int(self._stats.get("failure_count", 0)),
                "last_sent": self._stats.get("last_sent"),
                "avg_latency_ms": float(self._stats.get("avg_latency_ms", 0.0)),
            }
        }
