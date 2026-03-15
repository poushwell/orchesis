"""Real-time alerting for proxy security events."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import json
import threading
import time
from typing import Any
import urllib.request
import warnings

warnings.warn(
    "orchesis.alerting is deprecated. Use orchesis.integrations.alert_manager instead.",
    DeprecationWarning,
    stacklevel=2,
)


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AlertEvent:
    """An event that triggers an alert."""

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
    """Configuration for alerting."""

    enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)
    notify_on: list[str] = field(
        default_factory=lambda: ["threat_blocked", "budget_exceeded", "circuit_open"]
    )
    min_severity: str = "warning"
    cooldown_seconds: int = 60
    max_per_hour: int = 20
    daily_digest_enabled: bool = False
    daily_digest_hour: int = 9

    @classmethod
    def from_policy_dict(cls, alerts_cfg: Any) -> AlertConfig:
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
    """Manages alert delivery with rate limiting and multiple channels."""

    def __init__(self, config: AlertConfig | None = None) -> None:
        self._config = config or AlertConfig()
        self._lock = threading.Lock()
        self._last_sent: dict[str, float] = {}
        self._hour_count: int = 0
        self._hour_start: float = time.time()
        self._pending_digest: list[AlertEvent] = []
        self._send_queue: deque[AlertEvent] = deque(maxlen=100)
        self._stats = {"sent": 0, "dropped_rate_limit": 0, "dropped_severity": 0, "errors": 0}
        self._running = False
        self._thread: threading.Thread | None = None
        if self._config.enabled:
            self._start_sender()

    def _start_sender(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._thread.start()

    def _sender_loop(self) -> None:
        while self._running:
            try:
                if self._send_queue:
                    event = self._send_queue.popleft()
                    self._deliver(event)
                else:
                    time.sleep(0.5)
            except Exception:
                time.sleep(1.0)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def alert(self, event: AlertEvent) -> bool:
        """Submit an alert event. Returns True if queued, False if dropped."""
        if not self._config.enabled:
            return False

        severity_rank = {"info": 0, "warning": 1, "critical": 2}
        min_rank = severity_rank.get(self._config.min_severity, 1)
        event_rank = severity_rank.get(event.severity.value, 0)
        if event_rank < min_rank:
            with self._lock:
                self._stats["dropped_severity"] += 1
            return False

        if self._config.notify_on and event.event_type not in self._config.notify_on:
            return False

        now = time.time()
        with self._lock:
            if now - self._hour_start > 3600:
                self._hour_count = 0
                self._hour_start = now

            if self._hour_count >= self._config.max_per_hour:
                self._stats["dropped_rate_limit"] += 1
                return False

            last = self._last_sent.get(event.event_type, 0.0)
            if now - last < self._config.cooldown_seconds:
                self._stats["dropped_rate_limit"] += 1
                return False

            event.timestamp = event.timestamp or now
            self._send_queue.append(event)
            self._last_sent[event.event_type] = now
            self._hour_count += 1
            self._pending_digest.append(event)

        return True

    def _deliver(self, event: AlertEvent) -> None:
        if self._config.telegram_bot_token and self._config.telegram_chat_id:
            self._send_telegram(event)
        if self._config.webhook_url:
            self._send_webhook(event)

    def _send_telegram(self, event: AlertEvent) -> None:
        icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(event.severity.value, "📢")
        text = f"{icon} *Orchesis Alert*\n*{event.title}*\n{event.details}\n"
        if event.session_id:
            text += f"Session: `{event.session_id}`\n"
        if event.request_cost > 0:
            text += f"Cost: ${event.request_cost:.4f}\n"
        text += f"Type: {event.event_type}"

        url = f"https://api.telegram.org/bot{self._config.telegram_bot_token}/sendMessage"
        payload = json.dumps(
            {
                "chat_id": self._config.telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_notification": event.severity == AlertSeverity.INFO,
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                url, data=payload, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                _ = resp.read()
            with self._lock:
                self._stats["sent"] += 1
        except Exception:
            with self._lock:
                self._stats["errors"] += 1

    def _send_webhook(self, event: AlertEvent) -> None:
        payload = json.dumps(
            {
                "severity": event.severity.value,
                "event_type": event.event_type,
                "title": event.title,
                "details": event.details,
                "timestamp": event.timestamp,
                "session_id": event.session_id,
                "agent_id": event.agent_id,
                "cost": event.request_cost,
                "extra": event.extra,
                "source": "orchesis",
            }
        ).encode("utf-8")

        headers = {"Content-Type": "application/json", **self._config.webhook_headers}
        try:
            req = urllib.request.Request(self._config.webhook_url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                _ = resp.read()
            with self._lock:
                self._stats["sent"] += 1
        except Exception:
            with self._lock:
                self._stats["errors"] += 1

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._stats)
