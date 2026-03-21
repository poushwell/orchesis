"""WebChat chat.inject — inject alerts directly into WebChat stream.

No OpenClaw changes required.
Orchesis intercepts WebChat LLM responses and injects alert banners
as system messages before the response content.

Use cases:
- Security alert: "⚠️ Prompt injection detected in this session"
- Budget alert: "💸 You've used 80% of daily budget"
- Context alert: "📊 Context quality degraded — responses may be less accurate"
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any


class WebChatInjector:
    ALERT_TEMPLATES = {
        "security": "⚠️ Security Alert: {message}",
        "budget": "💸 Budget Alert: {message}",
        "context": "📊 Context Alert: {message}",
        "expiry": "⏰ Session Alert: {message}",
        "zenity": "🔴 CRITICAL: {message}",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self._pending: dict[str, list[dict[str, Any]]] = {}
        self._injected: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def queue_alert(self, session_id: str, alert_type: str, message: str) -> dict[str, Any]:
        """Queue an alert for injection into WebChat stream."""
        template = self.ALERT_TEMPLATES.get(alert_type, "ℹ️ {message}")
        formatted = template.format(message=message)
        alert: dict[str, Any] = {
            "session_id": session_id,
            "type": alert_type,
            "message": formatted,
            "raw_message": message,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "injected": False,
        }
        with self._lock:
            if session_id not in self._pending:
                self._pending[session_id] = []
            self._pending[session_id].append(alert)
        return alert

    def get_pending(self, session_id: str) -> list[dict[str, Any]]:
        """Get pending alerts for session — called before response delivery."""
        with self._lock:
            alerts = self._pending.pop(session_id, [])
        for alert in alerts:
            alert["injected"] = True
            alert["injected_at"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._injected.extend(alerts)
            if len(self._injected) > 10000:
                self._injected = self._injected[-10000:]
        return alerts

    def inject_into_response(self, session_id: str, response: dict[str, Any]) -> dict[str, Any]:
        """Prepend alerts to response content if any pending."""
        alerts = self.get_pending(session_id)
        if not alerts or not self.enabled:
            return response
        alert_text = "\n".join(str(item.get("message", "")) for item in alerts)
        content = response.get("content", "")
        response["content"] = f"{alert_text}\n\n{content}" if content else alert_text
        response["_alerts_injected"] = len(alerts)
        return response

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            pending_count = sum(len(items) for items in self._pending.values())
            injected_count = len(self._injected)
            active_sessions = len(self._pending)
        return {
            "enabled": self.enabled,
            "pending_alerts": pending_count,
            "total_injected": injected_count,
            "active_sessions": active_sessions,
        }
