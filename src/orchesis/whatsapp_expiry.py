"""WhatsApp 14-day session expiry tracker.

WhatsApp sessions expire silently after 14 days.
No warning from WhatsApp. Orchesis provides pre-alerts.

Alert schedule:
- Day 12.0: WARNING - 2 days remaining
- Day 13.5: CRITICAL - 12 hours remaining
- Day 14.0+: EXPIRED
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any


class WhatsAppExpiryTracker:
    EXPIRY_DAYS = 14
    WARNING_DAYS = 12.0
    CRITICAL_DAYS = 13.5

    def __init__(self, config: dict[str, Any] | None = None):
        _ = config
        self._sessions: dict[str, dict[str, Any]] = {}
        self._alerts_sent: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def register_session(self, session_id: str, started_at: str | None = None) -> dict[str, Any]:
        """Register new WhatsApp session."""
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            session = {
                "session_id": session_id,
                "started_at": started_at or now,
                "registered_at": now,
                "status": "active",
            }
            self._sessions[session_id] = session
            self._alerts_sent[session_id] = []
            return dict(session)

    def get_age_days(self, session_id: str) -> float:
        """Get session age in days."""
        with self._lock:
            session = self._sessions.get(session_id)
        if not isinstance(session, dict):
            return 0.0
        started = datetime.fromisoformat(str(session["started_at"]))
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - started).total_seconds() / 86400.0

    def check_expiry(self, session_id: str) -> dict[str, Any]:
        """Check session expiry status."""
        age = self.get_age_days(session_id)
        days_remaining = max(0.0, self.EXPIRY_DAYS - age)

        if age >= self.EXPIRY_DAYS:
            status = "EXPIRED"
            severity = "CRITICAL"
            message = "WhatsApp session has expired - reconnect required"
        elif age >= self.CRITICAL_DAYS:
            status = "CRITICAL"
            severity = "CRITICAL"
            message = f"WhatsApp session expires in {days_remaining * 24:.1f} hours"
        elif age >= self.WARNING_DAYS:
            status = "WARNING"
            severity = "HIGH"
            message = f"WhatsApp session expires in {days_remaining:.1f} days"
        else:
            status = "OK"
            severity = "INFO"
            message = f"Session healthy - {days_remaining:.1f} days remaining"

        return {
            "session_id": session_id,
            "age_days": round(age, 2),
            "days_remaining": round(days_remaining, 2),
            "status": status,
            "severity": severity,
            "message": message,
            "should_alert": status in ("WARNING", "CRITICAL", "EXPIRED"),
        }

    def check_all_sessions(self) -> list[dict[str, Any]]:
        """Check all registered sessions."""
        with self._lock:
            session_ids = list(self._sessions.keys())
        return [self.check_expiry(session_id) for session_id in session_ids]

    def get_sessions_needing_alert(self) -> list[dict[str, Any]]:
        """Return sessions that need alerts and haven't been alerted yet."""
        results: list[dict[str, Any]] = []
        for check in self.check_all_sessions():
            if not check["should_alert"]:
                continue
            session_id = str(check["session_id"])
            status = str(check["status"])
            with self._lock:
                already_sent = list(self._alerts_sent.get(session_id, []))
            if status not in already_sent:
                results.append(check)
                with self._lock:
                    self._alerts_sent.setdefault(session_id, []).append(status)
        return results

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            sessions = list(self._sessions.values())
        checks = [self.check_expiry(str(session["session_id"])) for session in sessions]
        return {
            "total_sessions": len(sessions),
            "expired": sum(1 for check in checks if check["status"] == "EXPIRED"),
            "critical": sum(1 for check in checks if check["status"] == "CRITICAL"),
            "warning": sum(1 for check in checks if check["status"] == "WARNING"),
            "healthy": sum(1 for check in checks if check["status"] == "OK"),
        }
