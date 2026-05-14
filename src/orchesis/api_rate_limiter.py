"""Per-client API rate limiting."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from math import ceil
from typing import Any


class ApiRateLimiter:
    """Per-client rate limiting for API server."""

    def __init__(self, config: dict | None = None):
        self.requests_per_minute = 60
        self.burst = 10
        self._clients: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.configure(config)

    def configure(self, config: dict | None = None) -> None:
        """Update limiter configuration without resetting counters."""
        cfg = config if isinstance(config, dict) else {}
        with self._lock:
            self.requests_per_minute = max(1, int(cfg.get("requests_per_minute", 60)))
            self.burst = max(0, int(cfg.get("burst", 10)))

    @staticmethod
    def _now() -> float:
        return float(time.time())

    @staticmethod
    def _iso(ts: float) -> str:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()

    def _record_for(self, client_id: str, now: float) -> dict[str, Any]:
        key = str(client_id or "unknown")
        row = self._clients.get(key)
        if not isinstance(row, dict):
            row = {
                "window_started_at": now,
                "count": 0,
                "total": 0,
                "blocked": 0,
                "last_seen": now,
            }
            self._clients[key] = row
            return row
        window_started_at = float(row.get("window_started_at", now) or now)
        if (now - window_started_at) >= 60.0:
            row["window_started_at"] = now
            row["count"] = 0
        row["last_seen"] = now
        return row

    def check(self, client_id: str) -> dict:
        """Check if client is within limits."""
        now = self._now()
        limit = int(self.requests_per_minute + self.burst)
        with self._lock:
            row = self._record_for(client_id, now)
            used = int(row.get("count", 0) or 0)
            window_started_at = float(row.get("window_started_at", now) or now)
            reset_ts = window_started_at + 60.0
            allowed = used < limit
            remaining = max(0, limit - used)
            retry_after = None if allowed else max(1, int(ceil(max(0.0, reset_ts - now))))
            return {
                "allowed": allowed,
                "remaining": remaining,
                "reset_at": self._iso(reset_ts),
                "retry_after": retry_after,
            }

    def record(self, client_id: str) -> None:
        """Record a request from client."""
        now = self._now()
        with self._lock:
            row = self._record_for(client_id, now)
            row["count"] = int(row.get("count", 0) or 0) + 1
            row["total"] = int(row.get("total", 0) or 0) + 1
            row["last_seen"] = now

    def note_blocked(self, client_id: str) -> None:
        """Increment blocked counter for client."""
        now = self._now()
        with self._lock:
            row = self._record_for(client_id, now)
            row["blocked"] = int(row.get("blocked", 0) or 0) + 1
            row["last_seen"] = now

    def get_stats(self) -> dict:
        """Per-client stats."""
        with self._lock:
            rows: dict[str, dict[str, Any]] = {}
            for client_id, row in self._clients.items():
                used = int(row.get("count", 0) or 0)
                blocked = int(row.get("blocked", 0) or 0)
                total = int(row.get("total", 0) or 0)
                started = float(row.get("window_started_at", self._now()) or self._now())
                last_seen = float(row.get("last_seen", started) or started)
                rows[str(client_id)] = {
                    "used_in_window": used,
                    "total": total,
                    "blocked": blocked,
                    "remaining": max(0, int(self.requests_per_minute + self.burst) - used),
                    "window_started_at": self._iso(started),
                    "last_seen": self._iso(last_seen),
                }
            return {
                "requests_per_minute": int(self.requests_per_minute),
                "burst": int(self.burst),
                "clients": rows,
            }

    def reset(self, client_id: str) -> None:
        """Reset client limits (admin use)."""
        key = str(client_id or "")
        with self._lock:
            self._clients.pop(key, None)
