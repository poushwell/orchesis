"""Spend-rate anomaly detection for proxy-level cost protection."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Any


@dataclass
class SpendWindow:
    """Tracks spending within a rolling time window."""

    window_seconds: int
    max_spend: float
    entries: list[tuple[float, float]] = field(default_factory=list)


@dataclass
class SpendRateResult:
    allowed: bool
    reason: str
    current_rate: float
    window_spend: float
    window_limit: float
    cooldown_until: float


class SpendRateDetector:
    """Detect abnormal spend velocity and apply temporary pauses."""

    def __init__(
        self,
        windows: list[SpendWindow] | None = None,
        spike_multiplier: float = 5.0,
        heartbeat_cost_threshold: float = 0.10,
        pause_seconds: int = 300,
    ) -> None:
        self._windows = windows or [
            SpendWindow(window_seconds=300, max_spend=2.0),
            SpendWindow(window_seconds=3600, max_spend=5.0),
        ]
        self._spike_multiplier = max(1.0, float(spike_multiplier))
        self._heartbeat_cost_threshold = max(0.0, float(heartbeat_cost_threshold))
        self._pause_seconds = max(1, int(pause_seconds))
        self._lock = threading.Lock()
        self._events: list[tuple[float, float]] = []
        self._paused_until: float = 0.0
        self._last_reason: str = ""
        self._stats = {
            "pauses": 0,
            "total_spend_tracked": 0.0,
            "prevented_spend": 0.0,
        }

    @staticmethod
    def _prune_entries(entries: list[tuple[float, float]], now: float, window_seconds: int) -> list[tuple[float, float]]:
        cutoff = now - float(max(1, int(window_seconds)))
        return [item for item in entries if item[0] >= cutoff]

    @staticmethod
    def _sum_entries(entries: list[tuple[float, float]]) -> float:
        return float(sum(amount for _, amount in entries))

    def record_spend(self, amount: float, timestamp: float | None = None) -> None:
        safe_amount = float(amount) if isinstance(amount, int | float) else 0.0
        if safe_amount <= 0.0:
            return
        now = float(timestamp) if isinstance(timestamp, int | float) else time.monotonic()
        with self._lock:
            self._events.append((now, safe_amount))
            for window in self._windows:
                window.entries.append((now, safe_amount))
            self._stats["total_spend_tracked"] += safe_amount

    def _current_rate_locked(self, now: float) -> float:
        if not self._events:
            return 0.0
        recent_window = min((w.window_seconds for w in self._windows), default=300)
        recent_entries = self._prune_entries(self._events, now, recent_window)
        spend = self._sum_entries(recent_entries)
        minutes = max(1e-6, float(recent_window) / 60.0)
        return spend / minutes

    def _pause_locked(self, now: float, reason: str, prevented_spend: float) -> float:
        self._paused_until = max(self._paused_until, now + float(self._pause_seconds))
        self._last_reason = reason
        self._stats["pauses"] += 1
        self._stats["prevented_spend"] += max(0.0, float(prevented_spend))
        return self._paused_until

    def check(self) -> SpendRateResult:
        now = time.monotonic()
        with self._lock:
            self._events = self._prune_entries(self._events, now, max((w.window_seconds for w in self._windows), default=3600))
            for window in self._windows:
                window.entries = self._prune_entries(window.entries, now, window.window_seconds)

            if now < self._paused_until:
                return SpendRateResult(
                    allowed=False,
                    reason=self._last_reason or "paused",
                    current_rate=self._current_rate_locked(now),
                    window_spend=0.0,
                    window_limit=0.0,
                    cooldown_until=self._paused_until,
                )

            # Mode 1: hard caps for rolling windows.
            for window in self._windows:
                spend = self._sum_entries(window.entries)
                if spend > float(window.max_spend):
                    reason = f"{window.window_seconds}s window"
                    paused_until = self._pause_locked(now, reason, spend - float(window.max_spend))
                    return SpendRateResult(
                        allowed=False,
                        reason=reason,
                        current_rate=spend / max(1e-6, float(window.window_seconds) / 60.0),
                        window_spend=spend,
                        window_limit=float(window.max_spend),
                        cooldown_until=paused_until,
                    )

            # Mode 2: spike detection versus baseline.
            if len(self._events) >= 4:
                short_window = min((w.window_seconds for w in self._windows), default=300)
                long_window = max((w.window_seconds for w in self._windows), default=3600)
                short_entries = self._prune_entries(self._events, now, short_window)
                long_entries = self._prune_entries(self._events, now, long_window)
                short_spend = self._sum_entries(short_entries)
                long_spend = self._sum_entries(long_entries)
                short_rate = short_spend / max(1e-6, float(short_window) / 60.0)
                long_rate = long_spend / max(1e-6, float(long_window) / 60.0)
                if long_rate > 0.0 and short_rate > long_rate * self._spike_multiplier:
                    paused_until = self._pause_locked(now, "spike", short_spend)
                    return SpendRateResult(
                        allowed=False,
                        reason="spike",
                        current_rate=short_rate,
                        window_spend=short_spend,
                        window_limit=max(0.0, long_rate * self._spike_multiplier * (float(short_window) / 60.0)),
                        cooldown_until=paused_until,
                    )

            return SpendRateResult(
                allowed=True,
                reason="ok",
                current_rate=self._current_rate_locked(now),
                window_spend=0.0,
                window_limit=0.0,
                cooldown_until=0.0,
            )

    def is_heartbeat_request(self, body: dict[str, Any]) -> bool:
        if not isinstance(body, dict):
            return False
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return False
        text_chunks: list[str] = []
        for msg in messages[:4]:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                text_chunks.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        maybe_text = item.get("text")
                        if isinstance(maybe_text, str):
                            text_chunks.append(maybe_text)
        text = "\n".join(text_chunks).lower()
        if not text.strip():
            return False
        primary_markers = (
            "heartbeat",
            "heartbeat_ok",
            "read heartbeat.md",
        )
        secondary_markers = (
            "schedule",
            "cron",
            "every 30",
            "keepalive",
            "health check",
        )
        if any(marker in text for marker in primary_markers):
            return True
        if len(messages) <= 2 and any(marker in text for marker in secondary_markers):
            return True
        return False

    def is_heartbeat_cost_high(self, body: dict[str, Any], cost: float) -> bool:
        return self.is_heartbeat_request(body) and float(cost) > self._heartbeat_cost_threshold

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "pauses": int(self._stats["pauses"]),
                "total_spend_tracked": round(float(self._stats["total_spend_tracked"]), 6),
                "prevented_spend": round(float(self._stats["prevented_spend"]), 6),
                "paused_until": float(self._paused_until),
                "spike_multiplier": float(self._spike_multiplier),
                "heartbeat_cost_threshold": float(self._heartbeat_cost_threshold),
                "pause_seconds": int(self._pause_seconds),
                "windows": [
                    {
                        "seconds": int(window.window_seconds),
                        "max_spend": float(window.max_spend),
                        "events": int(len(window.entries)),
                    }
                    for window in self._windows
                ],
            }
