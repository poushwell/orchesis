"""Thread-safe circuit breaker for upstream reliability protection."""

from __future__ import annotations

from collections import deque
import threading
import time
from typing import Any


class CircuitBreaker:
    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        *,
        enabled: bool = False,
        error_threshold: int = 5,
        window_seconds: int = 60,
        cooldown_seconds: int = 30,
        max_cooldown_seconds: int = 300,
        half_open_max_requests: int = 1,
        fallback_status: int = 503,
        fallback_message: str = "Service temporarily unavailable. Circuit breaker is open.",
    ) -> None:
        self._enabled = bool(enabled)
        self._error_threshold = max(1, int(error_threshold))
        self._window_seconds = max(1.0, float(window_seconds))
        self._base_cooldown = max(1.0, float(cooldown_seconds))
        self._max_cooldown = max(self._base_cooldown, float(max_cooldown_seconds))
        self._half_open_max_requests = max(1, int(half_open_max_requests))
        self.fallback_status = int(fallback_status)
        self.fallback_message = str(fallback_message)

        self._lock = threading.Lock()
        self._state = self.STATE_CLOSED
        self._failures: deque[float] = deque(maxlen=self._error_threshold)
        self._opened_at: float | None = None
        self._current_cooldown = self._base_cooldown
        self._half_open_requests = 0
        self._trip_count = 0
        self._last_failure: float | None = None

    def _now(self) -> float:
        return time.monotonic()

    def _prune_failures(self, now: float) -> None:
        while self._failures and (now - self._failures[0]) > self._window_seconds:
            self._failures.popleft()

    def _open(self, now: float, *, escalate_backoff: bool) -> None:
        if escalate_backoff:
            self._current_cooldown = min(self._max_cooldown, self._current_cooldown * 2.0)
        else:
            self._current_cooldown = max(self._base_cooldown, self._current_cooldown)
        self._state = self.STATE_OPEN
        self._opened_at = now
        self._half_open_requests = 0
        self._trip_count += 1

    def should_allow(self) -> bool:
        if not self._enabled:
            return True
        now = self._now()
        with self._lock:
            if self._state == self.STATE_OPEN:
                opened_at = self._opened_at if self._opened_at is not None else now
                if (now - opened_at) >= self._current_cooldown:
                    self._state = self.STATE_HALF_OPEN
                    self._half_open_requests = 0
                else:
                    return False

            if self._state == self.STATE_HALF_OPEN:
                if self._half_open_requests >= self._half_open_max_requests:
                    return False
                self._half_open_requests += 1
                return True

            return True

    def record_success(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._state = self.STATE_CLOSED
            self._failures.clear()
            self._opened_at = None
            self._half_open_requests = 0
            self._current_cooldown = self._base_cooldown

    def record_failure(self) -> None:
        if not self._enabled:
            return
        now = self._now()
        with self._lock:
            self._last_failure = now
            if self._state == self.STATE_HALF_OPEN:
                self._open(now, escalate_backoff=True)
                return

            self._prune_failures(now)
            self._failures.append(now)
            if self._state == self.STATE_CLOSED and len(self._failures) >= self._error_threshold:
                self._open(now, escalate_backoff=False)

    def get_state(self) -> str:
        with self._lock:
            return self._state

    def get_stats(self) -> dict[str, Any]:
        now = self._now()
        with self._lock:
            self._prune_failures(now)
            cooldown_remaining = 0.0
            if self._state == self.STATE_OPEN and self._opened_at is not None:
                cooldown_remaining = max(0.0, self._current_cooldown - (now - self._opened_at))
            return {
                "state": self._state,
                "error_count": len(self._failures),
                "last_failure": self._last_failure,
                "cooldown_remaining": round(cooldown_remaining, 4),
                "trip_count": self._trip_count,
            }

    def reset(self) -> None:
        with self._lock:
            self._state = self.STATE_CLOSED
            self._failures.clear()
            self._opened_at = None
            self._half_open_requests = 0
            self._trip_count = 0
            self._last_failure = None
            self._current_cooldown = self._base_cooldown
