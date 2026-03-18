"""Priority assignment and queue management for proxy requests."""

from __future__ import annotations

import threading
import time
from typing import Any


class RequestPrioritizer:
    """Assigns priority to requests for queue management."""

    MAX_ENTRIES = 10_000

    PRIORITY_LEVELS = {
        "critical": 0,  # system prompts, safety checks
        "high": 1,  # user-facing requests
        "normal": 2,  # background tasks
        "low": 3,  # batch operations
        "bulk": 4,  # non-urgent bulk
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        default = str(cfg.get("default", "normal")).strip().lower()
        self.default_priority = default if default in self.PRIORITY_LEVELS else "normal"
        self._queue: list[dict[str, Any]] = []
        self._rate_limits: dict[str, float] = {}
        self._last_emit_ts: dict[str, float] = {}
        self._served_timestamps: list[float] = []
        self._lock = threading.Lock()

    @staticmethod
    def _extract_text(payload: dict[str, Any]) -> str:
        messages = payload.get("messages")
        if isinstance(messages, list):
            parts: list[str] = []
            for item in messages:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if isinstance(content, str):
                    parts.append(content)
            return " ".join(parts)
        content = payload.get("content")
        if isinstance(content, str):
            return content
        return ""

    def assign_priority(self, request: dict) -> str:
        """Assign priority based on request characteristics."""
        if not isinstance(request, dict):
            return self.default_priority
        text = self._extract_text(request).lower()
        if any(token in text for token in ("system prompt", "safety", "guardrail", "policy check")):
            return "critical"
        if bool(request.get("bulk")) or int(request.get("batch_size", 0) or 0) >= 100:
            return "bulk"
        if bool(request.get("background")) or bool(request.get("async")):
            return "low"
        role = str(request.get("role", "")).lower()
        if role == "user" or "user" in text:
            return "high"
        return self.default_priority

    def enqueue(self, request: dict, priority: str | None = None) -> int:
        """Add to priority queue. Returns queue position."""
        chosen = str(priority or self.assign_priority(request)).strip().lower()
        if chosen not in self.PRIORITY_LEVELS:
            chosen = self.default_priority
        with self._lock:
            rps = float(self._rate_limits.get(chosen, 0.0) or 0.0)
            now = time.time()
            if rps > 0.0:
                min_interval = 1.0 / rps
                last = float(self._last_emit_ts.get(chosen, 0.0) or 0.0)
                if last > 0.0 and (now - last) < min_interval:
                    return -1
                self._last_emit_ts[chosen] = now
            row = {
                "request": dict(request) if isinstance(request, dict) else {},
                "priority": chosen,
                "queued_at": now,
            }
            self._queue.append(row)
            if len(self._queue) > self.MAX_ENTRIES:
                # Evict oldest queued entries to keep memory bounded.
                overflow = len(self._queue) - self.MAX_ENTRIES
                if overflow > 0:
                    del self._queue[:overflow]
            # Order by priority rank then queue time.
            self._queue.sort(
                key=lambda item: (
                    int(self.PRIORITY_LEVELS.get(str(item.get("priority", self.default_priority)), 99)),
                    float(item.get("queued_at", 0.0) or 0.0),
                )
            )
            for idx, item in enumerate(self._queue):
                if item is row:
                    return idx
            return max(0, len(self._queue) - 1)

    def dequeue(self) -> dict | None:
        """Get next request by priority."""
        with self._lock:
            if not self._queue:
                return None
            row = self._queue.pop(0)
            now = time.time()
            self._served_timestamps.append(now)
            cutoff = now - 60.0
            self._served_timestamps = [ts for ts in self._served_timestamps if ts >= cutoff]
            if len(self._served_timestamps) > self.MAX_ENTRIES:
                self._served_timestamps = self._served_timestamps[-self.MAX_ENTRIES :]
            request = row.get("request")
            return dict(request) if isinstance(request, dict) else {}

    def get_queue_stats(self) -> dict:
        with self._lock:
            counts = {key: 0 for key in self.PRIORITY_LEVELS.keys()}
            now = time.time()
            waits = []
            for item in self._queue:
                pr = str(item.get("priority", self.default_priority))
                if pr in counts:
                    counts[pr] += 1
                queued_at = float(item.get("queued_at", now) or now)
                waits.append(max(0.0, (now - queued_at) * 1000.0))
            cutoff = now - 60.0
            served = [ts for ts in self._served_timestamps if ts >= cutoff]
            self._served_timestamps = served
            avg_wait = (sum(waits) / float(len(waits))) if waits else 0.0
            return {
                "total": int(len(self._queue)),
                "by_priority": counts,
                "avg_wait_ms": float(round(avg_wait, 3)),
                "throughput_per_min": float(len(served)),
            }

    def set_rate_limit(self, priority: str, rps: float) -> None:
        """Set requests-per-second limit per priority level."""
        key = str(priority or "").strip().lower()
        if key not in self.PRIORITY_LEVELS:
            return
        with self._lock:
            self._rate_limits[key] = max(0.0, float(rps or 0.0))
