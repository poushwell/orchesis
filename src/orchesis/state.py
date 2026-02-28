"""State management primitives for rate limiting."""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _to_datetime_utc(timestamp: datetime | str | None) -> datetime:
    if timestamp is None:
        return datetime.now(timezone.utc)
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
    parsed = datetime.fromisoformat(timestamp)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class RateLimitTracker:
    """Thread-safe in-memory counter with optional JSONL persistence."""

    def __init__(self, persist_path: str | Path | None = ".orchesis/state.jsonl"):
        self.persist_path = Path(persist_path) if persist_path is not None else None
        self._lock = threading.Lock()
        self._events: dict[str, list[datetime]] = defaultdict(list)
        if self.persist_path is not None:
            self._load_existing()

    def _load_existing(self) -> None:
        if self.persist_path is None or not self.persist_path.exists():
            return
        for line in self.persist_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            tool = payload.get("tool")
            ts = payload.get("timestamp")
            if isinstance(tool, str) and isinstance(ts, str):
                try:
                    self._events[tool].append(_to_datetime_utc(ts))
                except ValueError:
                    continue

    def _persist(self, tool_name: str, ts: datetime) -> None:
        if self.persist_path is None:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tool": tool_name, "timestamp": ts.isoformat()}
        with self.persist_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _prune(self, tool_name: str, now: datetime, window_seconds: int) -> None:
        threshold = now - timedelta(seconds=window_seconds)
        self._events[tool_name] = [x for x in self._events[tool_name] if x >= threshold]

    def record(self, tool_name: str, timestamp: datetime | str | None = None) -> None:
        ts = _to_datetime_utc(timestamp)
        with self._lock:
            self._events[tool_name].append(ts)
            self._persist(tool_name, ts)

    def get_count(
        self,
        tool_name: str,
        window_seconds: int,
        *,
        now: datetime | str | None = None,
    ) -> int:
        current = _to_datetime_utc(now)
        with self._lock:
            self._prune(tool_name, current, window_seconds)
            return len(self._events[tool_name])

    def is_over_limit(
        self,
        tool_name: str,
        max_requests: int,
        window_seconds: int,
        *,
        now: datetime | str | None = None,
    ) -> bool:
        return self.get_count(tool_name, window_seconds, now=now) >= max_requests

    def get_tools(self) -> list[str]:
        with self._lock:
            return list(self._events.keys())
