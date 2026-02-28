"""State management primitives for rate limiting."""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GLOBAL_AGENT_ID = "__global__"


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
        self._events: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        self._spend_events: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
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
            event = payload.get("event", "rate")
            tool = payload.get("tool")
            ts = payload.get("timestamp")
            agent = payload.get("agent_id", GLOBAL_AGENT_ID)
            cost = payload.get("cost", 0.0)
            if event == "spend" and isinstance(ts, str):
                try:
                    dt = _to_datetime_utc(ts)
                    agent_id = agent if isinstance(agent, str) and agent else GLOBAL_AGENT_ID
                    numeric_cost = float(cost) if isinstance(cost, int | float) else 0.0
                    self._spend_events[agent_id].append((dt, numeric_cost))
                except ValueError:
                    continue
                continue
            if isinstance(tool, str) and isinstance(ts, str):
                try:
                    dt = _to_datetime_utc(ts)
                    agent_id = agent if isinstance(agent, str) and agent else GLOBAL_AGENT_ID
                    self._events[(agent_id, tool)].append(dt)
                    # Backward compatibility for legacy state entries carrying cost.
                    numeric_cost = float(cost) if isinstance(cost, int | float) else 0.0
                    if numeric_cost != 0.0:
                        self._spend_events[agent_id].append((dt, numeric_cost))
                except ValueError:
                    continue

    def _persist_rate(self, tool_name: str, ts: datetime, agent_id: str) -> None:
        if self.persist_path is None:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"event": "rate", "tool": tool_name, "timestamp": ts.isoformat(), "agent_id": agent_id}
        with self.persist_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _persist_spend(self, agent_id: str, ts: datetime, cost: float) -> None:
        if self.persist_path is None:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "event": "spend",
            "agent_id": agent_id,
            "timestamp": ts.isoformat(),
            "cost": cost,
        }
        with self.persist_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _prune(self, key: tuple[str, str], now: datetime, window_seconds: int) -> None:
        threshold = now - timedelta(seconds=window_seconds)
        self._events[key] = [x for x in self._events[key] if x >= threshold]

    def _prune_spend(self, agent_id: str, now: datetime, window_seconds: int) -> None:
        threshold = now - timedelta(seconds=window_seconds)
        self._spend_events[agent_id] = [
            (ts, cost) for ts, cost in self._spend_events[agent_id] if ts >= threshold
        ]

    def record(
        self,
        tool_name: str,
        timestamp: datetime | str | None = None,
        agent_id: str = GLOBAL_AGENT_ID,
    ) -> None:
        ts = _to_datetime_utc(timestamp)
        safe_agent_id = agent_id if isinstance(agent_id, str) and agent_id else GLOBAL_AGENT_ID
        with self._lock:
            key = (safe_agent_id, tool_name)
            self._events[key].append(ts)
            self._persist_rate(tool_name, ts, safe_agent_id)

    def record_spend(
        self,
        agent_id: str,
        cost: float,
        timestamp: datetime | str | None = None,
    ) -> None:
        ts = _to_datetime_utc(timestamp)
        safe_agent_id = agent_id if isinstance(agent_id, str) and agent_id else GLOBAL_AGENT_ID
        safe_cost = float(cost) if isinstance(cost, int | float) else 0.0
        with self._lock:
            self._spend_events[safe_agent_id].append((ts, safe_cost))
            self._persist_spend(safe_agent_id, ts, safe_cost)

    def get_count(
        self,
        tool_name: str,
        window_seconds: int,
        *,
        agent_id: str = GLOBAL_AGENT_ID,
        now: datetime | str | None = None,
    ) -> int:
        current = _to_datetime_utc(now)
        safe_agent_id = agent_id if isinstance(agent_id, str) and agent_id else GLOBAL_AGENT_ID
        with self._lock:
            key = (safe_agent_id, tool_name)
            self._prune(key, current, window_seconds)
            return len(self._events[key])

    def is_over_limit(
        self,
        tool_name: str,
        max_requests: int,
        window_seconds: int,
        *,
        agent_id: str = GLOBAL_AGENT_ID,
        now: datetime | str | None = None,
    ) -> bool:
        return (
            self.get_count(tool_name, window_seconds, now=now, agent_id=agent_id)
            >= max_requests
        )

    def get_agent_budget_spent(
        self,
        agent_id: str,
        window_seconds: int = 86400,
        *,
        now: datetime | str | None = None,
    ) -> float:
        current = _to_datetime_utc(now)
        safe_agent_id = agent_id if isinstance(agent_id, str) and agent_id else GLOBAL_AGENT_ID
        with self._lock:
            self._prune_spend(safe_agent_id, current, window_seconds)
            return sum(cost for _, cost in self._spend_events[safe_agent_id])

    def get_tools(self) -> list[str]:
        with self._lock:
            return sorted({tool for (_, tool) in self._events.keys()})

    def get_agents(self) -> list[str]:
        with self._lock:
            return sorted({agent for (agent, _) in self._events.keys()})
