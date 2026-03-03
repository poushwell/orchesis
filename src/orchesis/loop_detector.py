"""Detect and break agent tool call loops."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class LoopEvent:
    tool_name: str
    repetitions: int
    total_cost_wasted: float
    action_taken: str
    timestamp: float


class LoopDetector:
    """Detects repetitive tool call patterns that waste money."""

    def __init__(
        self,
        warn_threshold: int = 5,
        block_threshold: int = 10,
        window_seconds: float = 300.0,
        similarity_check: bool = True,
    ):
        self._lock = threading.Lock()
        self._warn_threshold = int(warn_threshold)
        self._block_threshold = int(block_threshold)
        self._window = float(window_seconds)
        self._similarity_check = bool(similarity_check)
        self._recent_calls: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._events: list[LoopEvent] = []
        self._total_saved: float = 0.0

    def _hash_params(self, params: dict[str, Any]) -> str:
        try:
            normalized = json.dumps(params, sort_keys=True, default=str)
            return hashlib.md5(normalized.encode("utf-8")).hexdigest()  # noqa: S324
        except Exception:
            return "unhashable"

    def check(self, tool_name: str, params: dict[str, Any], cost_per_call: float = 0.001) -> dict[str, Any]:
        now = time.time()
        params_hash = self._hash_params(params if isinstance(params, dict) else {})
        with self._lock:
            active = [
                (ts, h)
                for ts, h in self._recent_calls[tool_name]
                if (now - ts) < self._window
            ]
            active.append((now, params_hash))
            self._recent_calls[tool_name] = active

            if self._similarity_check:
                repetitions = sum(1 for _ts, item_hash in active if item_hash == params_hash)
            else:
                repetitions = len(active)

            if repetitions >= self._block_threshold:
                saved = float(cost_per_call)
                self._total_saved += saved
                self._events.append(
                    LoopEvent(
                        tool_name=tool_name,
                        repetitions=repetitions,
                        total_cost_wasted=float(repetitions) * float(cost_per_call),
                        action_taken="blocked",
                        timestamp=now,
                    )
                )
                return {
                    "action": "block",
                    "repetitions": repetitions,
                    "message": (
                        f"Loop detected: {tool_name} called {repetitions} times in "
                        f"{int(self._window)}s with similar params. Blocked to prevent waste."
                    ),
                    "saved_usd": saved,
                }

            if repetitions >= self._warn_threshold:
                self._events.append(
                    LoopEvent(
                        tool_name=tool_name,
                        repetitions=repetitions,
                        total_cost_wasted=float(repetitions) * float(cost_per_call),
                        action_taken="warned",
                        timestamp=now,
                    )
                )
                return {
                    "action": "warn",
                    "repetitions": repetitions,
                    "message": (
                        f"Warning: {tool_name} called {repetitions} times in "
                        f"{int(self._window)}s. You may be in a loop."
                    ),
                    "saved_usd": 0.0,
                }

        return {"action": "allow", "repetitions": 1, "message": "", "saved_usd": 0.0}

    @property
    def total_saved(self) -> float:
        with self._lock:
            return float(self._total_saved)

    @property
    def events(self) -> list[LoopEvent]:
        with self._lock:
            return list(self._events)

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            warned = sum(1 for item in self._events if item.action_taken == "warned")
            blocked = sum(1 for item in self._events if item.action_taken == "blocked")
            return {
                "total_saved_usd": round(self._total_saved, 4),
                "total_loops_detected": len(self._events),
                "loops_warned": warned,
                "loops_blocked": blocked,
            }

