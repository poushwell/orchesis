"""Cost velocity tracking utilities."""

from __future__ import annotations

import threading
import time


class CostVelocity:
    """Track spending rate, not just total spend."""

    def __init__(self):
        self._costs: list[tuple[float, float]] = []
        self._lock = threading.Lock()

    @staticmethod
    def _now() -> float:
        return time.time()

    def _prune(self, now: float) -> None:
        cutoff = now - (7 * 24 * 3600)
        self._costs = [item for item in self._costs if item[0] >= cutoff]

    def record(self, cost_usd: float) -> None:
        amount = float(cost_usd or 0.0)
        if amount <= 0.0:
            return
        with self._lock:
            now = self._now()
            self._costs.append((now, amount))
            self._prune(now)

    def current_rate_per_hour(self) -> float:
        with self._lock:
            now = self._now()
            self._prune(now)
            cutoff = now - (15 * 60)
            recent_cost = sum(cost for ts, cost in self._costs if ts >= cutoff)
        return float(recent_cost * 4.0)

    def _avg_7d_rate(self) -> float:
        with self._lock:
            now = self._now()
            self._prune(now)
            total = sum(cost for _, cost in self._costs)
        return float(total / 168.0) if total > 0 else 0.0

    def projection_24h(self) -> float:
        return float(self.current_rate_per_hour() * 24.0)

    def is_anomalous(self, threshold_multiplier: float = 3.0) -> bool:
        current = self.current_rate_per_hour()
        baseline = self._avg_7d_rate()
        with self._lock:
            sample_count = len(self._costs)
        if baseline <= 0.0 or sample_count < 5:
            return False
        return current > (float(threshold_multiplier) * baseline)

    def get_stats(self) -> dict:
        current = self.current_rate_per_hour()
        avg_7d = self._avg_7d_rate()
        return {
            "current_rate_per_hour": round(current, 6),
            "projection_24h": round(current * 24.0, 6),
            "avg_7d_rate": round(avg_7d, 6),
            "is_anomalous": self.is_anomalous(),
        }

