"""Immune Memory - long-term threat pattern retention.

B-cell memory analogy: after first exposure to threat,
faster and stronger response on re-exposure.

Applied: proxy remembers threat patterns,
accelerates detection on repeat attacks.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone


class ImmuneMemory:
    """Long-term threat pattern memory with accelerated recall."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.memory_capacity = int(cfg.get("capacity", 10000))
        self.recall_boost = float(cfg.get("recall_boost", 2.0))
        self._memory: dict[str, dict] = {}
        self._exposures: dict[str, int] = {}
        self._lock = threading.Lock()

    def _pattern_hash(self, pattern: str) -> str:
        return hashlib.sha256(str(pattern).encode()).hexdigest()[:16]

    def expose(self, threat_pattern: str, severity: float) -> dict:
        """First or repeated exposure to threat pattern."""
        key = self._pattern_hash(threat_pattern)

        with self._lock:
            is_memory = key in self._memory
            self._exposures[key] = self._exposures.get(key, 0) + 1
            exposures = self._exposures[key]

            # Memory cell strength grows with exposures.
            memory_strength = min(1.0, exposures * 0.2)
            recall_speed = self.recall_boost ** min(exposures - 1, 5)

            self._memory[key] = {
                "pattern_hash": key,
                "severity": float(severity),
                "exposures": exposures,
                "memory_strength": round(memory_strength, 4),
                "recall_speed": round(recall_speed, 4),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }

            # Evict oldest if over capacity.
            if len(self._memory) > self.memory_capacity:
                oldest = sorted(self._memory.items(), key=lambda x: x[1]["last_seen"])[0][0]
                del self._memory[oldest]

            return {
                "pattern_hash": key,
                "primary_response": not is_memory,
                "memory_response": is_memory,
                "memory_strength": memory_strength,
                "recall_speed": recall_speed,
                "exposures": exposures,
            }

    def recall(self, threat_pattern: str) -> dict | None:
        """Check immune memory for threat pattern."""
        key = self._pattern_hash(threat_pattern)
        with self._lock:
            return self._memory.get(key)

    def get_memory_stats(self) -> dict:
        with self._lock:
            return {
                "memory_cells": len(self._memory),
                "capacity": self.memory_capacity,
                "utilization": round(len(self._memory) / self.memory_capacity, 4),
                "recall_boost": self.recall_boost,
            }

