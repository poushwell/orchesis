"""Shannon-Hartley Context Capacity (H33B).

C_eff = B_eff x I(context; response | task)

Effective channel capacity for context -> response information transfer.
H33B: generalization of original H33 beyond AWGN assumption.

Original H33 (special case): uniform token distribution + AWGN.
H33B (general): C_eff = B_eff x I(X;Y|Z) via conditional mutual information.
"""

from __future__ import annotations

import math
import threading
from typing import Any


class ShannonHartleyCalculator:
    """Context channel capacity via Shannon-Hartley theorem."""

    def __init__(self, config: dict | None = None):
        _ = config
        self._measurements: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def compute_entropy(self, probs: list[float]) -> float:
        """H(X) = -sum(p * log2(p))."""
        return -sum(float(p) * math.log2(float(p)) for p in probs if float(p) > 0.0)

    def compute_channel_capacity(
        self, context_entropy: float, response_entropy: float, noise: float = 0.1
    ) -> dict[str, float]:
        """C = B * log2(1 + S/N) with effective bound by response entropy."""
        snr = max(0.01, (float(context_entropy) - float(noise)) / max(0.01, float(noise)))
        capacity = float(context_entropy) * math.log2(1.0 + snr)
        c_eff = min(capacity, float(response_entropy))
        utilization = c_eff / max(0.01, capacity)
        return {
            "bandwidth": round(float(context_entropy), 4),
            "snr": round(float(snr), 4),
            "capacity": round(float(capacity), 4),
            "c_eff": round(float(c_eff), 4),
            "utilization": round(float(utilization), 4),
            "noise": round(float(noise), 4),
        }

    def compute_conditional_mutual_info(
        self, context_tokens: list[int], response_tokens: list[int]
    ) -> float:
        """I(context; response) approximation via token overlap."""
        if not context_tokens or not response_tokens:
            return 0.0
        ctx_set = set(int(item) for item in context_tokens)
        resp_set = set(int(item) for item in response_tokens)
        overlap = len(ctx_set & resp_set)
        union = len(ctx_set | resp_set)
        if union == 0:
            return 0.0
        jaccard = float(overlap) / float(union)
        if jaccard >= 1.0:
            return 10.0
        return round(-math.log2(max(0.01, 1.0 - jaccard)), 4)

    def record_measurement(self, session_id: str, capacity: dict[str, float]) -> None:
        with self._lock:
            self._measurements.append({"session_id": str(session_id), **dict(capacity)})
            if len(self._measurements) > 10_000:
                self._measurements = self._measurements[-10_000:]

    def get_stats(self) -> dict[str, float | int]:
        with self._lock:
            if not self._measurements:
                return {"measurements": 0}
            rows = list(self._measurements)
        avg_util = sum(float(item.get("utilization", 0.0)) for item in rows) / float(len(rows))
        avg_capacity = sum(float(item.get("capacity", 0.0)) for item in rows) / float(len(rows))
        return {
            "measurements": len(rows),
            "avg_utilization": round(avg_util, 4),
            "avg_capacity": round(avg_capacity, 4),
        }
