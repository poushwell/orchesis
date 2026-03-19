"""Kolmogorov Importance for context messages.

H36: Kolmogorov complexity as importance proxy.
UCI-K duality: K(message) correlates with UCI score.

Preliminary result: DENY_k > ALLOW_k, r=0.096.
Approximate K via compression ratio (lossless).
"""

from __future__ import annotations

import threading
import zlib
from typing import Any


class KolmogorovImportance:
    """Approximate Kolmogorov complexity via compression."""

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.correlation_threshold = float(cfg.get("rho_threshold", 0.4))
        self._measurements: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def estimate_k(self, text: str) -> float:
        """Estimate K(text) via compression ratio.

        K_approx = compressed_size / original_size
        High K = high complexity = potentially more important.
        """
        if not text:
            return 0.0
        encoded = str(text).encode("utf-8")
        compressed = zlib.compress(encoded, level=9)
        return float(len(compressed)) / float(max(1, len(encoded)))

    def compute_importance(self, message: dict) -> dict[str, Any]:
        """Compute Kolmogorov-based importance score."""
        payload = message if isinstance(message, dict) else {}
        content = payload.get("content", "")
        if isinstance(content, list):
            content = " ".join(part.get("text", "") for part in content if isinstance(part, dict))

        k_score = self.estimate_k(str(content))
        role = str(payload.get("role", "user") or "user")

        role_weight = {"system": 1.3, "assistant": 1.1, "user": 1.0}.get(role, 1.0)
        importance = min(1.0, k_score * role_weight)

        return {
            "k_score": round(k_score, 4),
            "importance": round(importance, 4),
            "role": role,
            "high_complexity": bool(k_score > 0.7),
        }

    def record_correlation(self, k_score: float, uci_score: float, decision: str) -> None:
        """Record K-UCI correlation data point."""
        with self._lock:
            self._measurements.append(
                {
                    "k": float(k_score),
                    "uci": float(uci_score),
                    "decision": str(decision),
                }
            )
            if len(self._measurements) > 10_000:
                self._measurements = self._measurements[-10_000:]

    def compute_rho(self) -> float:
        """Pearson correlation between K and UCI scores."""
        with self._lock:
            data = list(self._measurements)

        if len(data) < 3:
            return 0.0

        ks = [float(item["k"]) for item in data]
        ucis = [float(item["uci"]) for item in data]

        n = len(ks)
        mean_k = sum(ks) / float(n)
        mean_uci = sum(ucis) / float(n)

        num = sum((k - mean_k) * (u - mean_uci) for k, u in zip(ks, ucis))
        den_k = sum((k - mean_k) ** 2 for k in ks) ** 0.5
        den_uci = sum((u - mean_uci) ** 2 for u in ucis) ** 0.5

        if den_k == 0.0 or den_uci == 0.0:
            return 0.0
        return round(float(num) / float(den_k * den_uci), 4)

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            n = len(self._measurements)
        rho = self.compute_rho() if n >= 3 else None
        return {
            "measurements": int(n),
            "rho": rho,
            "rho_significant": bool((rho or 0.0) > self.correlation_threshold),
            "preliminary_result": "DENY_k > ALLOW_k, r=0.096",
        }
