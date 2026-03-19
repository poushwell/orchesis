"""Carnot Efficiency - theoretical ceiling for proxy efficiency.

Analogous to Carnot thermodynamic limit:
eta_max = 1 - T_cold/T_hot

For context management:
eta_proxy = semantic_value_extracted / total_tokens_processed
eta_carnot = 1 - H_min/H_max  (entropy ratio)

Theoretical maximum efficiency bounded by information theory.
"""

from __future__ import annotations

import math
import threading


class CarnotEfficiencyCalculator:
    """Theoretical efficiency ceiling for context management."""

    def __init__(self, config: dict | None = None):
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def compute_entropy(self, token_frequencies: list[int]) -> float:
        """Shannon entropy of token distribution."""
        if not token_frequencies:
            return 0.0
        total = sum(token_frequencies)
        if total == 0:
            return 0.0
        probs = [f / total for f in token_frequencies if f > 0]
        return -sum(p * math.log2(p) for p in probs)

    def compute_carnot_limit(self, h_min: float, h_max: float) -> float:
        """eta_carnot = 1 - H_min/H_max (analogous to Carnot)."""
        if h_max <= 0:
            return 0.0
        return max(0.0, min(1.0, 1.0 - h_min / h_max))

    def compute_actual_efficiency(self, session_id: str) -> dict:
        """Actual vs theoretical efficiency for session."""
        with self._lock:
            session = dict(self._sessions.get(session_id, {}))

        semantic_tokens = session.get("semantic_tokens", 0)
        total_tokens = session.get("total_tokens", 1)
        h_min = session.get("h_min", 0.1)
        h_max = session.get("h_max", 8.0)

        actual = semantic_tokens / max(1, total_tokens)
        carnot = self.compute_carnot_limit(h_min, h_max)

        return {
            "session_id": session_id,
            "actual_efficiency": round(actual, 4),
            "carnot_limit": round(carnot, 4),
            "efficiency_gap": round(carnot - actual, 4),
            "utilization": round(actual / max(0.001, carnot), 4),
        }

    def record_session(self, session_id: str, data: dict) -> None:
        with self._lock:
            self._sessions[session_id] = dict(data)

    def get_global_stats(self) -> dict:
        with self._lock:
            session_ids = list(self._sessions.keys())
        if not session_ids:
            return {"sessions": 0}

        efficiencies = [self.compute_actual_efficiency(sid) for sid in session_ids]
        avg_actual = sum(e["actual_efficiency"] for e in efficiencies) / len(efficiencies)
        avg_carnot = sum(e["carnot_limit"] for e in efficiencies) / len(efficiencies)
        return {
            "sessions": len(efficiencies),
            "avg_actual_efficiency": round(avg_actual, 4),
            "avg_carnot_limit": round(avg_carnot, 4),
            "avg_gap": round(avg_carnot - avg_actual, 4),
        }
