"""H43 MVE — Quantum Probability: injection ordering effects.

Tests whether P(security_first→task) ≠ P(task_first→security).
If order matters → quantum probability model needed for proxy.
"""

from __future__ import annotations

import threading
from typing import Any


class H43QuantumMVE:
    """Quantum probability experiment runner for H43."""

    HYPOTHESIS = "H43: Injection order affects outcome probability"
    KILL_CONDITION = "delta_bar < 0.05 → H43 rejected"
    CONFIRM_CONDITION = "delta_bar > 0.10, p < 0.05 → quantum model needed"

    def __init__(self):
        self._results: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_trial(self, order: str, security_score: float, task_score: float) -> dict[str, Any]:
        """Record one trial result.

        order: 'security_first' or 'task_first'
        """
        delta = abs(security_score - task_score)
        trial: dict[str, Any] = {
            "order": order,
            "security_score": security_score,
            "task_score": task_score,
            "delta": round(delta, 4),
        }
        with self._lock:
            self._results.append(trial)
        return trial

    def compute_delta_bar(self) -> dict[str, Any]:
        """Compute mean delta across all trials."""
        with self._lock:
            results = list(self._results)
        if not results:
            return {"delta_bar": 0.0, "n": 0, "status": "insufficient_data"}

        sf = [item["delta"] for item in results if item["order"] == "security_first"]
        tf = [item["delta"] for item in results if item["order"] == "task_first"]
        if not sf or not tf:
            return {"delta_bar": 0.0, "n": len(results), "status": "insufficient_data"}

        mean_sf = sum(sf) / len(sf)
        mean_tf = sum(tf) / len(tf)
        delta_bar = abs(mean_sf - mean_tf)
        status = "REJECTED" if delta_bar < 0.05 else ("CONFIRMED" if delta_bar > 0.10 else "INCONCLUSIVE")
        return {
            "delta_bar": round(delta_bar, 4),
            "mean_security_first": round(mean_sf, 4),
            "mean_task_first": round(mean_tf, 4),
            "n_security_first": len(sf),
            "n_task_first": len(tf),
            "n_total": len(results),
            "status": status,
            "hypothesis": self.HYPOTHESIS,
        }

    def get_stats(self) -> dict[str, Any]:
        result = self.compute_delta_bar()
        with self._lock:
            trials_recorded = len(self._results)
        return {
            "trials_recorded": trials_recorded,
            "status": result.get("status", "pending"),
            "delta_bar": result.get("delta_bar", 0.0),
        }
