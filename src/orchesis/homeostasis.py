"""Homeostasis - biological equilibrium for context management.

Applied: maintain stable context quality (CQS) within target range
despite varying input quality and load.
"""

from __future__ import annotations

import threading


class HomeostasisController:
    """Negative feedback homeostasis for context quality."""

    SETPOINT = 0.75
    BAND_WIDTH = 0.15

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.setpoint = float(cfg.get("setpoint", self.SETPOINT))
        self.band = float(cfg.get("band", self.BAND_WIDTH))
        self.gain = float(cfg.get("gain", 0.3))
        self._history: list[float] = []
        self._interventions: list[dict] = []
        self._lock = threading.Lock()

    def measure(self, cqs: float) -> dict:
        """Measure CQS and determine homeostatic response."""
        with self._lock:
            self._history.append(float(cqs))
            if len(self._history) > 1000:
                self._history = self._history[-1000:]

        deviation = float(cqs) - self.setpoint
        in_band = abs(deviation) <= self.band
        response = self._negative_feedback(deviation)
        if response["action"] != "maintain":
            with self._lock:
                self._interventions.append(response)
                if len(self._interventions) > 1000:
                    self._interventions = self._interventions[-1000:]

        return {
            "cqs": round(float(cqs), 4),
            "setpoint": self.setpoint,
            "deviation": round(deviation, 4),
            "in_band": in_band,
            "response": response,
            "intervention_needed": not in_band,
        }

    def _negative_feedback(self, deviation: float) -> dict:
        """Negative feedback response to deviation."""
        correction = -self.gain * float(deviation)
        if deviation > self.band:
            action = "reduce_injection"
        elif deviation < -self.band:
            action = "increase_injection"
        else:
            action = "maintain"
        return {
            "action": action,
            "correction": round(correction, 4),
            "direction": "reduce" if deviation > 0 else "increase",
        }

    def get_equilibrium_stats(self) -> dict:
        with self._lock:
            if not self._history:
                return {"measurements": 0}
            in_band = sum(1 for cqs in self._history if abs(cqs - self.setpoint) <= self.band)
            return {
                "measurements": len(self._history),
                "avg_cqs": round(sum(self._history) / len(self._history), 4),
                "in_band_rate": round(in_band / len(self._history), 4),
                "setpoint": self.setpoint,
                "band": self.band,
            }

