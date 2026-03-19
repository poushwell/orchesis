"""H17-CC: Criticality Control via LQR.

Keep Psi in [0.4, 0.6] through feedback control.
MRAC: adaptive gain for unknown dynamics.
"""

from __future__ import annotations

import math
import threading


class CriticalityController:
    """LQR-based criticality control for context phase management."""

    PSI_TARGET = 0.5
    PSI_LOW = 0.3
    PSI_HIGH = 0.7
    PSI_OPTIMAL_LOW = 0.4
    PSI_OPTIMAL_HIGH = 0.6

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.q = float(cfg.get("q", 1.0))
        self.r = float(cfg.get("r", 0.1))
        self.adaptive_gain = float(cfg.get("adaptive_gain", 0.1))
        self._gain_history: list[float] = []
        self._psi_history: list[float] = []
        self._lock = threading.Lock()

    def compute_control(self, psi: float) -> dict:
        """LQR control signal to bring Psi to target."""
        error = self.PSI_TARGET - float(psi)
        k = math.sqrt(self.q / self.r)
        u = k * error
        action = self._select_action(float(psi), u)

        with self._lock:
            self._psi_history.append(float(psi))
            self._gain_history.append(k)
            if len(self._psi_history) > 1000:
                self._psi_history = self._psi_history[-1000:]
                self._gain_history = self._gain_history[-1000:]

        return {
            "psi": float(psi),
            "error": round(error, 4),
            "control_signal": round(u, 4),
            "lqr_gain": round(k, 4),
            "action": action,
            "in_optimal_range": self.PSI_OPTIMAL_LOW <= float(psi) <= self.PSI_OPTIMAL_HIGH,
        }

    def _select_action(self, psi: float, u: float) -> str:
        _ = u
        if psi > self.PSI_HIGH:
            return "thaw"
        if psi < self.PSI_LOW:
            return "crystallize"
        if psi > self.PSI_OPTIMAL_HIGH:
            return "gentle_thaw"
        if psi < self.PSI_OPTIMAL_LOW:
            return "gentle_crystallize"
        return "maintain"

    def mrac_update(self, psi_actual: float, psi_predicted: float) -> float:
        """MRAC: adaptive gain scheduling."""
        error = float(psi_actual) - float(psi_predicted)
        delta_gain = self.adaptive_gain * error
        self.adaptive_gain = max(0.01, min(1.0, self.adaptive_gain + delta_gain))
        return self.adaptive_gain

    def get_stats(self) -> dict:
        with self._lock:
            if not self._psi_history:
                return {"observations": 0}
            avg_psi = sum(self._psi_history) / len(self._psi_history)
            in_range = sum(1 for p in self._psi_history if self.PSI_OPTIMAL_LOW <= p <= self.PSI_OPTIMAL_HIGH)
            return {
                "observations": len(self._psi_history),
                "avg_psi": round(avg_psi, 4),
                "in_optimal_range_rate": round(in_range / len(self._psi_history), 4),
                "adaptive_gain": round(self.adaptive_gain, 4),
            }

