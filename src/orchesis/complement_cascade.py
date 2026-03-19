"""Complement Cascade - immune system analogy for threat response.

Biological complement system: cascade of proteins that amplify
immune response to threats.

Applied to context security:
- C1: initial threat detection (pattern match)
- C3: amplification (cross-check multiple signals)
- C5: effector (blocking action)
- MAC: membrane attack complex (circuit breaker)
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone


class ComplementCascade:
    """Immune-inspired threat amplification cascade."""

    STAGES = {
        "C1": {"name": "Initial Recognition", "threshold": 0.3},
        "C3": {"name": "Amplification", "threshold": 0.5},
        "C5": {"name": "Effector Activation", "threshold": 0.7},
        "MAC": {"name": "Terminal Attack", "threshold": 0.9},
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.amplification_factor = float(cfg.get("amplification", 1.5))
        self._activations: list[dict] = []
        self._lock = threading.Lock()

    def activate(self, threat_signal: float, threat_type: str) -> dict:
        """Run complement cascade for threat signal."""
        stages_activated: list[str] = []
        current_signal = float(threat_signal)

        for stage, params in self.STAGES.items():
            if current_signal >= float(params["threshold"]):
                stages_activated.append(stage)
                current_signal = min(1.0, current_signal * self.amplification_factor)
            else:
                break

        terminal = "MAC" in stages_activated
        action = self._determine_action(stages_activated)
        result = {
            "threat_signal": round(float(threat_signal), 4),
            "threat_type": threat_type,
            "stages_activated": stages_activated,
            "amplified_signal": round(current_signal, 4),
            "terminal_attack": terminal,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            self._activations.append(result)
            if len(self._activations) > 10000:
                self._activations = self._activations[-10000:]
        return result

    def _determine_action(self, stages: list[str]) -> str:
        if "MAC" in stages:
            return "circuit_break"
        if "C5" in stages:
            return "block"
        if "C3" in stages:
            return "warn"
        if "C1" in stages:
            return "monitor"
        return "none"

    def get_cascade_stats(self) -> dict:
        with self._lock:
            if not self._activations:
                return {"activations": 0}
            terminal = sum(1 for item in self._activations if item["terminal_attack"])
            return {
                "total_activations": len(self._activations),
                "terminal_attacks": terminal,
                "terminal_rate": round(terminal / len(self._activations), 4),
                "amplification_factor": self.amplification_factor,
            }
