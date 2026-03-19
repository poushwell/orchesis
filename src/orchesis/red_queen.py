"""Red Queen Dynamics - adversarial co-evolution monitoring.

H41: Threat landscape evolves as defenses improve.
Monitor attack mutation rate vs detection adaptation rate.

"It takes all the running you can do, to keep in the same place."
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone


class RedQueenMonitor:
    """Monitors adversarial co-evolution dynamics."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.window_size = int(cfg.get("window", 100))
        self._attack_events: list[dict] = []
        self._detection_events: list[dict] = []
        self._mutations: list[dict] = []
        self._lock = threading.Lock()

    def record_attack(self, attack: dict) -> None:
        """Record new attack attempt."""
        with self._lock:
            self._attack_events.append(
                {
                    **attack,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            if len(self._attack_events) > self.window_size:
                self._attack_events = self._attack_events[-self.window_size :]

    def record_detection(self, detection: dict) -> None:
        """Record successful detection."""
        with self._lock:
            self._detection_events.append(
                {
                    **detection,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            if len(self._detection_events) > self.window_size:
                self._detection_events = self._detection_events[-self.window_size :]

    def compute_arms_race_index(self) -> dict:
        """ARI = attack_mutation_rate / detection_adaptation_rate."""
        with self._lock:
            attacks = list(self._attack_events)
            detections = list(self._detection_events)

        n_attacks = len(attacks)
        n_detections = len(detections)
        if n_attacks == 0:
            return {"ari": 0.0, "status": "no_attacks"}

        detection_rate = n_detections / max(1, n_attacks)
        novel_attacks = sum(1 for attack in attacks if attack.get("novel", False))
        mutation_rate = novel_attacks / max(1, n_attacks)
        ari = mutation_rate / max(0.01, detection_rate)

        return {
            "ari": round(ari, 4),
            "attack_mutation_rate": round(mutation_rate, 4),
            "detection_rate": round(detection_rate, 4),
            "status": "arms_race" if ari > 1.0 else "stable",
            "n_attacks": n_attacks,
            "n_detections": n_detections,
        }

    def get_emerging_patterns(self) -> list[dict]:
        """Detect emerging attack patterns not yet in signatures."""
        with self._lock:
            novel = [attack for attack in self._attack_events if attack.get("novel", False)]
        return novel[-10:]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "attacks_recorded": len(self._attack_events),
                "detections_recorded": len(self._detection_events),
                "window_size": self.window_size,
            }
