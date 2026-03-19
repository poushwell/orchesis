"""Adaptive Threshold Manager - self-calibrating detection thresholds.

Thresholds adapt based on observed false positive/negative rates.
Uses exponential moving average style stepping for smooth adaptation.
"""

from __future__ import annotations

import threading


class AdaptiveThresholdManager:
    """Self-calibrating detection thresholds."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.alpha = float(cfg.get("alpha", 0.1))
        self.fpr_target = float(cfg.get("fpr_target", 0.05))
        self._thresholds: dict[str, float] = {}
        self._feedback: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    def get_threshold(self, detector: str, default: float = 0.5) -> float:
        with self._lock:
            return float(self._thresholds.get(str(detector), float(default)))

    def record_feedback(self, detector: str, predicted: bool, actual: bool) -> None:
        """Record TP/TN/FP/FN for threshold adaptation."""
        key = str(detector)
        with self._lock:
            if key not in self._feedback:
                self._feedback[key] = []
            self._feedback[key].append(
                {
                    "predicted": bool(predicted),
                    "actual": bool(actual),
                    "correct": bool(predicted) == bool(actual),
                }
            )
            if len(self._feedback[key]) > 1000:
                self._feedback[key] = self._feedback[key][-1000:]

    def adapt(self, detector: str) -> dict:
        """Adapt threshold based on recent feedback."""
        key = str(detector)
        with self._lock:
            feedback = list(self._feedback.get(key, []))
            current = float(self._thresholds.get(key, 0.5))

        if len(feedback) < 10:
            return {"detector": key, "adapted": False, "reason": "insufficient_data"}

        fp = sum(1 for item in feedback if item["predicted"] and not item["actual"])
        fn = sum(1 for item in feedback if not item["predicted"] and item["actual"])
        total = len(feedback)

        fpr = fp / max(1, total)
        fnr = fn / max(1, total)

        if fpr > self.fpr_target:
            new_threshold = min(0.99, current + self.alpha)
        elif fnr > self.fpr_target:
            new_threshold = max(0.01, current - self.alpha)
        else:
            new_threshold = current

        with self._lock:
            self._thresholds[key] = float(new_threshold)

        return {
            "detector": key,
            "old_threshold": round(current, 4),
            "new_threshold": round(float(new_threshold), 4),
            "fpr": round(float(fpr), 4),
            "fnr": round(float(fnr), 4),
            "adapted": float(new_threshold) != current,
        }

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "detectors": len(self._thresholds),
                "thresholds": dict(self._thresholds),
                "fpr_target": self.fpr_target,
            }

