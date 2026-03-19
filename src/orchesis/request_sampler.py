"""Request sampling strategies for decision logging."""

from __future__ import annotations

import random
from typing import Any


class RequestSampler:
    """Intelligent request sampling for storage efficiency."""

    STRATEGIES = {
        "random": "Sample N% randomly",
        "always_block": "Always record blocked requests",
        "reservoir": "Reservoir sampling for uniform distribution",
        "adaptive": "Higher rate during anomalies",
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.rate = max(0.0, min(1.0, float(cfg.get("rate", 1.0))))
        self._base_rate = self.rate
        self.strategy = str(cfg.get("strategy", "always_block") or "always_block")
        if self.strategy not in self.STRATEGIES:
            self.strategy = "always_block"
        self.always_record_blocks = bool(cfg.get("always_record_blocks", True))
        self._sampled = 0
        self._skipped = 0
        self._seen = 0
        self._rng = random.Random(int(cfg.get("seed", 1337)))

    def should_record(self, decision: dict) -> bool:
        """Returns True if this request should be recorded."""
        payload = decision if isinstance(decision, dict) else {}
        decision_name = str(payload.get("decision", "")).upper()
        if self.always_record_blocks and decision_name == "DENY":
            self._sampled += 1
            self._seen += 1
            return True

        if self.strategy == "adaptive":
            score_raw = payload.get("anomaly_score", payload.get("risk_score", 0.0))
            try:
                self.adjust_rate(float(score_raw))
            except (TypeError, ValueError):
                self.adjust_rate(0.0)

        probability = self.rate
        if self.strategy == "always_block":
            probability = self.rate
        elif self.strategy == "random":
            probability = self.rate
        elif self.strategy == "reservoir":
            probability = self.rate
        elif self.strategy == "adaptive":
            probability = self.rate

        take = self._rng.random() < max(0.0, min(1.0, probability))
        self._seen += 1
        if take:
            self._sampled += 1
            return True
        self._skipped += 1
        return False

    def get_stats(self) -> dict:
        effective = self._sampled / float(self._sampled + self._skipped) if (self._sampled + self._skipped) else 0.0
        return {
            "rate": float(self.rate),
            "strategy": str(self.strategy),
            "sampled": int(self._sampled),
            "skipped": int(self._skipped),
            "effective_rate": float(round(effective, 6)),
        }

    def adjust_rate(self, anomaly_score: float) -> None:
        """Adaptive: increase sampling during anomalies."""
        score = max(0.0, min(1.0, float(anomaly_score or 0.0)))
        if score >= 0.9:
            self.rate = min(1.0, max(self._base_rate, self._base_rate * 4.0))
        elif score >= 0.7:
            self.rate = min(1.0, max(self._base_rate, self._base_rate * 2.0))
        elif score >= 0.5:
            self.rate = min(1.0, max(self._base_rate, self._base_rate * 1.5))
        else:
            self.rate = self._base_rate
