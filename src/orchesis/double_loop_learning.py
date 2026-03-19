"""Double-Loop Learning (Argyris & Schon 1978).

Single-loop: fix errors within existing rules.
Double-loop: question and modify the governing rules themselves.

Applied to context management:
- Single-loop: adjust compression threshold (fix within policy)
- Double-loop: question whether compression is the right strategy
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone


class DoubleLoopLearner:
    """Argyris double-loop learning for policy adaptation."""

    LOOPS = {
        "single": "Adjust parameters within existing strategy",
        "double": "Question and revise the governing strategy itself",
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.single_loop_threshold = float(cfg.get("single_threshold", 0.3))
        self.double_loop_threshold = float(cfg.get("double_threshold", 0.6))
        self._errors: list[dict] = []
        self._adaptations: list[dict] = []
        self._governing_rules: dict[str, float] = {
            "compression_aggressiveness": 0.5,
            "injection_frequency": 0.3,
            "cache_threshold": 0.85,
        }
        self._lock = threading.Lock()

    def record_error(self, error_type: str, magnitude: float, context: dict) -> None:
        """Record an error for learning."""
        with self._lock:
            self._errors.append(
                {
                    "type": error_type,
                    "magnitude": magnitude,
                    "context": context,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            if len(self._errors) > 10000:
                self._errors = self._errors[-10000:]

    def determine_loop(self, error_rate: float) -> str:
        """Determine if single or double loop learning needed."""
        if error_rate < self.single_loop_threshold:
            return "none"
        if error_rate < self.double_loop_threshold:
            return "single"
        return "double"

    def single_loop_adapt(self, rule: str, delta: float) -> dict:
        """Single-loop: adjust parameter within strategy."""
        with self._lock:
            if rule not in self._governing_rules:
                return {"error": f"Unknown rule: {rule}"}
            old_val = self._governing_rules[rule]
            new_val = max(0.0, min(1.0, old_val + delta))
            self._governing_rules[rule] = new_val
            adaptation = {
                "loop": "single",
                "rule": rule,
                "old_value": round(old_val, 4),
                "new_value": round(new_val, 4),
                "delta": round(delta, 4),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._adaptations.append(adaptation)
            return adaptation

    def double_loop_adapt(self, new_strategy: str, rationale: str) -> dict:
        """Double-loop: question and revise governing strategy."""
        with self._lock:
            adaptation = {
                "loop": "double",
                "new_strategy": new_strategy,
                "rationale": rationale,
                "rules_reset": dict(self._governing_rules),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._governing_rules = {key: 0.5 for key in self._governing_rules}
            self._adaptations.append(adaptation)
            return adaptation

    def get_learning_stats(self) -> dict:
        with self._lock:
            single = sum(1 for item in self._adaptations if item["loop"] == "single")
            double = sum(1 for item in self._adaptations if item["loop"] == "double")
            return {
                "errors_recorded": len(self._errors),
                "single_loop_adaptations": single,
                "double_loop_adaptations": double,
                "governing_rules": dict(self._governing_rules),
            }
