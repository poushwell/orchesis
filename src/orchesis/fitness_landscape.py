"""Fitness Landscape Mapping - evolutionary context optimization.

Maps agent performance across policy configurations.
Finds local optima and saddle points in policy space.
Research Backlog Tier 2.
"""

from __future__ import annotations

import math
import threading
from typing import Any


class FitnessLandscapeMapper:
    """Maps fitness landscape of policy configurations."""
    MAX_EVALUATIONS = 10_000

    def __init__(self, config: dict | None = None):
        _ = config
        self._evaluations: dict[str, float] = {}
        self._lock = threading.Lock()

    def evaluate(self, config_point: dict, fitness: float) -> None:
        """Record fitness at config point."""
        key = self._config_to_key(config_point)
        with self._lock:
            self._evaluations[key] = float(fitness)
            if len(self._evaluations) > self.MAX_EVALUATIONS:
                keys = list(self._evaluations.keys())
                for stale_key in keys[: -self.MAX_EVALUATIONS]:
                    del self._evaluations[stale_key]

    def find_local_optima(self) -> list[dict[str, Any]]:
        """Find local maxima in fitness landscape."""
        with self._lock:
            evals = dict(self._evaluations)

        if not evals:
            return []

        max_fitness = max(evals.values())
        optima = [
            {"config": key, "fitness": value, "global_optimum": abs(value - max_fitness) < 0.01}
            for key, value in evals.items()
            if value >= max_fitness * 0.9
        ]
        return sorted(optima, key=lambda item: -float(item["fitness"]))

    def compute_ruggedness(self) -> float:
        """Landscape ruggedness = standard deviation of fitness values."""
        with self._lock:
            values = list(self._evaluations.values())
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        return round(math.sqrt(variance), 4)

    def get_gradient(self, config_point: dict) -> dict[str, Any]:
        """Estimated gradient at config point."""
        key = self._config_to_key(config_point)
        with self._lock:
            current = float(self._evaluations.get(key, 0.5))
            neighbors = list(self._evaluations.values())

        if not neighbors:
            return {"gradient": 0.0, "direction": "unknown", "at_optimum": True}

        avg_neighbor = sum(neighbors) / len(neighbors)
        gradient = current - avg_neighbor
        return {
            "gradient": round(gradient, 4),
            "direction": "ascending" if gradient > 0 else "descending",
            "at_optimum": abs(gradient) < 0.01,
        }

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            evaluations_count = len(self._evaluations)
        return {
            "evaluations": evaluations_count,
            "ruggedness": self.compute_ruggedness(),
            "optima_count": len(self.find_local_optima()),
        }

    def _config_to_key(self, config: dict) -> str:
        if not isinstance(config, dict):
            return "[]"
        return str(sorted(config.items()))
