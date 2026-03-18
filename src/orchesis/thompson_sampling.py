"""Thompson sampling multi-objective routing."""

from __future__ import annotations

import random
import threading
from collections import defaultdict
from typing import Any


class ThompsonSampler:
    """Multi-armed bandit for model/strategy routing.

    Objectives: quality x cost x latency
    Per-task-type bandits: coding / research / planning / writing / analysis
    """

    TASK_TYPES = ["coding", "research", "planning", "writing", "analysis", "unknown"]

    ARMS = {
        "gpt-4o": {"cost_per_ktok": 0.005},
        "gpt-4o-mini": {"cost_per_ktok": 0.00015},
        "claude-3-5-sonnet": {"cost_per_ktok": 0.003},
        "claude-3-haiku": {"cost_per_ktok": 0.00025},
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.explore_rate = max(0.0, min(1.0, float(cfg.get("explore_rate", 0.1))))
        self._rng = random.Random(cfg.get("seed"))
        # Beta distribution params per arm per task_type
        self._alpha: dict[str, dict[str, float]] = {}
        self._beta: dict[str, dict[str, float]] = {}
        self._observations: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        for arm in self.ARMS:
            self._alpha[arm] = {task: 1.0 for task in self.TASK_TYPES}
            self._beta[arm] = {task: 1.0 for task in self.TASK_TYPES}

    def _normalize_task_type(self, task_type: str) -> str:
        value = str(task_type or "unknown").strip().lower()
        return value if value in self.TASK_TYPES else "unknown"

    def _known_arm(self, arm: str) -> bool:
        return str(arm or "") in self.ARMS

    def sample(self, task_type: str, available_arms: list[str]) -> str:
        """Thompson sample - return best arm for task type."""
        task = self._normalize_task_type(task_type)
        candidates = [str(arm) for arm in available_arms if self._known_arm(str(arm))]
        if not candidates:
            return "gpt-4o-mini"
        with self._lock:
            if len(candidates) > 1 and self._rng.random() < self.explore_rate:
                return self._rng.choice(candidates)
            sampled: dict[str, float] = {}
            for arm in candidates:
                a = float(self._alpha[arm][task])
                b = float(self._beta[arm][task])
                draw = self._rng.betavariate(max(1e-6, a), max(1e-6, b))
                sampled[arm] = float(draw)
            return max(sampled.items(), key=lambda item: item[1])[0]

    def update(self, arm: str, task_type: str, reward: float) -> None:
        """Update Beta distribution for arm/task_type pair.
        Reward: composite score of quality x (1/cost) x (1/latency)
        """
        model = str(arm or "")
        if not self._known_arm(model):
            return
        task = self._normalize_task_type(task_type)
        value = max(0.0, min(1.0, float(reward or 0.0)))
        with self._lock:
            self._alpha[model][task] = float(self._alpha[model][task]) + value
            self._beta[model][task] = float(self._beta[model][task]) + (1.0 - value)
            self._observations.append(
                {
                    "arm": model,
                    "task_type": task,
                    "reward": value,
                }
            )
            if len(self._observations) > 50_000:
                self._observations = self._observations[-50_000:]

    def get_best_arm(self, task_type: str) -> str:
        """Return current best arm (exploit only, no explore)."""
        task = self._normalize_task_type(task_type)
        with self._lock:
            means: dict[str, float] = {}
            for arm in self.ARMS:
                a = float(self._alpha[arm][task])
                b = float(self._beta[arm][task])
                means[arm] = a / max(1e-6, (a + b))
            return max(means.items(), key=lambda item: item[1])[0]

    def get_arm_stats(self, arm: str) -> dict:
        model = str(arm or "")
        with self._lock:
            rows = [item for item in self._observations if str(item.get("arm", "")) == model]
            by_task: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "reward_sum": 0.0})
            for row in rows:
                task = str(row.get("task_type", "unknown"))
                by_task[task]["count"] += 1.0
                by_task[task]["reward_sum"] += float(row.get("reward", 0.0) or 0.0)
            by_task_out = {
                task: {
                    "samples": int(vals["count"]),
                    "avg_reward": round(vals["reward_sum"] / vals["count"], 6) if vals["count"] > 0 else 0.0,
                }
                for task, vals in by_task.items()
            }
            avg = (
                sum(float(item.get("reward", 0.0) or 0.0) for item in rows) / float(len(rows))
                if rows
                else 0.0
            )
            return {
                "arm": model,
                "total_samples": len(rows),
                "avg_reward": round(avg, 6),
                "by_task_type": by_task_out,
            }

    def get_regret(self) -> float:
        """Cumulative regret vs always-best-arm baseline."""
        with self._lock:
            if not self._observations:
                return 0.0
            per_task_per_arm: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
            for row in self._observations:
                arm = str(row.get("arm", ""))
                task = str(row.get("task_type", "unknown"))
                per_task_per_arm[task][arm].append(float(row.get("reward", 0.0) or 0.0))
            best_avg_by_task: dict[str, float] = {}
            for task, arm_map in per_task_per_arm.items():
                best_avg_by_task[task] = max(
                    (sum(vals) / float(len(vals)) for vals in arm_map.values() if vals),
                    default=0.0,
                )
            regret = 0.0
            for row in self._observations:
                task = str(row.get("task_type", "unknown"))
                reward = float(row.get("reward", 0.0) or 0.0)
                regret += max(0.0, best_avg_by_task.get(task, 0.0) - reward)
            return round(regret, 6)

    def reset_arm(self, arm: str) -> None:
        """Reset priors for arm (e.g. after model update)."""
        model = str(arm or "")
        if not self._known_arm(model):
            return
        with self._lock:
            self._alpha[model] = {task: 1.0 for task in self.TASK_TYPES}
            self._beta[model] = {task: 1.0 for task in self.TASK_TYPES}
            self._observations = [item for item in self._observations if str(item.get("arm", "")) != model]
