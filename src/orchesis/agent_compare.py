"""Agent Comparison - side-by-side behavioral comparison of agents."""

from __future__ import annotations

import threading
from typing import Any


class AgentComparer:
    """Compare behavioral profiles of multiple agents."""

    METRICS = [
        "token_yield",
        "deny_rate",
        "loop_rate",
        "avg_tokens",
        "cost_per_request",
        "cache_hit_rate",
    ]

    def __init__(self):
        self._profiles: dict[str, dict[str, list[float]]] = {}
        self._lock = threading.Lock()

    def record_metric(self, agent_id: str, metric: str, value: float) -> None:
        agent = str(agent_id or "").strip()
        key = str(metric or "").strip()
        if not agent:
            return
        with self._lock:
            if agent not in self._profiles:
                self._profiles[agent] = {name: [] for name in self.METRICS}
            if key in self._profiles[agent]:
                self._profiles[agent][key].append(float(value))

    def compare(self, agent_a: str, agent_b: str) -> dict[str, Any]:
        left = str(agent_a or "").strip()
        right = str(agent_b or "").strip()
        with self._lock:
            profile_a = dict(self._profiles.get(left, {}))
            profile_b = dict(self._profiles.get(right, {}))

        comparison: dict[str, dict[str, Any]] = {}
        for metric in self.METRICS:
            vals_a = list(profile_a.get(metric, [0.0])) or [0.0]
            vals_b = list(profile_b.get(metric, [0.0])) or [0.0]
            avg_a = sum(vals_a) / float(max(1, len(vals_a)))
            avg_b = sum(vals_b) / float(max(1, len(vals_b)))
            comparison[metric] = {
                left: round(avg_a, 4),
                right: round(avg_b, 4),
                "winner": left if avg_a >= avg_b else right,
                "delta": round(abs(avg_a - avg_b), 4),
            }

        overall_winner = max(
            [left, right],
            key=lambda agent: sum(1 for values in comparison.values() if values["winner"] == agent),
        )
        return {
            "agent_a": left,
            "agent_b": right,
            "metrics": comparison,
            "overall_winner": overall_winner,
            "metrics_won_a": sum(1 for values in comparison.values() if values["winner"] == left),
            "metrics_won_b": sum(1 for values in comparison.values() if values["winner"] == right),
        }

    def rank_all(self) -> list[dict[str, Any]]:
        with self._lock:
            snapshot = {agent: dict(metrics) for agent, metrics in self._profiles.items()}

        scores: list[dict[str, Any]] = []
        for agent, profile in snapshot.items():
            score = (
                sum((sum(values) / float(max(1, len(values)))) for values in profile.values() if values)
                / float(max(1, len(self.METRICS)))
            )
            scores.append({"agent_id": agent, "score": round(score, 4)})
        return sorted(scores, key=lambda item: -float(item["score"]))

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {"agents_tracked": len(self._profiles)}
