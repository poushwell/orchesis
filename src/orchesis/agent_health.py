"""Agent health scoring model."""

from __future__ import annotations

from typing import Any


class AgentHealthScore:
    """Aggregated health metric: security + cost + context + coordination."""

    WEIGHTS = {
        "security": 0.35,
        "cost_efficiency": 0.25,
        "context_quality": 0.25,
        "reliability": 0.15,
    }

    def _clamp01(self, value: Any) -> float:
        if not isinstance(value, int | float):
            return 0.0
        raw = float(value)
        if raw > 1.0 and raw <= 100.0:
            raw = raw / 100.0
        return max(0.0, min(1.0, raw))

    def _clamp100(self, value: float) -> float:
        return max(0.0, min(100.0, float(value)))

    def _grade_for(self, score: float) -> str:
        if score >= 95.0:
            return "A+"
        if score >= 90.0:
            return "A"
        if score >= 80.0:
            return "B+"
        if score >= 70.0:
            return "B"
        if score >= 60.0:
            return "C"
        return "D"

    def _trend_for(self, score: float, previous_score: float | None) -> str:
        if not isinstance(previous_score, int | float):
            return "stable"
        delta = float(score) - float(previous_score)
        if delta >= 3.0:
            return "improving"
        if delta <= -3.0:
            return "degrading"
        return "stable"

    def compute(self, agent_stats: dict) -> dict:
        """Returns score 0-100 + grade A+/A/B+/B/C/D + breakdown."""
        block_rate = self._clamp01(agent_stats.get("block_rate", 0.0))
        threat_frequency = self._clamp01(agent_stats.get("threat_frequency", 0.0))
        cost_budget_ratio = self._clamp01(agent_stats.get("cost_budget_ratio", 0.0))
        savings_rate = self._clamp01(agent_stats.get("savings_rate", 0.0))
        cache_hit_rate = self._clamp01(agent_stats.get("cache_hit_rate", 0.0))
        loop_frequency = self._clamp01(agent_stats.get("loop_frequency", 0.0))
        error_rate = self._clamp01(agent_stats.get("error_rate", 0.0))
        latency_ms_raw = agent_stats.get("latency_ms", 0.0)
        latency_ms = float(latency_ms_raw) if isinstance(latency_ms_raw, int | float) else 0.0
        latency_penalty = max(0.0, min(1.0, latency_ms / 2000.0))

        security = self._clamp100(100.0 - (threat_frequency * 70.0) - ((1.0 - block_rate) * 30.0))
        cost_efficiency = self._clamp100(((1.0 - cost_budget_ratio) * 70.0) + (savings_rate * 30.0))
        context_quality = self._clamp100((cache_hit_rate * 70.0) + ((1.0 - loop_frequency) * 30.0))
        reliability = self._clamp100(((1.0 - error_rate) * 60.0) + ((1.0 - latency_penalty) * 40.0))

        breakdown = {
            "security": round(security, 2),
            "cost_efficiency": round(cost_efficiency, 2),
            "context_quality": round(context_quality, 2),
            "reliability": round(reliability, 2),
        }

        weighted_score = (
            breakdown["security"] * self.WEIGHTS["security"]
            + breakdown["cost_efficiency"] * self.WEIGHTS["cost_efficiency"]
            + breakdown["context_quality"] * self.WEIGHTS["context_quality"]
            + breakdown["reliability"] * self.WEIGHTS["reliability"]
        )
        score = round(self._clamp100(weighted_score), 2)
        grade = self._grade_for(score)
        trend = self._trend_for(score, agent_stats.get("previous_score"))
        return {
            "score": score,
            "grade": grade,
            "breakdown": breakdown,
            "trend": trend,
        }
