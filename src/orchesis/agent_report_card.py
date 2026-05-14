"""Agent Report Card - one-page summary for any agent.

Combines: ARC score, AABB benchmark, token yield, security,
compliance, cost efficiency into single grade.
"""

from __future__ import annotations

from datetime import datetime, timezone


class AgentReportCard:
    GRADE_THRESHOLDS = {
        "A+": 95,
        "A": 90,
        "B+": 85,
        "B": 80,
        "C+": 75,
        "C": 70,
        "D": 60,
        "F": 0,
    }

    def __init__(self):
        self._cards: dict[str, dict] = {}

    def generate(self, agent_id: str, metrics: dict) -> dict:
        scores = {
            "security": self._score_security(metrics),
            "cost_efficiency": self._score_cost(metrics),
            "reliability": self._score_reliability(metrics),
            "compliance": self._score_compliance(metrics),
            "performance": self._score_performance(metrics),
        }
        overall = sum(scores.values()) / len(scores)
        grade = self._get_grade(overall)

        card = {
            "agent_id": agent_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_score": round(overall, 1),
            "grade": grade,
            "category_scores": {k: round(v, 1) for k, v in scores.items()},
            "badge": f"Orchesis Verified: {grade} ({overall:.0f}/100)",
            "strengths": [k for k, v in scores.items() if v >= 80],
            "improvements": [k for k, v in scores.items() if v < 70],
            "arc_ready": overall >= 75,
        }
        self._cards[agent_id] = card
        return card

    def _score_security(self, m: dict) -> float:
        deny_rate = m.get("deny_rate", 0)
        return min(100.0, 60 + deny_rate * 40)

    def _score_cost(self, m: dict) -> float:
        yield_ = m.get("token_yield", 0.5)
        return min(100.0, yield_ * 100)

    def _score_reliability(self, m: dict) -> float:
        error_rate = m.get("error_rate", 0.1)
        return max(0.0, (1 - error_rate) * 100)

    def _score_compliance(self, m: dict) -> float:
        recording = m.get("recording_enabled", False)
        audit = m.get("audit_trail", False)
        return 50 + (25 if recording else 0) + (25 if audit else 0)

    def _score_performance(self, m: dict) -> float:
        latency_ok = m.get("latency_within_sla", True)
        cache_rate = m.get("cache_hit_rate", 0.3)
        return (50 if latency_ok else 20) + cache_rate * 50

    def _get_grade(self, score: float) -> str:
        for grade, threshold in self.GRADE_THRESHOLDS.items():
            if score >= threshold:
                return grade
        return "F"

    def compare_grades(self, agent_a: str, agent_b: str) -> dict:
        card_a = self._cards.get(agent_a)
        card_b = self._cards.get(agent_b)
        if not card_a or not card_b:
            return {"error": "One or both agents not found"}
        return {
            "agent_a": {"id": agent_a, "grade": card_a["grade"], "score": card_a["overall_score"]},
            "agent_b": {"id": agent_b, "grade": card_b["grade"], "score": card_b["overall_score"]},
            "winner": agent_a if card_a["overall_score"] >= card_b["overall_score"] else agent_b,
        }

    def get_stats(self) -> dict:
        return {"cards_generated": len(self._cards)}
