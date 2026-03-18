"""Agent scorecard computation for weekly/monthly reports."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class AgentScorecard:
    """Weekly/monthly agent performance scorecard."""

    METRICS = {
        "security_score": {"weight": 0.25, "unit": "percent"},
        "cost_efficiency": {"weight": 0.25, "unit": "usd_per_krequest"},
        "cache_hit_rate": {"weight": 0.20, "unit": "percent"},
        "reliability": {"weight": 0.15, "unit": "percent"},
        "context_quality": {"weight": 0.15, "unit": "score"},
    }

    def __init__(self):
        self._history: dict[str, list[dict]] = {}

    @staticmethod
    def _as_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        if hasattr(item, "__dict__"):
            raw = getattr(item, "__dict__", {})
            if isinstance(raw, dict):
                return raw
        return {}

    @staticmethod
    def _as_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _clamp100(value: float) -> float:
        return max(0.0, min(100.0, float(value)))

    @staticmethod
    def _grade_for(score: float) -> str:
        value = float(score)
        if value >= 97.0:
            return "A+"
        if value >= 90.0:
            return "A"
        if value >= 85.0:
            return "B+"
        if value >= 75.0:
            return "B"
        if value >= 60.0:
            return "C"
        return "D"

    @staticmethod
    def _period_days(period: str) -> int:
        text = str(period or "7d").strip().lower()
        if text.endswith("d") and text[:-1].isdigit():
            return max(1, int(text[:-1]))
        return 7

    def _compute_metrics(self, agent_id: str, decisions_log: list, period: str) -> dict[str, float]:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self._period_days(period))
        rows: list[dict[str, Any]] = []
        for item in decisions_log:
            row = self._as_dict(item)
            if str(row.get("agent_id", "")) != str(agent_id):
                continue
            ts = self._parse_ts(row.get("timestamp"))
            if ts is not None and ts < cutoff:
                continue
            rows.append(row)
        if not rows:
            return {
                "security_score": 50.0,
                "cost_efficiency": 50.0,
                "cache_hit_rate": 0.0,
                "reliability": 50.0,
                "context_quality": 50.0,
            }

        total = float(len(rows))
        denied = 0.0
        cost_sum = 0.0
        cache_sum = 0.0
        cache_count = 0.0
        duration_sum_us = 0.0
        for row in rows:
            decision = str(row.get("decision", "ALLOW")).upper()
            if decision == "DENY":
                denied += 1.0
            cost_sum += self._as_float(row.get("cost", 0.0))
            snapshot = row.get("state_snapshot")
            if not isinstance(snapshot, dict):
                snapshot = {}
            cache_rate = snapshot.get("cache_hit_rate")
            if isinstance(cache_rate, int | float):
                cache_sum += max(0.0, min(1.0, float(cache_rate)))
                cache_count += 1.0
            duration_sum_us += self._as_float(row.get("evaluation_duration_us", row.get("evaluation_us", 0.0)))

        deny_rate = denied / max(1.0, total)
        allow_rate = 1.0 - deny_rate
        security_score = self._clamp100(100.0 - (deny_rate * 100.0))
        reliability = self._clamp100(allow_rate * 100.0)
        cache_percent = self._clamp100((cache_sum / cache_count) * 100.0 if cache_count > 0.0 else 0.0)
        cost_per_k = (cost_sum / max(1.0, total)) * 1000.0
        cost_efficiency = self._clamp100(100.0 - min(100.0, cost_per_k * 5.0))
        avg_ms = (duration_sum_us / max(1.0, total)) / 1000.0
        context_quality = self._clamp100(100.0 - min(60.0, avg_ms / 2.0) - (deny_rate * 40.0))

        return {
            "security_score": round(security_score, 4),
            "cost_efficiency": round(cost_efficiency, 4),
            "cache_hit_rate": round(cache_percent, 4),
            "reliability": round(reliability, 4),
            "context_quality": round(context_quality, 4),
        }

    def compute(self, agent_id: str, decisions_log: list, period: str = "7d") -> dict:
        metrics = self._compute_metrics(agent_id, decisions_log, period)
        overall = 0.0
        for metric_name, config in self.METRICS.items():
            overall += float(metrics.get(metric_name, 0.0)) * float(config["weight"])
        overall = self._clamp100(overall)
        grade = self._grade_for(overall)

        previous = None
        history = self._history.get(agent_id, [])
        for item in reversed(history):
            if str(item.get("period", "7d")) == str(period):
                previous = item
                break
        wow = {
            "overall_score_delta": round(overall - float(previous.get("overall_score", 0.0)), 4) if previous else 0.0,
            "metrics_delta": {
                key: round(float(metrics.get(key, 0.0)) - float((previous or {}).get("metrics", {}).get(key, 0.0)), 4)
                for key in self.METRICS
            },
        }

        highlights: list[str] = []
        improvements: list[str] = []
        if metrics["cache_hit_rate"] >= 85.0:
            highlights.append(f"Best cache hit rate: {metrics['cache_hit_rate']:.1f}%")
        if metrics["security_score"] >= 95.0:
            highlights.append("Security posture remains excellent")
        if wow["metrics_delta"]["cost_efficiency"] < -5.0:
            improvements.append("Cost efficiency dropped vs previous period")
        if wow["metrics_delta"]["reliability"] < -3.0:
            improvements.append("Reliability declined vs previous period")
        if not highlights:
            highlights.append("Stable baseline across key metrics")
        if not improvements:
            improvements.append("No critical regressions detected")

        scorecard = {
            "agent_id": str(agent_id),
            "period": str(period),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_score": round(overall, 4),
            "grade": grade,
            "rank": 1,
            "metrics": metrics,
            "week_over_week": wow,
            "highlights": highlights,
            "improvements": improvements,
            "badges": [],
        }
        self._history.setdefault(agent_id, []).append(
            {
                "period": str(period),
                "overall_score": scorecard["overall_score"],
                "metrics": dict(metrics),
            }
        )
        self._history[agent_id] = self._history[agent_id][-12:]
        return scorecard

    def compute_all(self, decisions_log: list) -> list[dict]:
        agent_ids = sorted(
            {
                str(self._as_dict(item).get("agent_id", "") or "")
                for item in decisions_log
                if str(self._as_dict(item).get("agent_id", "") or "").strip()
            }
        )
        cards = [self.compute(agent_id=agent_id, decisions_log=decisions_log, period="7d") for agent_id in agent_ids]
        cards.sort(key=lambda item: float(item.get("overall_score", 0.0)), reverse=True)
        for idx, card in enumerate(cards, start=1):
            card["rank"] = idx
        for card in cards:
            card["badges"] = self.assign_badges(card, cards)
        return cards

    def get_leaderboard(self, decisions_log: list) -> list[dict]:
        cards = self.compute_all(decisions_log)
        return [
            {
                "agent_id": item["agent_id"],
                "rank": item["rank"],
                "overall_score": item["overall_score"],
                "grade": item["grade"],
                "badges": list(item.get("badges", [])),
            }
            for item in cards
        ]

    def assign_badges(self, scorecard: dict, all_scores: list[dict]) -> list[str]:
        """Assign achievement badges based on relative performance."""
        if not isinstance(scorecard, dict) or not isinstance(all_scores, list) or not all_scores:
            return []
        badges: list[str] = []
        agent_id = str(scorecard.get("agent_id", ""))
        by_id = {str(item.get("agent_id", "")): item for item in all_scores if isinstance(item, dict)}
        current = by_id.get(agent_id, scorecard)
        top = all_scores[0] if all_scores else {}
        if str(top.get("agent_id", "")) == agent_id:
            badges.append("🏆 Top Performer")
        best_cost = max(
            (float(item.get("metrics", {}).get("cost_efficiency", 0.0)) for item in all_scores if isinstance(item, dict)),
            default=0.0,
        )
        if float(current.get("metrics", {}).get("cost_efficiency", 0.0)) >= best_cost and best_cost > 0.0:
            badges.append("💡 Most Efficient")
        best_cache = max(
            (float(item.get("metrics", {}).get("cache_hit_rate", 0.0)) for item in all_scores if isinstance(item, dict)),
            default=0.0,
        )
        if float(current.get("metrics", {}).get("cache_hit_rate", 0.0)) >= best_cache and best_cache >= 80.0:
            badges.append("⚡ Cache Master")
        return badges
