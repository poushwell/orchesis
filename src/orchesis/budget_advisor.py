"""Budget recommendation helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if hasattr(item, "__dict__"):
        raw = getattr(item, "__dict__", {})
        if isinstance(raw, dict):
            return raw
    return {}


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


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


class BudgetAdvisor:
    """Generates budget recommendations from spending patterns."""

    def analyze(self, decisions_log: list, current_budget: dict) -> dict:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=24)
        agent_spend: dict[str, float] = {}
        session_spend: dict[str, float] = {}
        daily_spend = 0.0
        loop_waste = 0.0
        cache_miss_waste = 0.0

        for item in decisions_log:
            row = _as_dict(item)
            ts = _parse_ts(row.get("timestamp"))
            if ts is not None and ts < since:
                continue
            snapshot = row.get("state_snapshot")
            if not isinstance(snapshot, dict):
                snapshot = {}
            cost = _as_float(row.get("cost"))
            daily_spend += cost
            agent_id = str(row.get("agent_id") or "unknown")
            session_id = str(snapshot.get("session_id") or row.get("session_id") or "__default__")
            agent_spend[agent_id] = _as_float(agent_spend.get(agent_id)) + cost
            session_spend[session_id] = _as_float(session_spend.get(session_id)) + cost

            # Loop waste can come from explicit metrics or inferred repeated retries.
            loop_saved = _as_float(snapshot.get("loop_cost_saved_usd", snapshot.get("cost_saved_loop_usd", 0.0)))
            is_loop = bool(snapshot.get("loop_detected")) or ("loop" in str(row.get("reasons", "")).lower())
            loop_waste += loop_saved
            if is_loop:
                loop_waste += cost * 0.60

            # Cache miss waste (when we had to pay for work that could be cached).
            miss_waste = _as_float(snapshot.get("cache_miss_waste_usd", 0.0))
            hit_rate = snapshot.get("cache_hit_rate")
            if isinstance(hit_rate, int | float):
                bounded = max(0.0, min(1.0, float(hit_rate)))
                miss_waste += cost * (1.0 - bounded) * 0.25
            cache_miss_waste += miss_waste

        daily_spend = round(daily_spend, 6)
        projected_monthly = round(daily_spend * 30.0, 6)
        loop_waste = round(loop_waste, 6)
        cache_miss_waste = round(cache_miss_waste, 6)
        total_waste = round(loop_waste + cache_miss_waste, 6)

        top_agents = sorted(agent_spend.items(), key=lambda row: row[1], reverse=True)[:5]
        top_sessions = sorted(session_spend.items(), key=lambda row: row[1], reverse=True)[:5]
        top_spenders = [
            {"kind": "agent", "id": key, "cost": round(value, 6)} for key, value in top_agents
        ] + [{"kind": "session", "id": key, "cost": round(value, 6)} for key, value in top_sessions]

        daily_limit = _as_float(
            current_budget.get("daily_limit_usd", current_budget.get("daily", current_budget.get("budget_daily", 0.0)))
        )
        recommendations: list[dict[str, Any]] = []

        if cache_miss_waste > 0.01:
            recommendations.append(
                {
                    "type": "enable_cache",
                    "reason": "Cache miss waste is significant; improve hit rate to reduce recurring spend.",
                    "suggested_value": 0.70,
                    "estimated_savings": round(cache_miss_waste * 30.0, 6),
                    "priority": "high" if cache_miss_waste > 0.10 else "medium",
                }
            )

        if total_waste > max(0.01, daily_spend * 0.20):
            recommendations.append(
                {
                    "type": "decrease",
                    "reason": "Waste is high relative to current daily spend.",
                    "suggested_value": round(max(0.0, daily_spend * 0.90), 6),
                    "estimated_savings": round(total_waste * 0.50, 6),
                    "priority": "high",
                }
            )

        if daily_limit > 0.0 and daily_spend > daily_limit * 0.85:
            recommendations.append(
                {
                    "type": "increase",
                    "reason": "Current spend is close to configured daily budget limit.",
                    "suggested_value": round(daily_limit * 1.20, 6),
                    "estimated_savings": 0.0,
                    "priority": "medium",
                }
            )

        if top_agents:
            top_agent, top_cost = top_agents[0]
            if daily_spend > 0.0 and (top_cost / daily_spend) >= 0.45:
                recommendations.append(
                    {
                        "type": "set_per_agent",
                        "reason": f"Agent {top_agent} dominates daily spend; set an explicit per-agent limit.",
                        "suggested_value": round(top_cost * 1.10, 6),
                        "estimated_savings": round(top_cost * 0.15, 6),
                        "priority": "medium",
                    }
                )

        if not recommendations:
            recommendations.append(
                {
                    "type": "enable_cache",
                    "reason": "No major anomalies detected; keep improving cache efficiency.",
                    "suggested_value": 0.60,
                    "estimated_savings": round(max(0.0, daily_spend * 0.05), 6),
                    "priority": "low",
                }
            )

        return {
            "current_daily_spend": daily_spend,
            "projected_monthly": projected_monthly,
            "recommendations": recommendations,
            "top_spenders": top_spenders[:10],
            "waste_detected": {
                "loop_waste": loop_waste,
                "cache_miss_waste": cache_miss_waste,
                "total_waste": total_waste,
            },
        }

    def get_quick_wins(self, analysis: dict) -> list[str]:
        """Returns top 3 actionable recommendations."""
        if not isinstance(analysis, dict):
            return []
        recs = analysis.get("recommendations")
        if not isinstance(recs, list):
            return []
        priority_rank = {"high": 0, "medium": 1, "low": 2}
        ordered = sorted(
            [item for item in recs if isinstance(item, dict)],
            key=lambda item: (
                priority_rank.get(str(item.get("priority", "low")), 3),
                -_as_float(item.get("estimated_savings", 0.0)),
            ),
        )
        wins: list[str] = []
        for item in ordered[:3]:
            kind = str(item.get("type", "recommendation")).replace("_", " ")
            reason = str(item.get("reason", "")).strip()
            value = _as_float(item.get("suggested_value", 0.0))
            wins.append(f"{kind.title()}: {reason} (target {value:.2f})")
        return wins
