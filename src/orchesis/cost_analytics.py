"""Cost analytics helpers for dashboard and API."""

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


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


class CostAnalytics:
    """Detailed cost breakdown and forecasting."""

    def compute(self, decisions_log: list[Any], period_hours: int = 24) -> dict[str, Any]:
        safe_period = max(1, int(period_hours))
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=safe_period)

        model_cost: dict[str, float] = {}
        agent_cost: dict[str, float] = {}
        hour_cost: dict[str, float] = {}
        session_cost: dict[str, float] = {}
        savings = {
            "cache": 0.0,
            "loop_prevention": 0.0,
            "compression": 0.0,
        }

        for item in decisions_log:
            row = _as_dict(item)
            ts = _parse_ts(row.get("timestamp"))
            if ts is None or ts < since:
                continue

            snapshot = row.get("state_snapshot")
            if not isinstance(snapshot, dict):
                snapshot = {}

            cost = _as_float(row.get("cost"))
            model = str(snapshot.get("model") or row.get("model") or "unknown")
            agent = str(row.get("agent_id") or "unknown")
            session_id = str(snapshot.get("session_id") or row.get("session_id") or "__default__")
            hour_key = ts.strftime("%Y-%m-%d %H:00")

            model_cost[model] = _as_float(model_cost.get(model)) + cost
            agent_cost[agent] = _as_float(agent_cost.get(agent)) + cost
            hour_cost[hour_key] = _as_float(hour_cost.get(hour_key)) + cost
            session_cost[session_id] = _as_float(session_cost.get(session_id)) + cost

            # Support multiple key names so analytics works across old/new logs.
            savings["cache"] += _as_float(
                snapshot.get("cache_cost_saved_usd", snapshot.get("cost_saved_cache_usd", 0.0))
            )
            savings["loop_prevention"] += _as_float(
                snapshot.get("loop_cost_saved_usd", snapshot.get("cost_saved_loop_usd", 0.0))
            )
            savings["compression"] += _as_float(
                snapshot.get("compression_cost_saved_usd", snapshot.get("cost_saved_compression_usd", 0.0))
            )

        total_cost = round(sum(model_cost.values()), 6)
        ordered_hours: list[dict[str, Any]] = []
        cursor = since.replace(minute=0, second=0, microsecond=0)
        for _ in range(safe_period):
            label = cursor.strftime("%Y-%m-%d %H:00")
            ordered_hours.append({"hour": label, "cost": round(_as_float(hour_cost.get(label)), 6)})
            cursor += timedelta(hours=1)

        top_sessions = sorted(
            ({"session_id": sid, "cost": round(value, 6)} for sid, value in session_cost.items()),
            key=lambda row: row["cost"],
            reverse=True,
        )[:5]

        savings["cache"] = round(savings["cache"], 6)
        savings["loop_prevention"] = round(savings["loop_prevention"], 6)
        savings["compression"] = round(savings["compression"], 6)
        savings["total"] = round(savings["cache"] + savings["loop_prevention"] + savings["compression"], 6)

        forecast_24h = round((total_cost / float(safe_period)) * 24.0, 6)
        return {
            "period_hours": safe_period,
            "total_cost": total_cost,
            "cost_by_model": {k: round(v, 6) for k, v in sorted(model_cost.items(), key=lambda x: x[1], reverse=True)},
            "cost_by_agent": {k: round(v, 6) for k, v in sorted(agent_cost.items(), key=lambda x: x[1], reverse=True)},
            "cost_by_hour": ordered_hours,
            "top_expensive_sessions": top_sessions,
            "forecast_24h": forecast_24h,
            "savings": savings,
        }
