"""Cost attribution engine for teams/projects/cost-centers."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import fnmatch
from typing import Any


class CostAttributionEngine:
    """Attributes costs to teams, projects, users."""

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        rules = cfg.get("rules", [])
        self._attribution_rules: list[dict] = [dict(item) for item in rules if isinstance(item, dict)]
        self._team_budgets = cfg.get("team_budgets", {}) if isinstance(cfg.get("team_budgets"), dict) else {}
        self._last_result: dict[str, Any] | None = None
        self._last_daily_team_costs: dict[str, dict[str, float]] = {}

    def add_rule(self, rule: dict) -> None:
        """Add attribution rule: {agent_pattern, team, project, cost_center}"""
        if isinstance(rule, dict):
            self._attribution_rules.append(dict(rule))

    @staticmethod
    def _event_value(event: Any, key: str, default: Any = None) -> Any:
        if isinstance(event, dict):
            return event.get(key, default)
        return getattr(event, key, default)

    @staticmethod
    def _parse_date(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            return datetime.now(timezone.utc).date().isoformat()
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc).date().isoformat()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.date().isoformat()

    def _match_rule(self, agent_id: str) -> dict[str, Any] | None:
        for rule in self._attribution_rules:
            pattern = str(rule.get("agent_pattern", "") or "")
            if pattern and fnmatch.fnmatch(agent_id, pattern):
                return rule
        return None

    @staticmethod
    def _update_bucket(bucket: dict[str, Any], key: str, agent_id: str, cost: float) -> None:
        row = bucket.setdefault(key, {"cost": 0.0, "requests": 0, "agents": []})
        row["cost"] = round(float(row.get("cost", 0.0)) + float(cost), 8)
        row["requests"] = int(row.get("requests", 0)) + 1
        agents = set(str(item) for item in row.get("agents", []) if isinstance(item, str))
        agents.add(agent_id)
        row["agents"] = sorted(agents)

    def attribute(self, decisions_log: list) -> dict:
        by_team: dict[str, Any] = {}
        by_project: dict[str, Any] = {}
        by_cost_center: dict[str, Any] = {}
        unattributed = {"cost": 0.0, "requests": 0, "agents": []}
        total = 0.0
        daily_team_costs: dict[str, dict[str, float]] = defaultdict(dict)

        for event in decisions_log if isinstance(decisions_log, list) else []:
            agent_id = str(self._event_value(event, "agent_id", "unknown") or "unknown")
            try:
                cost = float(self._event_value(event, "cost", 0.0) or 0.0)
            except (TypeError, ValueError):
                cost = 0.0
            total += cost
            rule = self._match_rule(agent_id)
            if not rule:
                unattributed["cost"] = round(float(unattributed["cost"]) + cost, 8)
                unattributed["requests"] = int(unattributed["requests"]) + 1
                agents = set(str(item) for item in unattributed["agents"])
                agents.add(agent_id)
                unattributed["agents"] = sorted(agents)
                continue

            team = str(rule.get("team", "unknown") or "unknown")
            project = str(rule.get("project", "") or "")
            cost_center = str(rule.get("cost_center", "") or "")
            self._update_bucket(by_team, team, agent_id, cost)
            if project:
                self._update_bucket(by_project, project, agent_id, cost)
            if cost_center:
                self._update_bucket(by_cost_center, cost_center, agent_id, cost)

            day = self._parse_date(self._event_value(event, "timestamp", ""))
            team_daily = daily_team_costs.setdefault(team, {})
            team_daily[day] = float(team_daily.get(day, 0.0)) + cost

        result = {
            "by_team": by_team,
            "by_project": by_project,
            "by_cost_center": by_cost_center,
            "unattributed": unattributed,
            "total": round(total, 8),
            "period": "all",
        }
        self._last_result = result
        self._last_daily_team_costs = {team: dict(day_costs) for team, day_costs in daily_team_costs.items()}
        return result

    def get_chargebacks(self, period: str = "month") -> list[dict]:
        """Generate chargeback report per team/project."""
        result = self._last_result if isinstance(self._last_result, dict) else {}
        teams = result.get("by_team", {}) if isinstance(result.get("by_team"), dict) else {}
        rows: list[dict[str, Any]] = []
        for team, payload in teams.items():
            if not isinstance(payload, dict):
                continue
            rows.append(
                {
                    "team": str(team),
                    "period": str(period),
                    "cost": round(float(payload.get("cost", 0.0)), 8),
                    "requests": int(payload.get("requests", 0)),
                    "agents": list(payload.get("agents", [])),
                }
            )
        rows.sort(key=lambda item: float(item.get("cost", 0.0)), reverse=True)
        return rows

    def forecast_by_team(self, team: str, days_ahead: int = 30) -> dict:
        """Forecast costs for team."""
        name = str(team or "")
        days = max(1, int(days_ahead))
        series = self._last_daily_team_costs.get(name, {})
        if not series:
            return {"team": name, "days_ahead": days, "forecast_cost": 0.0}
        avg_daily = sum(float(v) for v in series.values()) / max(1, len(series))
        return {
            "team": name,
            "days_ahead": days,
            "forecast_cost": round(avg_daily * days, 8),
            "avg_daily_cost": round(avg_daily, 8),
        }

    def get_budget_status(self, team: str) -> dict:
        """Team budget usage vs limit."""
        name = str(team or "")
        result = self._last_result if isinstance(self._last_result, dict) else {}
        teams = result.get("by_team", {}) if isinstance(result.get("by_team"), dict) else {}
        used = float(teams.get(name, {}).get("cost", 0.0)) if isinstance(teams.get(name), dict) else 0.0
        limit = float(self._team_budgets.get(name, 0.0) or 0.0)
        pct = (used / limit * 100.0) if limit > 0 else 0.0
        return {
            "team": name,
            "used": round(used, 8),
            "limit": round(limit, 8),
            "remaining": round(max(0.0, limit - used), 8),
            "percent_used": round(max(0.0, pct), 2),
            "over_budget": bool(limit > 0 and used > limit),
        }

