"""Session activity heatmap utilities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class SessionHeatmap:
    """Generates heatmap data from session activity."""

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _event_value(event: Any, key: str, default: Any = None) -> Any:
        if isinstance(event, dict):
            return event.get(key, default)
        return getattr(event, key, default)

    def compute(self, decisions_log: list, days: int = 7) -> dict:
        safe_days = max(1, min(31, int(days)))
        now = datetime.now(timezone.utc)
        start_date = (now - timedelta(days=safe_days - 1)).date()
        date_series = [start_date + timedelta(days=offset) for offset in range(safe_days)]
        date_set = set(date_series)

        buckets: dict[tuple[Any, int], dict[str, Any]] = {}
        for day in date_series:
            for hour in range(24):
                buckets[(day, hour)] = {"count": 0, "cost": 0.0, "blocked": 0}

        for event in decisions_log if isinstance(decisions_log, list) else []:
            ts = self._parse_ts(self._event_value(event, "timestamp", ""))
            if ts is None:
                continue
            day = ts.date()
            if day not in date_set:
                continue
            hour = int(ts.hour)
            cell = buckets[(day, hour)]
            cell["count"] += 1
            try:
                cell["cost"] += float(self._event_value(event, "cost", 0.0) or 0.0)
            except (TypeError, ValueError):
                pass
            decision_raw = str(self._event_value(event, "decision", "") or "").upper()
            allowed_raw = self._event_value(event, "allowed", None)
            blocked = decision_raw == "DENY" or (allowed_raw is False)
            if blocked:
                cell["blocked"] += 1

        max_count = max((int(info["count"]) for info in buckets.values()), default=0)
        cells: list[dict[str, Any]] = []
        peak = {"day": "", "hour": 0, "count": 0}
        quiet = {"day": "", "hour": 0, "count": 0}
        quiet_set = False

        for day in date_series:
            for hour in range(24):
                info = buckets[(day, hour)]
                count = int(info["count"])
                cost = float(info["cost"])
                blocked = int(info["blocked"])
                intensity = (float(count) / float(max_count)) if max_count > 0 else 0.0
                row = {
                    "day": day.strftime("%a"),
                    "hour": hour,
                    "count": count,
                    "cost": round(cost, 8),
                    "blocked": blocked,
                    "intensity": round(max(0.0, min(1.0, intensity)), 6),
                }
                cells.append(row)
                if count > int(peak["count"]):
                    peak = {"day": row["day"], "hour": hour, "count": count}
                if (not quiet_set) or count < int(quiet["count"]):
                    quiet = {"day": row["day"], "hour": hour, "count": count}
                    quiet_set = True

        total_requests = sum(int(cell["count"]) for cell in cells)
        return {
            "days": safe_days,
            "cells": cells,
            "peak": peak,
            "quiet": quiet,
            "total_requests": total_requests,
        }

    def get_daily_summary(self, decisions_log: list) -> list[dict]:
        """Per-day totals for last 7 days."""
        payload = self.compute(decisions_log, days=7)
        daily: dict[str, dict[str, Any]] = {}
        for cell in payload["cells"]:
            day = str(cell.get("day", ""))
            item = daily.setdefault(day, {"day": day, "count": 0, "cost": 0.0, "blocked": 0})
            item["count"] += int(cell.get("count", 0) or 0)
            item["cost"] += float(cell.get("cost", 0.0) or 0.0)
            item["blocked"] += int(cell.get("blocked", 0) or 0)
        return [
            {"day": item["day"], "count": int(item["count"]), "cost": round(float(item["cost"]), 8), "blocked": int(item["blocked"])}
            for item in daily.values()
        ]
