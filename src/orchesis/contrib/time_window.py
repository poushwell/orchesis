"""Plugin: Allow tool calls only during specific hours."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from orchesis.plugins import PluginInfo


class TimeWindowHandler:
    def _now(self, tz_name: str) -> datetime:
        zone = ZoneInfo(tz_name)
        return datetime.now(timezone.utc).astimezone(zone)

    def _parse_minutes(self, value: str) -> int:
        hour_text, minute_text = value.split(":", 1)
        hour = int(hour_text)
        minute = int(minute_text)
        if hour < 0 or hour > 23 or minute < 0 or minute > 59:
            raise ValueError("invalid time range")
        return hour * 60 + minute

    def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
        _ = (request, kwargs)
        checked = ["time_window"]
        window = rule.get("allowed_hours")
        if not isinstance(window, dict):
            return ["time_window: allowed_hours is required"], checked
        start = window.get("start")
        end = window.get("end")
        tz_name = window.get("timezone", "UTC")
        if not isinstance(start, str) or not isinstance(end, str) or not isinstance(tz_name, str):
            return ["time_window: allowed_hours requires start/end/timezone"], checked
        try:
            current = self._now(tz_name)
            now_minutes = current.hour * 60 + current.minute
            start_minutes = self._parse_minutes(start)
            end_minutes = self._parse_minutes(end)
        except Exception:
            return ["time_window: invalid allowed_hours configuration"], checked
        if start_minutes <= end_minutes:
            in_window = start_minutes <= now_minutes <= end_minutes
        else:
            in_window = now_minutes >= start_minutes or now_minutes <= end_minutes
        if not in_window:
            return [f"time_window: outside allowed window {start}-{end} {tz_name}"], checked
        return [], checked


PLUGIN_INFO = PluginInfo(
    name="time_window",
    rule_type="time_window",
    version="1.0",
    description="Allow tool calls only during specific hours",
    handler=TimeWindowHandler(),
)
