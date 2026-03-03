"""Generate cost reports in multiple formats."""

from __future__ import annotations

from datetime import date
from typing import Any


class CostReporter:
    """Generates cost reports from CostTracker data."""

    def __init__(self, cost_tracker, loop_detector=None):
        self._tracker = cost_tracker
        self._loop = loop_detector

    def daily_summary(self, day: str | None = None) -> dict[str, Any]:
        safe_day = day or date.today().isoformat()
        tool_costs = self._tracker.get_tool_costs(safe_day)
        hourly = self._tracker.get_hourly_costs(safe_day)
        total = self._tracker.get_daily_total(safe_day)
        top_tools = sorted(tool_costs.items(), key=lambda item: item[1], reverse=True)

        raw = self._tracker.to_dict().get("calls", [])
        total_calls = 0
        for call in raw:
            ts = call.get("timestamp")
            try:
                call_day = date.fromtimestamp(float(ts)).isoformat()
            except Exception:
                continue
            if call_day == safe_day:
                total_calls += 1

        summary: dict[str, Any] = {
            "date": safe_day,
            "total_usd": round(total, 4),
            "top_tools": [{"tool": tool, "cost_usd": round(cost, 4)} for tool, cost in top_tools[:10]],
            "hourly_breakdown": {str(hour): round(cost, 4) for hour, cost in sorted(hourly.items())},
            "total_calls": total_calls,
        }
        if self._loop is not None:
            loop_stats = self._loop.get_stats()
            summary["loops"] = loop_stats
            summary["saved_by_loop_detection"] = loop_stats.get("total_saved_usd", 0.0)
        return summary

    def format_console(self, summary: dict[str, Any] | None = None) -> str:
        payload = summary or self.daily_summary()
        lines = [
            f"=== Orchesis Cost Report: {payload['date']} ===",
            f"Total: ${payload['total_usd']:.4f} ({payload['total_calls']} calls)",
            "",
            "Top tools by cost:",
        ]
        top_tools = payload.get("top_tools", [])
        if not top_tools:
            lines.append("  (no calls)")
        else:
            for item in top_tools[:5]:
                lines.append(f"  {item['tool']}: ${item['cost_usd']:.4f}")
        if "loops" in payload and payload["loops"].get("total_loops_detected", 0) > 0:
            lines.extend(
                [
                    "",
                    f"Loop detection: {payload['loops']['loops_blocked']} blocked, {payload['loops']['loops_warned']} warned",
                    f"Saved by loop detection: ${payload.get('saved_by_loop_detection', 0):.4f}",
                ]
            )
        return "\n".join(lines)

    def format_markdown(self, summary: dict[str, Any] | None = None) -> str:
        payload = summary or self.daily_summary()
        lines = [
            f"# Orchesis Cost Report: {payload['date']}",
            "",
            f"**Total:** ${payload['total_usd']:.4f} ({payload['total_calls']} calls)",
            "",
            "## Top Tools by Cost",
            "",
            "| Tool | Cost |",
            "|------|------|",
        ]
        top_tools = payload.get("top_tools", [])
        if not top_tools:
            lines.append("| (no calls) | $0.0000 |")
        else:
            for item in top_tools:
                lines.append(f"| {item['tool']} | ${item['cost_usd']:.4f} |")
        hourly = payload.get("hourly_breakdown", {})
        if hourly:
            lines.extend(["", "## Hourly Breakdown", ""])
            for hour, cost in sorted(hourly.items(), key=lambda item: int(item[0])):
                lines.append(f"- {hour}:00 - ${cost:.4f}")
        if "loops" in payload:
            lines.extend(
                [
                    "",
                    "## Loop Detection",
                    f"- Loops blocked: {payload['loops']['loops_blocked']}",
                    f"- Loops warned: {payload['loops']['loops_warned']}",
                    f"- Money saved: ${payload.get('saved_by_loop_detection', 0):.4f}",
                ]
            )
        return "\n".join(lines)

