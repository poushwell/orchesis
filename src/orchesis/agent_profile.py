"""Agent intelligence profile for dashboard display."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.replay import read_events_from_jsonl


class AgentIntelligenceProfile:
    """Aggregates agent knowledge for dashboard display."""

    def build(self, agent_id: str, dna_store, health_score, decisions_log) -> dict:
        now = time.time()
        dna = dna_store.get(agent_id) if dna_store is not None else None
        baseline = {}
        profile_age_hours = 0.0
        cold_start = True
        if dna is not None:
            exported = dna.export()
            baseline = exported.get("baseline", {}) if isinstance(exported.get("baseline"), dict) else {}
            created_at = exported.get("created_at")
            if isinstance(created_at, int | float):
                profile_age_hours = max(0.0, (now - float(created_at)) / 3600.0)
            cold_start = bool(exported.get("cold_start", True))

        decisions_path = Path(str(decisions_log))
        events = [e for e in read_events_from_jsonl(decisions_path) if e.agent_id == agent_id]
        events.sort(key=lambda item: str(item.timestamp))

        tool_counts: dict[str, int] = {}
        deny_count = 0
        total_cost = 0.0
        alerts: list[dict[str, Any]] = []
        by_day: dict[str, dict[str, int]] = {}
        for event in events:
            tool_counts[event.tool] = tool_counts.get(event.tool, 0) + 1
            if event.decision == "DENY":
                deny_count += 1
                reason = event.reasons[0] if event.reasons else "blocked_by_policy"
                alerts.append(
                    {
                        "timestamp": event.timestamp,
                        "severity": "high" if "exceeded" in reason.lower() else "medium",
                        "reason": reason,
                    }
                )
            total_cost += float(event.cost or 0.0)
            day_key = str(event.timestamp)[:10]
            bucket = by_day.setdefault(day_key, {"total": 0, "deny": 0})
            bucket["total"] += 1
            if event.decision == "DENY":
                bucket["deny"] += 1

        detected_patterns: list[str] = []
        top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)
        if top_tools:
            tool_name, tool_count = top_tools[0]
            if tool_count >= 2:
                detected_patterns.append(f"Uses {tool_name} frequently")
        if events and deny_count == 0:
            detected_patterns.append("Stable policy compliance")

        cost_optimizations: list[str] = []
        cache_hit_rate = float(baseline.get("cache_hit_rate", 0.0) or 0.0)
        if cache_hit_rate > 0.0 and total_cost > 0.0:
            saved = round(total_cost * min(0.8, cache_hit_rate) * 0.25, 2)
            cost_optimizations.append(f"Saved ${saved:.2f} via cache")
        if events and deny_count > 0:
            cost_optimizations.append("Policy denials reduced potential downstream spend")

        reliability_history: list[float] = []
        today = datetime.now(timezone.utc).date()
        for days_ago in range(6, -1, -1):
            day = today.fromordinal(today.toordinal() - days_ago).isoformat()
            stats = by_day.get(day, {"total": 0, "deny": 0})
            total = int(stats.get("total", 0))
            deny = int(stats.get("deny", 0))
            score = 1.0 if total == 0 else max(0.0, min(1.0, 1.0 - (deny / float(total))))
            reliability_history.append(round(score, 4))
        if not any(reliability_history) and isinstance(health_score, dict):
            score_raw = health_score.get("score", health_score.get("health_score", 1.0))
            try:
                score = float(score_raw)
            except (TypeError, ValueError):
                score = 1.0
            reliability_history = [round(score, 4)] * 7

        return {
            "agent_id": agent_id,
            "profile_age_hours": round(profile_age_hours, 4),
            "cold_start": cold_start,
            "baseline_metrics": {
                "avg_prompt_length": float(baseline.get("avg_prompt_length", 0.0) or 0.0),
                "tool_call_frequency": float(baseline.get("tool_call_frequency", 0.0) or 0.0),
                "cache_hit_rate": float(baseline.get("cache_hit_rate", 0.0) or 0.0),
                "error_rate": float(baseline.get("error_rate", 0.0) or 0.0),
            },
            "detected_patterns": detected_patterns,
            "cost_optimizations": cost_optimizations,
            "reliability_history": reliability_history,
            "anomaly_alerts": alerts[-20:],
        }

