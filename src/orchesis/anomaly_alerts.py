"""Anomaly alert manager based on Context DNA deviation."""

from __future__ import annotations

import time
from uuid import uuid4
from typing import Any


class AnomalyAlertManager:
    """Generates alerts when agent behavior deviates from baseline."""

    MAX_ENTRIES = 10_000

    ALERT_TYPES = {
        "cost_spike": "Cost increased >3x vs baseline",
        "tool_abuse": "Unusual tool call frequency",
        "prompt_inflation": "Prompt length growing abnormally",
        "session_duration": "Session running unusually long",
        "error_rate": "Error rate above threshold",
        "cache_miss_surge": "Cache hit rate dropped significantly",
    }

    _SEVERITY = {
        "cost_spike": "high",
        "tool_abuse": "medium",
        "prompt_inflation": "medium",
        "session_duration": "medium",
        "error_rate": "critical",
        "cache_miss_surge": "medium",
    }

    def __init__(self, dna_store: Any, config: dict | None = None):
        self.dna_store = dna_store
        cfg = config if isinstance(config, dict) else {}
        self.threshold = float(cfg.get("anomaly_threshold", 0.5))
        self._alerts: list[dict[str, Any]] = []

    @staticmethod
    def _as_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def _active_exists(self, agent_id: str, alert_type: str) -> bool:
        for item in self._alerts:
            if item.get("dismissed"):
                continue
            if str(item.get("agent_id")) == str(agent_id) and str(item.get("type")) == str(alert_type):
                return True
        return False

    def _emit(
        self,
        agent_id: str,
        alert_type: str,
        current: float,
        baseline: float,
    ) -> dict[str, Any] | None:
        if self._active_exists(agent_id, alert_type):
            return None
        alert = {
            "id": str(uuid4()),
            "agent_id": str(agent_id),
            "type": str(alert_type),
            "message": self.ALERT_TYPES.get(alert_type, "Behavior deviation detected"),
            "severity": self._SEVERITY.get(alert_type, "medium"),
            "timestamp": float(time.time()),
            "current": float(current),
            "baseline": float(baseline),
            "dismissed": False,
        }
        self._alerts.append(alert)
        if len(self._alerts) > self.MAX_ENTRIES:
            # Keep most recent alerts only.
            self._alerts = self._alerts[-self.MAX_ENTRIES :]
        return alert

    def check(self, agent_id: str, current_stats: dict) -> list[dict]:
        """Check for anomalies. Returns new alerts."""
        dna = self.dna_store.get(agent_id) if self.dna_store is not None else None
        baseline = {}
        if dna is not None and isinstance(getattr(dna, "baseline", None), dict):
            baseline = dict(getattr(dna, "baseline"))
        if not baseline:
            return []

        current = current_stats if isinstance(current_stats, dict) else {}
        created: list[dict[str, Any]] = []
        th = max(0.01, float(self.threshold))

        current_cost = self._as_float(current.get("cost_per_request"))
        baseline_cost = self._as_float(baseline.get("cost_per_request"))
        if baseline_cost > 0.0 and current_cost > baseline_cost * 3.0:
            alert = self._emit(agent_id, "cost_spike", current_cost, baseline_cost)
            if alert:
                created.append(alert)

        current_tool = self._as_float(current.get("tool_call_frequency"))
        baseline_tool = self._as_float(baseline.get("tool_call_frequency"))
        if baseline_tool > 0.0 and current_tool > baseline_tool * (1.0 + (2.0 * th)):
            alert = self._emit(agent_id, "tool_abuse", current_tool, baseline_tool)
            if alert:
                created.append(alert)

        current_prompt = self._as_float(current.get("avg_prompt_length"))
        baseline_prompt = self._as_float(baseline.get("avg_prompt_length"))
        if baseline_prompt > 0.0 and current_prompt > baseline_prompt * (1.0 + (2.0 * th)):
            alert = self._emit(agent_id, "prompt_inflation", current_prompt, baseline_prompt)
            if alert:
                created.append(alert)

        current_duration = self._as_float(current.get("session_duration_avg"))
        baseline_duration = self._as_float(baseline.get("session_duration_avg"))
        if baseline_duration > 0.0 and current_duration > baseline_duration * (1.0 + (2.0 * th)):
            alert = self._emit(agent_id, "session_duration", current_duration, baseline_duration)
            if alert:
                created.append(alert)

        current_error = self._as_float(current.get("error_rate"))
        baseline_error = self._as_float(baseline.get("error_rate"))
        if current_error > max(baseline_error + (0.2 * th), 0.2):
            alert = self._emit(agent_id, "error_rate", current_error, baseline_error)
            if alert:
                created.append(alert)

        current_cache = self._as_float(current.get("cache_hit_rate"))
        baseline_cache = self._as_float(baseline.get("cache_hit_rate"))
        if baseline_cache > 0.0 and current_cache < max(0.0, baseline_cache - max(0.15, 0.3 * th)):
            alert = self._emit(agent_id, "cache_miss_surge", current_cache, baseline_cache)
            if alert:
                created.append(alert)

        return created

    def get_alerts(
        self,
        agent_id: str | None = None,
        since: float | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get alerts with optional filtering."""
        rows = [item for item in self._alerts if not bool(item.get("dismissed"))]
        if isinstance(agent_id, str) and agent_id.strip():
            rows = [item for item in rows if str(item.get("agent_id")) == agent_id]
        if isinstance(since, int | float):
            rows = [item for item in rows if self._as_float(item.get("timestamp")) >= float(since)]
        rows.sort(key=lambda item: self._as_float(item.get("timestamp")), reverse=True)
        return rows[: max(1, min(500, int(limit)))]

    def dismiss(self, alert_id: str) -> bool:
        """Dismiss an alert."""
        target = str(alert_id)
        for item in self._alerts:
            if str(item.get("id")) != target:
                continue
            if bool(item.get("dismissed")):
                return False
            item["dismissed"] = True
            item["dismissed_at"] = float(time.time())
            return True
        return False

    def get_summary(self) -> dict:
        """Alert counts by type and severity."""
        active = [item for item in self._alerts if not bool(item.get("dismissed"))]
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for item in active:
            t = str(item.get("type", "unknown"))
            s = str(item.get("severity", "medium"))
            by_type[t] = by_type.get(t, 0) + 1
            by_severity[s] = by_severity.get(s, 0) + 1
        return {
            "total_active": len(active),
            "total_all": len(self._alerts),
            "by_type": by_type,
            "by_severity": by_severity,
        }
