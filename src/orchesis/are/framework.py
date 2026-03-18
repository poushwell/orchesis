"""ARE framework for agent reliability engineering."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
from typing import Any


class AREFramework:
    """ARE — Agent Reliability Engineering.

    SRE for AI agents. Defines reliability as a discipline.
    Error budgets, SLOs, SLIs for AI agent systems.
    """

    SLI_DEFINITIONS = {
        "availability": "Fraction of requests served successfully",
        "latency_p99": "99th percentile response latency",
        "error_rate": "Fraction of requests resulting in errors",
        "token_yield": "Semantic value per token consumed",
        "security_rate": "Fraction of threats successfully blocked",
    }

    def __init__(self):
        self._slos: dict[str, dict[str, Any]] = {}
        self._sli_history: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_ts(value: str) -> datetime | None:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def define_slo(self, name: str, sli: str, target: float, window_days: int = 30) -> dict:
        """Define a Service Level Objective."""
        slo_name = str(name or "").strip()
        sli_name = str(sli or "").strip()
        if not slo_name:
            raise ValueError("slo name is required")
        if sli_name not in self.SLI_DEFINITIONS:
            raise ValueError(f"unknown sli: {sli_name}")
        row = {
            "name": slo_name,
            "sli": sli_name,
            "target": float(target),
            "window_days": max(1, int(window_days)),
            "defined_at": self._now_iso(),
        }
        with self._lock:
            self._slos[slo_name] = row
            self._sli_history.setdefault(slo_name, [])
        return dict(row)

    def record_sli(self, name: str, value: float) -> None:
        """Record SLI measurement."""
        slo_name = str(name or "").strip()
        with self._lock:
            if slo_name not in self._slos:
                raise KeyError(f"slo not found: {slo_name}")
            self._sli_history.setdefault(slo_name, []).append(
                {"timestamp": self._now_iso(), "value": float(value)}
            )

    def _window_values(self, slo_name: str) -> list[float]:
        slo = self._slos.get(slo_name)
        if not isinstance(slo, dict):
            return []
        window_days = max(1, int(slo.get("window_days", 30)))
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        values: list[float] = []
        for row in self._sli_history.get(slo_name, []):
            if not isinstance(row, dict):
                continue
            ts = self._parse_ts(str(row.get("timestamp", "")))
            if ts is None or ts < cutoff:
                continue
            try:
                values.append(float(row.get("value", 0.0)))
            except (TypeError, ValueError):
                continue
        return values

    def get_error_budget(self, slo_name: str) -> dict:
        values = self._window_values(slo_name)
        if slo_name not in self._slos:
            raise KeyError(f"slo not found: {slo_name}")
        slo = self._slos[slo_name]
        target = float(slo.get("target", 0.0))
        current = sum(values) / len(values) if values else 0.0
        sli = str(slo.get("sli", "availability"))
        lower_better = sli in {"latency_p99", "error_rate"}
        if lower_better:
            budget_remaining = max(0.0, target - current)
            burn_rate = (max(0.0, current - target) / target) if target > 0 else 0.0
            exhausted = current > target
        else:
            budget_remaining = max(0.0, current - target)
            burn_rate = (max(0.0, target - current) / target) if target > 0 else 0.0
            exhausted = current < target
        return {
            "slo_name": str(slo_name),
            "target": round(target, 6),
            "current": round(float(current), 6),
            "budget_remaining": round(float(budget_remaining), 6),
            "burn_rate": round(float(burn_rate), 6),
            "exhausted": bool(exhausted),
        }

    def get_reliability_report(self) -> dict:
        """Full reliability report across all SLOs."""
        with self._lock:
            names = sorted(self._slos.keys())
        entries = [self.get_error_budget(name) for name in names]
        exhausted_count = sum(1 for row in entries if bool(row.get("exhausted", False)))
        return {
            "slos": entries,
            "total_slos": len(entries),
            "exhausted": exhausted_count,
            "healthy": len(entries) - exhausted_count,
        }

    def get_burn_rate_alert(self, slo_name: str) -> dict | None:
        """Alert if error budget burning too fast."""
        budget = self.get_error_budget(slo_name)
        burn_rate = float(budget.get("burn_rate", 0.0))
        if burn_rate < 0.5 and not bool(budget.get("exhausted", False)):
            return None
        severity = "critical" if burn_rate >= 1.0 or bool(budget.get("exhausted", False)) else "warning"
        return {
            "slo_name": str(slo_name),
            "burn_rate": round(burn_rate, 6),
            "severity": severity,
            "message": f"Error budget burn too high for {slo_name}",
        }

