"""Detailed inspection helpers for single requests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


PHASE_ORDER: list[str] = [
    "parse",
    "flow_xray",
    "cascade",
    "circuit_breaker",
    "loop_detection",
    "behavioral",
    "mast_request",
    "auto_healing",
    "budget",
    "policy",
    "threat_intel",
    "model_router",
    "secrets",
    "context",
    "upstream",
    "post_upstream",
    "send",
]


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if hasattr(item, "__dict__"):
        raw = getattr(item, "__dict__", {})
        if isinstance(raw, dict):
            return raw
    return {}


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RequestInspector:
    """Detailed inspection of a single request through pipeline."""

    def inspect(self, request_id: str, decisions_log: list) -> dict:
        target = str(request_id or "").strip()
        if not target:
            return {}
        row: dict[str, Any] | None = None
        for item in decisions_log:
            payload = _as_dict(item)
            event_id = str(payload.get("event_id", payload.get("request_id", "")) or "")
            if event_id == target:
                row = payload
                break
        if row is None:
            return {}

        decision = str(row.get("decision", "ALLOW") or "ALLOW").upper()
        timestamp = str(row.get("timestamp", "") or _now_iso())
        agent_id = str(row.get("agent_id", "__global__") or "__global__")
        tool = str(row.get("tool", "") or "")
        reasons_raw = row.get("reasons", [])
        reasons = [str(item) for item in reasons_raw if isinstance(item, str)] if isinstance(reasons_raw, list) else []
        eval_order_raw = row.get("evaluation_order", [])
        evaluation_order = [str(item) for item in eval_order_raw if isinstance(item, str)] if isinstance(eval_order_raw, list) else []
        total_duration_us = _as_int(row.get("evaluation_duration_us", row.get("evaluation_us", 0)))
        cost = _as_float(row.get("cost", 0.0))
        triggered_raw = row.get("rules_triggered", [])
        rules_triggered = [str(item) for item in triggered_raw if isinstance(item, str)] if isinstance(triggered_raw, list) else []
        run_set = set(evaluation_order)
        blocking_index = max(0, len(evaluation_order) - 1) if decision == "DENY" and evaluation_order else -1
        warn_index = max(0, len(evaluation_order) - 1) if decision == "ALLOW" and reasons and evaluation_order else -1
        active_count = max(1, len(evaluation_order))
        phase_duration = total_duration_us // active_count if active_count > 0 else 0
        phases: list[dict[str, Any]] = []
        for idx, phase_name in enumerate(PHASE_ORDER, start=1):
            if phase_name not in run_set:
                result = "skip"
                duration_us = 0
            else:
                run_idx = evaluation_order.index(phase_name)
                if blocking_index >= 0 and run_idx == blocking_index:
                    result = "block"
                elif warn_index >= 0 and run_idx == warn_index:
                    result = "warn"
                else:
                    result = "pass"
                duration_us = phase_duration
            details: dict[str, Any] = {
                "executed": phase_name in run_set,
                "rules_triggered": list(rules_triggered) if phase_name == "policy" else [],
            }
            if phase_name == "policy":
                details["reasons"] = list(reasons)
            phases.append(
                {
                    "phase_number": idx,
                    "phase_name": phase_name,
                    "result": result,
                    "duration_us": int(duration_us),
                    "details": details,
                }
            )

        return {
            "request_id": target,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "tool": tool,
            "final_decision": "DENY" if decision == "DENY" else "ALLOW",
            "phases": phases,
            "total_duration_us": int(total_duration_us),
            "cost": float(cost),
            "reasons": reasons,
        }

    def find_blocking_phase(self, inspection: dict) -> dict | None:
        """Returns the phase that blocked the request."""
        if not isinstance(inspection, dict):
            return None
        phases = inspection.get("phases", [])
        if not isinstance(phases, list):
            return None
        for item in phases:
            if isinstance(item, dict) and str(item.get("result", "")).lower() == "block":
                return item
        return None

    def get_timeline(self, inspection: dict) -> list[dict]:
        """Returns phases as timeline events."""
        if not isinstance(inspection, dict):
            return []
        phases = inspection.get("phases", [])
        if not isinstance(phases, list):
            return []
        cursor = 0
        timeline: list[dict[str, Any]] = []
        for item in phases:
            if not isinstance(item, dict):
                continue
            duration = _as_int(item.get("duration_us", 0))
            event = {
                "phase_number": _as_int(item.get("phase_number", 0)),
                "phase_name": str(item.get("phase_name", "")),
                "result": str(item.get("result", "skip")),
                "start_us": cursor,
                "end_us": cursor + max(0, duration),
                "duration_us": max(0, duration),
            }
            timeline.append(event)
            cursor += max(0, duration)
        return timeline
