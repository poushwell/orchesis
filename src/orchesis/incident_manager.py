"""Incident management primitives."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any


class IncidentManager:
    """Tracks and manages security incidents."""

    SEVERITIES = ["low", "medium", "high", "critical"]
    STATUSES = ["open", "investigating", "mitigated", "resolved", "false_positive"]
    MAX_ENTRIES = 10_000
    MAX_TIMELINE_ENTRIES = 200
    MAX_MITIGATIONS = 200

    def __init__(self):
        self._incidents: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def _normalize_severity(cls, value: Any) -> str:
        candidate = str(value or "medium").strip().lower()
        return candidate if candidate in cls.SEVERITIES else "medium"

    def create(self, threat: dict, agent_id: str) -> dict:
        payload = threat if isinstance(threat, dict) else {}
        incident_id = f"inc-{uuid.uuid4().hex[:12]}"
        row = {
            "incident_id": incident_id,
            "created_at": self._now_iso(),
            "severity": self._normalize_severity(payload.get("severity")),
            "status": "open",
            "agent_id": str(agent_id or "unknown"),
            "threat_type": str(payload.get("type", payload.get("threat_type", "unknown")) or "unknown"),
            "description": str(payload.get("description", payload.get("detail", "No description")) or "No description"),
            "timeline": [
                {
                    "at": self._now_iso(),
                    "event": "created",
                    "note": str(payload.get("description", "Incident created")),
                }
            ],
            "mitigations": [],
        }
        self._incidents[incident_id] = row
        self._order.append(incident_id)
        self._trim_if_needed()
        return dict(row)

    def _trim_if_needed(self) -> None:
        cap = max(1, int(self.MAX_ENTRIES))
        while len(self._order) > cap:
            oldest = self._order.pop(0)
            self._incidents.pop(oldest, None)

    def update_status(self, incident_id: str, status: str, note: str = "") -> bool:
        row = self._incidents.get(incident_id)
        if row is None:
            return False
        normalized = str(status or "").strip().lower()
        if normalized not in self.STATUSES:
            return False
        row["status"] = normalized
        row["timeline"].append(
            {
                "at": self._now_iso(),
                "event": "status_changed",
                "status": normalized,
                "note": str(note or ""),
            }
        )
        if len(row["timeline"]) > self.MAX_TIMELINE_ENTRIES:
            row["timeline"] = row["timeline"][-self.MAX_TIMELINE_ENTRIES :]
        if normalized in {"resolved", "false_positive"}:
            row["resolved_at"] = self._now_iso()
        return True

    def add_mitigation(self, incident_id: str, action: str) -> bool:
        row = self._incidents.get(incident_id)
        if row is None:
            return False
        action_text = str(action or "").strip()
        if not action_text:
            return False
        row["mitigations"].append(action_text)
        if len(row["mitigations"]) > self.MAX_MITIGATIONS:
            row["mitigations"] = row["mitigations"][-self.MAX_MITIGATIONS :]
        row["timeline"].append(
            {
                "at": self._now_iso(),
                "event": "mitigation_added",
                "note": action_text,
            }
        )
        if len(row["timeline"]) > self.MAX_TIMELINE_ENTRIES:
            row["timeline"] = row["timeline"][-self.MAX_TIMELINE_ENTRIES :]
        return True

    def get_incident(self, incident_id: str) -> dict | None:
        row = self._incidents.get(incident_id)
        return dict(row) if isinstance(row, dict) else None

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        agent_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        rows = list(self._incidents.values())
        if status is not None:
            wanted = str(status).strip().lower()
            rows = [row for row in rows if str(row.get("status", "")).lower() == wanted]
        if severity is not None:
            wanted = str(severity).strip().lower()
            rows = [row for row in rows if str(row.get("severity", "")).lower() == wanted]
        if agent_id is not None:
            wanted = str(agent_id).strip()
            rows = [row for row in rows if str(row.get("agent_id", "")) == wanted]
        rows.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
        cap = max(1, min(10_000, int(limit)))
        return [dict(row) for row in rows[:cap]]

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def get_metrics(self) -> dict:
        rows = list(self._incidents.values())
        total = len(rows)
        open_count = sum(1 for row in rows if str(row.get("status", "open")) in {"open", "investigating"})
        by_severity = {level: 0 for level in self.SEVERITIES}
        for row in rows:
            severity = str(row.get("severity", "medium")).lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1

        mttr_samples: list[float] = []
        false_positive_count = 0
        for row in rows:
            status = str(row.get("status", "")).lower()
            if status == "false_positive":
                false_positive_count += 1
            if status not in {"resolved", "false_positive"}:
                continue
            started = self._parse_ts(row.get("created_at"))
            ended = self._parse_ts(row.get("resolved_at"))
            if started is None or ended is None or ended < started:
                continue
            mttr_samples.append((ended - started).total_seconds() / 3600.0)

        mttr_hours = sum(mttr_samples) / len(mttr_samples) if mttr_samples else 0.0
        false_positive_rate = (false_positive_count / total * 100.0) if total > 0 else 0.0
        return {
            "total": total,
            "open": open_count,
            "by_severity": by_severity,
            "mttr_hours": round(mttr_hours, 6),
            "false_positive_rate": round(false_positive_rate, 2),
        }

