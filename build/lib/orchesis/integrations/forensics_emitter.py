"""Real-time forensics incident emitter."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from orchesis.forensics import Incident
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import DecisionEvent


def _now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


class ForensicsEmitter:
    """Real-time incident detection via EventBus."""

    def __init__(
        self,
        incidents_path: str = ".orchesis/incidents.jsonl",
        alert_callback: Callable[[Incident], None] | None = None,
    ) -> None:
        self._path = Path(incidents_path)
        self._alert = alert_callback
        self._recent_denies: dict[str, list[float]] = defaultdict(list)
        self._logger = StructuredLogger("forensics_emitter")

    def _write_incident(self, incident: Incident) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "id": incident.id,
            "severity": incident.severity,
            "type": incident.type,
            "title": incident.title,
            "timestamp": incident.timestamp,
            "agent_id": incident.agent_id,
            "tool": incident.tool,
            "details": incident.details,
            "related_events": incident.related_events,
            "policy_version": incident.policy_version,
            "resolution": incident.resolution,
            "timeline": incident.timeline,
        }
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _to_incident(
        self,
        event: DecisionEvent,
        *,
        severity: str,
        incident_type: str,
        title: str,
        details: dict | None = None,
    ) -> Incident:
        return Incident(
            id=f"inc-{event.event_id[:8]}",
            severity=severity,
            type=incident_type,
            title=title,
            timestamp=event.timestamp,
            agent_id=event.agent_id,
            tool=event.tool,
            details=details or {},
            related_events=[],
            policy_version=event.policy_version,
            resolution="open",
            timeline=[{"ts": event.timestamp, "action": "detected"}],
        )

    def emit(self, event: DecisionEvent) -> None:
        """Process event and emit incidents; fail-silent on any error."""
        try:
            incident: Incident | None = None
            reasons = [reason.lower() for reason in event.reasons]
            if event.decision == "DENY" and any("bypass" in reason for reason in reasons):
                incident = self._to_incident(
                    event,
                    severity="critical",
                    incident_type="bypass",
                    title="Bypass attempt detected",
                    details={"reasons": event.reasons},
                )
            elif event.decision == "DENY":
                now = _now_ts()
                window = [ts for ts in self._recent_denies[event.agent_id] if now - ts <= 60.0]
                window.append(now)
                self._recent_denies[event.agent_id] = window
                if len(window) > 5:
                    incident = self._to_incident(
                        event,
                        severity="high",
                        incident_type="anomaly",
                        title="Brute force deny burst",
                        details={"deny_count_1m": len(window)},
                    )
            if incident is None:
                return
            self._write_incident(incident)
            if self._alert is not None:
                try:
                    self._alert(incident)
                except Exception:
                    self._logger.warn("incident alert callback failed", incident_id=incident.id)
        except Exception as error:  # noqa: BLE001
            self._logger.warn("forensics emitter failed", error=str(error))
