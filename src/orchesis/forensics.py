"""Incident forensics engine over decision telemetry logs."""

from __future__ import annotations

import json
import hashlib
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from orchesis.replay import read_events_from_jsonl
from orchesis.telemetry import DecisionEvent


def _now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime | None:
    """Parse timestamp into timezone-aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class Incident:
    """Forensics incident model."""

    id: str
    severity: str
    type: str
    title: str
    timestamp: str
    agent_id: str | None = None
    tool: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    related_events: list[dict[str, Any]] = field(default_factory=list)
    policy_version: str | None = None
    resolution: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class IncidentReport:
    """Aggregate report for incidents in a period."""

    incidents: list[Incident]
    summary: dict[str, Any]
    period_start: str
    period_end: str
    mean_time_to_detect: float | None = None


class ForensicsEngine:
    """Analyze audit logs and produce incident reports."""

    def __init__(
        self,
        decisions_path: str = ".orchesis/decisions.jsonl",
        fuzz_meta_path: str = ".orchesis/fuzz_meta.json",
    ) -> None:
        self._decisions_path = Path(decisions_path)
        self._fuzz_meta_path = Path(fuzz_meta_path)
        self._incident_index: dict[str, Incident] = {}

    def _load_events(self) -> list[DecisionEvent]:
        return read_events_from_jsonl(self._decisions_path)

    def _new_incident(
        self,
        *,
        severity: str,
        incident_type: str,
        title: str,
        event: DecisionEvent,
        details: dict[str, Any] | None = None,
        related_events: list[DecisionEvent] | None = None,
    ) -> Incident:
        inc = Incident(
            id=(
                "inc-"
                + hashlib.sha256(
                    f"{event.event_id}:{incident_type}:{title}:{event.timestamp}".encode("utf-8")
                ).hexdigest()[:8]
            ),
            severity=severity,
            type=incident_type,
            title=title,
            timestamp=event.timestamp,
            agent_id=event.agent_id,
            tool=event.tool,
            details=details or {},
            related_events=[asdict(item) for item in (related_events or [event])],
            policy_version=event.policy_version,
            resolution="open",
            timeline=[{"ts": event.timestamp, "action": "detected"}],
        )
        return inc

    def detect_incidents(
        self,
        since: str | None = None,
        severity_filter: str | None = None,
    ) -> list[Incident]:
        """Scan decision log for incidents."""
        events = self._load_events()
        threshold = _parse_ts(since) if isinstance(since, str) else None
        filtered: list[DecisionEvent] = []
        for event in events:
            ts = _parse_ts(event.timestamp)
            if threshold is not None and (ts is None or ts < threshold):
                continue
            filtered.append(event)

        if not filtered:
            self._incident_index = {}
            return []

        incidents: list[Incident] = []
        avg_latency = sum(item.evaluation_duration_us for item in filtered) / max(1, len(filtered))
        deny_windows: dict[str, list[datetime]] = defaultdict(list)
        seen_burst_keys: set[tuple[str, str]] = set()

        for event in filtered:
            reasons_l = [reason.lower() for reason in event.reasons]
            ts = _parse_ts(event.timestamp) or datetime.now(timezone.utc)

            # 1) bypass marker
            if event.decision == "DENY" and any("bypass" in reason for reason in reasons_l):
                incidents.append(
                    self._new_incident(
                        severity="critical",
                        incident_type="bypass",
                        title="Bypass attempt detected",
                        event=event,
                        details={"reasons": event.reasons},
                    )
                )

            # 2) brute force denies in one minute
            if event.decision == "DENY":
                agent_window = deny_windows[event.agent_id]
                agent_window.append(ts)
                one_minute_ago = ts - timedelta(minutes=1)
                deny_windows[event.agent_id] = [item for item in agent_window if item >= one_minute_ago]
                if len(deny_windows[event.agent_id]) > 5:
                    key = (event.agent_id, ts.strftime("%Y-%m-%dT%H:%M"))
                    if key not in seen_burst_keys:
                        seen_burst_keys.add(key)
                        incidents.append(
                            self._new_incident(
                                severity="high",
                                incident_type="anomaly",
                                title="Brute force deny burst",
                                event=event,
                                details={"deny_count_1m": len(deny_windows[event.agent_id])},
                            )
                        )

            # 3) privilege escalation attempts
            if any("lacks capability" in reason or "not in allowed_tools" in reason for reason in reasons_l):
                incidents.append(
                    self._new_incident(
                        severity="medium",
                        incident_type="identity_violation",
                        title="Privilege escalation attempt",
                        event=event,
                    )
                )

            # 4) budget exceeded
            if any("daily budget exceeded" in reason for reason in reasons_l):
                incidents.append(
                    self._new_incident(
                        severity="high",
                        incident_type="budget_breach",
                        title="Budget limit exceeded",
                        event=event,
                    )
                )

            # 5) rate limit exceeded
            if any("rate_limit" in reason and "exceeded" in reason for reason in reasons_l):
                incidents.append(
                    self._new_incident(
                        severity="medium",
                        incident_type="rate_limit_breach",
                        title="Rate limit exceeded",
                        event=event,
                    )
                )

            # 6) unknown agent
            if event.agent_id in {"__global__", "__unknown__", "unknown"} or event.agent_id.startswith(
                "unknown"
            ):
                incidents.append(
                    self._new_incident(
                        severity="medium",
                        incident_type="identity_violation",
                        title="Unknown agent identity observed",
                        event=event,
                    )
                )

            # 7) latency anomaly
            if avg_latency > 0 and event.evaluation_duration_us > avg_latency * 10:
                incidents.append(
                    self._new_incident(
                        severity="low",
                        incident_type="anomaly",
                        title="Latency spike detected",
                        event=event,
                        details={
                            "latency_us": event.evaluation_duration_us,
                            "average_us": round(avg_latency, 2),
                        },
                    )
                )

        if severity_filter is not None:
            target = severity_filter.strip().lower()
            incidents = [item for item in incidents if item.severity == target]

        self._incident_index = {item.id: item for item in incidents}
        incidents.sort(key=lambda item: item.timestamp, reverse=True)
        return incidents

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get single incident with context."""
        if incident_id in self._incident_index:
            return self._incident_index[incident_id]
        for item in self.detect_incidents():
            if item.id == incident_id:
                return item
        return None

    def build_report(
        self,
        since: str | None = None,
        until: str | None = None,
    ) -> IncidentReport:
        """Build comprehensive report for incident period."""
        incidents = self.detect_incidents(since=since)
        end_dt = _parse_ts(until) if isinstance(until, str) else datetime.now(timezone.utc)
        if end_dt is None:
            end_dt = datetime.now(timezone.utc)
        if until is not None:
            incidents = [item for item in incidents if (_parse_ts(item.timestamp) or end_dt) <= end_dt]

        by_severity = Counter(item.severity for item in incidents)
        by_type = Counter(item.type for item in incidents)
        by_agent = Counter(item.agent_id or "unknown" for item in incidents)

        if incidents:
            detect_delays: list[float] = []
            for item in incidents:
                if item.timeline:
                    first = _parse_ts(item.timeline[0]["ts"]) if isinstance(item.timeline[0], dict) else None
                    detected = _parse_ts(item.timestamp)
                    if first is not None and detected is not None:
                        detect_delays.append(max(0.0, (detected - first).total_seconds()))
            mttd = (sum(detect_delays) / len(detect_delays)) if detect_delays else 0.0
            period_start = min(item.timestamp for item in incidents)
            period_end = max(item.timestamp for item in incidents)
        else:
            mttd = None
            period_start = since or _now_iso()
            period_end = until or _now_iso()

        summary = {
            "total": len(incidents),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_agent": dict(by_agent),
        }
        return IncidentReport(
            incidents=incidents,
            summary=summary,
            period_start=period_start,
            period_end=period_end,
            mean_time_to_detect=mttd,
        )

    def agent_risk_profile(self, agent_id: str) -> dict[str, Any]:
        """Compute risk profile for one agent."""
        events = [item for item in self._load_events() if item.agent_id == agent_id]
        total = len(events)
        denied = sum(1 for item in events if item.decision == "DENY")
        deny_rate = (denied / total) if total else 0.0
        incidents = [item for item in self.detect_incidents() if item.agent_id == agent_id]
        incident_density = (len(incidents) / total) if total else 0.0
        risk_score = min(1.0, (deny_rate * 0.6) + (incident_density * 0.4))
        denied_events = [item for item in events if item.decision == "DENY"]
        top_tools = Counter(item.tool for item in denied_events).most_common(5)
        reasons = Counter(reason for item in denied_events for reason in item.reasons).most_common(5)

        now = datetime.now(timezone.utc)
        last_24 = [item for item in events if (_parse_ts(item.timestamp) or now) >= now - timedelta(hours=24)]
        prev_24 = [
            item
            for item in events
            if now - timedelta(hours=48) <= (_parse_ts(item.timestamp) or now) < now - timedelta(hours=24)
        ]
        last_deny_rate = (
            sum(1 for item in last_24 if item.decision == "DENY") / len(last_24) if last_24 else 0.0
        )
        prev_deny_rate = (
            sum(1 for item in prev_24 if item.decision == "DENY") / len(prev_24) if prev_24 else 0.0
        )
        trend = "stable"
        if last_deny_rate > prev_deny_rate + 0.02:
            trend = "increasing"
        elif last_deny_rate + 0.02 < prev_deny_rate:
            trend = "decreasing"

        return {
            "agent_id": agent_id,
            "total_requests": total,
            "denied": denied,
            "deny_rate": round(deny_rate, 4),
            "top_denied_tools": top_tools,
            "top_deny_reasons": reasons,
            "incidents": len(incidents),
            "risk_score": round(risk_score, 4),
            "trend": trend,
        }

    def attack_timeline(
        self,
        incident_id: str | None = None,
        agent_id: str | None = None,
        last_n: int = 50,
    ) -> list[dict[str, Any]]:
        """Build chronological event timeline for visualization."""
        events = self._load_events()
        if incident_id is not None:
            incident = self.get_incident(incident_id)
            if incident is None:
                return []
            agent_id = incident.agent_id
        if agent_id is not None:
            events = [item for item in events if item.agent_id == agent_id]
        events = sorted(events, key=lambda item: item.timestamp)
        if last_n > 0:
            events = events[-last_n:]
        return [
            {
                "ts": item.timestamp,
                "agent_id": item.agent_id,
                "tool": item.tool,
                "decision": item.decision,
                "reasons": list(item.reasons),
                "latency_us": item.evaluation_duration_us,
            }
            for item in events
        ]

    def export_json(self, report: IncidentReport) -> str:
        """Export report as JSON string."""
        payload = {
            "incidents": [asdict(item) for item in report.incidents],
            "summary": report.summary,
            "period_start": report.period_start,
            "period_end": report.period_end,
            "mean_time_to_detect": report.mean_time_to_detect,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def export_markdown(self, report: IncidentReport) -> str:
        """Export report as markdown."""
        sev = report.summary.get("by_severity", {})
        most_affected = "n/a"
        by_agent = report.summary.get("by_agent", {})
        if isinstance(by_agent, dict) and by_agent:
            most_affected = max(by_agent.items(), key=lambda item: item[1])[0]
        lines = [
            f"# Incident Report: {report.period_start} to {report.period_end}",
            "",
            "## Summary",
            f"- Total incidents: {report.summary.get('total', 0)}",
            (
                "- Critical: "
                f"{sev.get('critical', 0)}, High: {sev.get('high', 0)}, "
                f"Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)}"
            ),
            f"- Most affected agent: {most_affected}",
            "",
            "## Incidents",
            "",
        ]
        for item in report.incidents:
            lines.extend(
                [
                    f"### [{item.id.upper()}] {item.severity.title()}: {item.title}",
                    f"**Time:** {item.timestamp}",
                    f"**Agent:** {item.agent_id or 'unknown'}",
                    f"**Tool:** {item.tool or 'unknown'}",
                    f"**Details:** {item.details or {}}",
                    f"**Status:** {item.resolution or 'open'}",
                    "",
                ]
            )
        lines.extend(
            [
                "## Agent Risk Profiles",
                "",
                "| Agent | Requests | Denied | Deny Rate | Risk Score |",
                "|-------|----------|--------|-----------|------------|",
            ]
        )
        if isinstance(by_agent, dict):
            for agent in sorted(by_agent):
                profile = self.agent_risk_profile(agent)
                lines.append(
                    f"| {agent} | {profile['total_requests']} | {profile['denied']} | "
                    f"{profile['deny_rate']*100:.1f}% | {profile['risk_score']:.2f} |"
                )
        return "\n".join(lines)
