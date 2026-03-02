"""Audit query and incident investigation utilities."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from orchesis.replay import read_events_from_jsonl
from orchesis.telemetry import DecisionEvent

ANOMALY_RULES = [
    {
        "name": "high_deny_rate",
        "description": "Agent denied >80% of requests",
        "threshold": 0.8,
        "min_requests": 10,
    },
    {
        "name": "rate_limit_hammering",
        "description": "Agent hit rate limit >5 times in 10 min",
        "window_minutes": 10,
        "threshold": 5,
    },
    {
        "name": "tool_persistence",
        "description": "Same tool denied >20 times by same agent",
        "threshold": 20,
    },
    {
        "name": "unknown_agent_recon",
        "description": "Unregistered agent making >50 requests",
        "threshold": 50,
    },
    {
        "name": "burst_spike",
        "description": "Agent rate >10x their average in 5 min window",
        "window_minutes": 5,
        "multiplier": 10,
    },
]


@dataclass
class AuditQuery:
    agent_id: str | None = None
    tool: str | None = None
    decision: str | None = None
    since_hours: float | None = None
    policy_version: str | None = None
    session_id: str | None = None
    limit: int = 100


@dataclass
class AuditStats:
    total_events: int
    allow_count: int
    deny_count: int
    deny_rate: float
    unique_agents: int
    unique_tools: int
    unique_sessions: int
    top_denied_tools: list[tuple[str, int]]
    top_denied_agents: list[tuple[str, int]]
    top_deny_reasons: list[tuple[str, int]]
    avg_evaluation_us: float
    p95_evaluation_us: float
    events_per_minute: float


def _parse_ts(value: str) -> datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_session_id(event: DecisionEvent) -> str:
    snapshot = event.state_snapshot
    if isinstance(snapshot, dict):
        session_id = snapshot.get("session_id")
        if isinstance(session_id, str) and session_id:
            return session_id
    return "__default__"


class AuditEngine:
    """Query and analyze decision logs."""

    def __init__(self, log_path: str = ".orchesis/decisions.jsonl"):
        self._events: list[DecisionEvent] = []
        self._load(log_path)

    def _load(self, path: str) -> None:
        """Load events from JSONL. Handle corrupt lines gracefully."""
        self._events = read_events_from_jsonl(Path(path))

    def query(self, q: AuditQuery) -> list[DecisionEvent]:
        """Filter events by query parameters."""
        filtered: list[DecisionEvent] = []
        threshold: datetime | None = None
        if isinstance(q.since_hours, int | float):
            threshold = datetime.now(timezone.utc) - timedelta(hours=float(q.since_hours))

        for event in self._events:
            if q.agent_id is not None and event.agent_id != q.agent_id:
                continue
            if q.tool is not None and event.tool != q.tool:
                continue
            if q.decision is not None and event.decision != q.decision:
                continue
            if q.policy_version is not None and event.policy_version != q.policy_version:
                continue
            if q.session_id is not None and _extract_session_id(event) != q.session_id:
                continue
            if threshold is not None:
                ts = _parse_ts(event.timestamp)
                if ts is None or ts < threshold:
                    continue
            filtered.append(event)

        filtered = sorted(filtered, key=lambda item: item.timestamp, reverse=True)
        limit = q.limit if q.limit > 0 else len(filtered)
        return filtered[:limit]

    def stats(self, q: AuditQuery | None = None) -> AuditStats:
        """Compute aggregate statistics, optionally filtered."""
        events = self.query(q) if q is not None else list(self._events)
        total = len(events)
        allow_count = sum(1 for event in events if event.decision == "ALLOW")
        deny_events = [event for event in events if event.decision == "DENY"]
        deny_count = len(deny_events)
        deny_rate = (deny_count / total) if total > 0 else 0.0

        unique_agents = len({event.agent_id for event in events})
        unique_tools = len({event.tool for event in events})
        unique_sessions = len({_extract_session_id(event) for event in events})

        denied_tool_counter = Counter(event.tool for event in deny_events)
        denied_agent_counter = Counter(event.agent_id for event in deny_events)
        reason_counter: Counter[str] = Counter()
        for event in deny_events:
            for reason in event.reasons:
                reason_counter[reason] += 1

        eval_times = [int(event.evaluation_duration_us) for event in events]
        avg_eval = (sum(eval_times) / len(eval_times)) if eval_times else 0.0
        p95_eval = 0.0
        if eval_times:
            sorted_times = sorted(eval_times)
            p95_index = max(0, int(0.95 * (len(sorted_times) - 1)))
            p95_eval = float(sorted_times[p95_index])

        timestamps = [ts for event in events if (ts := _parse_ts(event.timestamp)) is not None]
        if len(timestamps) < 2:
            events_per_minute = float(total)
        else:
            span_seconds = max(1.0, (max(timestamps) - min(timestamps)).total_seconds())
            events_per_minute = total / (span_seconds / 60.0)

        return AuditStats(
            total_events=total,
            allow_count=allow_count,
            deny_count=deny_count,
            deny_rate=deny_rate,
            unique_agents=unique_agents,
            unique_tools=unique_tools,
            unique_sessions=unique_sessions,
            top_denied_tools=denied_tool_counter.most_common(5),
            top_denied_agents=denied_agent_counter.most_common(5),
            top_deny_reasons=reason_counter.most_common(5),
            avg_evaluation_us=avg_eval,
            p95_evaluation_us=p95_eval,
            events_per_minute=events_per_minute,
        )

    def timeline(self, agent_id: str, hours: float = 24) -> list[DecisionEvent]:
        """Get chronological timeline for one agent."""
        events = self.query(AuditQuery(agent_id=agent_id, since_hours=hours, limit=10_000))
        return sorted(events, key=lambda item: item.timestamp)

    def anomalies(self) -> list[dict[str, Any]]:
        """Detect suspicious patterns using static rule thresholds."""
        anomalies: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()
        by_agent: dict[str, list[DecisionEvent]] = defaultdict(list)
        for event in self._events:
            by_agent[event.agent_id].append(event)

        # high_deny_rate
        cfg_deny = next(rule for rule in ANOMALY_RULES if rule["name"] == "high_deny_rate")
        threshold = float(cfg_deny["threshold"])
        min_requests = int(cfg_deny["min_requests"])
        for agent_id, events in by_agent.items():
            total = len(events)
            if total < min_requests:
                continue
            deny = sum(1 for event in events if event.decision == "DENY")
            rate = deny / total
            if rate > threshold:
                anomalies.append(
                    {
                        "rule": "high_deny_rate",
                        "agent_id": agent_id,
                        "detail": f"{rate * 100:.0f}% deny rate ({deny}/{total} requests)",
                        "severity": "high",
                        "timestamp": now,
                    }
                )

        # rate_limit_hammering
        cfg_hammer = next(rule for rule in ANOMALY_RULES if rule["name"] == "rate_limit_hammering")
        hammer_window = timedelta(minutes=int(cfg_hammer["window_minutes"]))
        hammer_threshold = int(cfg_hammer["threshold"])
        for agent_id, events in by_agent.items():
            rate_limit_hits = [
                ts
                for event in events
                if any("rate_limit" in reason for reason in event.reasons)
                if (ts := _parse_ts(event.timestamp)) is not None
            ]
            rate_limit_hits.sort()
            left = 0
            max_hits = 0
            for right, ts in enumerate(rate_limit_hits):
                while left <= right and (ts - rate_limit_hits[left]) > hammer_window:
                    left += 1
                max_hits = max(max_hits, right - left + 1)
            if max_hits > hammer_threshold:
                anomalies.append(
                    {
                        "rule": "rate_limit_hammering",
                        "agent_id": agent_id,
                        "detail": (
                            f"agent hit rate limit {max_hits} times "
                            f"in {int(hammer_window.total_seconds() // 60)} minutes"
                        ),
                        "severity": "medium",
                        "timestamp": now,
                    }
                )

        # tool_persistence
        cfg_tool = next(rule for rule in ANOMALY_RULES if rule["name"] == "tool_persistence")
        tool_threshold = int(cfg_tool["threshold"])
        denied_by_agent_tool = Counter(
            (event.agent_id, event.tool) for event in self._events if event.decision == "DENY"
        )
        for (agent_id, tool), count in denied_by_agent_tool.items():
            if count > tool_threshold:
                anomalies.append(
                    {
                        "rule": "tool_persistence",
                        "agent_id": agent_id,
                        "detail": f"tool '{tool}' denied {count} times",
                        "severity": "medium",
                        "timestamp": now,
                    }
                )

        # unknown_agent_recon
        cfg_unknown = next(rule for rule in ANOMALY_RULES if rule["name"] == "unknown_agent_recon")
        unknown_threshold = int(cfg_unknown["threshold"])
        for agent_id, events in by_agent.items():
            if not agent_id.startswith("unknown"):
                continue
            if len(events) > unknown_threshold:
                anomalies.append(
                    {
                        "rule": "unknown_agent_recon",
                        "agent_id": agent_id,
                        "detail": f"unknown agent made {len(events)} requests",
                        "severity": "high",
                        "timestamp": now,
                    }
                )

        # burst_spike
        cfg_burst = next(rule for rule in ANOMALY_RULES if rule["name"] == "burst_spike")
        burst_window = timedelta(minutes=int(cfg_burst["window_minutes"]))
        burst_multiplier = float(cfg_burst["multiplier"])
        for agent_id, events in by_agent.items():
            timestamps = sorted(
                ts for event in events if (ts := _parse_ts(event.timestamp)) is not None
            )
            if len(timestamps) < 10:
                continue
            left = 0
            max_window_count = 0
            for right, ts in enumerate(timestamps):
                while left <= right and (ts - timestamps[left]) > burst_window:
                    left += 1
                max_window_count = max(max_window_count, right - left + 1)

            span_seconds = max(1.0, (timestamps[-1] - timestamps[0]).total_seconds())
            expected_windows = max(1.0, span_seconds / burst_window.total_seconds())
            avg_window_count = len(timestamps) / expected_windows
            if avg_window_count > 0 and max_window_count > avg_window_count * burst_multiplier:
                anomalies.append(
                    {
                        "rule": "burst_spike",
                        "agent_id": agent_id,
                        "detail": (
                            f"burst window count {max_window_count} exceeds "
                            f"{burst_multiplier:.0f}x average ({avg_window_count:.2f})"
                        ),
                        "severity": "high",
                        "timestamp": now,
                    }
                )

        return anomalies

    def export_csv(self, events: list[DecisionEvent], path: str) -> None:
        """Export events to CSV for external analysis."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "event_id",
                    "timestamp",
                    "agent_id",
                    "session_id",
                    "tool",
                    "decision",
                    "policy_version",
                    "evaluation_duration_us",
                    "reasons",
                ]
            )
            for event in events:
                writer.writerow(
                    [
                        event.event_id,
                        event.timestamp,
                        event.agent_id,
                        _extract_session_id(event),
                        event.tool,
                        event.decision,
                        event.policy_version,
                        event.evaluation_duration_us,
                        "; ".join(event.reasons),
                    ]
                )
