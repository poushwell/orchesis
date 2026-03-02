"""OTel-compatible span emission without SDK dependency."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from orchesis.telemetry import DecisionEvent, EventEmitter


@dataclass
class SpanData:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    operation: str
    start_time_ns: int
    end_time_ns: int
    status: str
    attributes: dict[str, str | int | float | bool]
    events: list[dict[str, Any]]


class TraceContext:
    """Lightweight trace context propagation."""

    def __init__(self, trace_id: str | None = None, parent_span_id: str | None = None):
        self.trace_id = trace_id or self._generate_trace_id()
        self.parent_span_id = parent_span_id

    @staticmethod
    def _generate_trace_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def from_headers(headers: dict) -> "TraceContext":
        raw = headers.get("traceparent")
        if not isinstance(raw, str):
            return TraceContext()
        parts = raw.strip().split("-")
        if len(parts) != 4:
            return TraceContext()
        version, trace_id, parent_span_id, _flags = parts
        if len(version) != 2 or len(trace_id) != 32 or len(parent_span_id) != 16:
            return TraceContext()
        if not all(char in "0123456789abcdef" for char in trace_id.lower()):
            return TraceContext()
        if not all(char in "0123456789abcdef" for char in parent_span_id.lower()):
            return TraceContext()
        return TraceContext(trace_id=trace_id.lower(), parent_span_id=parent_span_id.lower())

    def to_headers(self) -> dict[str, str]:
        span_id = uuid.uuid4().hex[:16]
        parent = self.parent_span_id or span_id
        return {"traceparent": f"00-{self.trace_id}-{parent}-01"}


class OTelEmitter(EventEmitter):
    """Converts DecisionEvents into OTel-compatible span data."""

    def __init__(self, path: str = ".orchesis/traces.jsonl"):
        self.path = Path(path)

    def emit(self, event: DecisionEvent) -> None:
        span = self._decision_to_span(event)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(span), ensure_ascii=False) + "\n")

    def _decision_to_span(self, event: DecisionEvent) -> SpanData:
        end_time_ns = time.time_ns()
        duration_us = max(0, int(event.evaluation_duration_us))
        start_time_ns = end_time_ns - (duration_us * 1000)
        snapshot = event.state_snapshot if isinstance(event.state_snapshot, dict) else {}
        trace_id = (
            snapshot.get("trace_id")
            if isinstance(snapshot.get("trace_id"), str)
            else uuid.uuid4().hex
        )
        parent_span_id = (
            snapshot.get("parent_span_id")
            if isinstance(snapshot.get("parent_span_id"), str)
            else None
        )
        span_id = uuid.uuid4().hex[:16]
        rules_triggered = set(event.rules_triggered)
        events = [
            {
                "name": "rule.checked",
                "timestamp_ns": end_time_ns,
                "attributes": {
                    "rule_name": rule_name,
                    "triggered": rule_name in rules_triggered,
                },
            }
            for rule_name in event.rules_checked
        ]
        attributes: dict[str, str | int | float | bool] = {
            "orchesis.agent_id": event.agent_id,
            "orchesis.tool": event.tool,
            "orchesis.decision": event.decision,
            "orchesis.policy_version": event.policy_version,
            "orchesis.evaluation_duration_us": event.evaluation_duration_us,
            "orchesis.rules_checked_count": len(event.rules_checked),
            "orchesis.reasons_count": len(event.reasons),
        }
        return SpanData(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation="orchesis.evaluate",
            start_time_ns=start_time_ns,
            end_time_ns=end_time_ns,
            status="OK" if event.decision == "ALLOW" else "ERROR",
            attributes=attributes,
            events=events,
        )
