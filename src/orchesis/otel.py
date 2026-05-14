"""OTel-compatible span emission without SDK dependency."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from orchesis.telemetry import DecisionEvent, EventEmitter

if TYPE_CHECKING:
    from orchesis.otel_export import OTLPSpanExporter

# GenAI semantic conventions (OpenTelemetry spec)
GENAI_ATTRS = {
    "gen_ai.system": str,
    "gen_ai.operation.name": str,
    "gen_ai.request.model": str,
    "gen_ai.request.max_tokens": int,
    "gen_ai.request.temperature": float,
    "gen_ai.request.top_p": float,
    "gen_ai.response.model": str,
    "gen_ai.response.finish_reasons": str,
    "gen_ai.response.id": str,
    "gen_ai.usage.input_tokens": int,
    "gen_ai.usage.output_tokens": int,
    "gen_ai.usage.total_tokens": int,
    "orchesis.proxy.phase": str,
    "orchesis.decision": str,
    "orchesis.cost_usd": float,
    "orchesis.session_id": str,
    "orchesis.agent_id": str,
    "orchesis.cascade_level": str,
    "orchesis.cache_hit": bool,
    "orchesis.cache_type": str,
    "orchesis.threat_detected": bool,
    "orchesis.threat_ids": str,
    "orchesis.loop_detected": bool,
    "orchesis.experiment_id": str,
    "orchesis.variant_name": str,
    "orchesis.context_tokens_saved": int,
    "orchesis.circuit_state": str,
}


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


class ProxySpanEmitter:
    """
    Creates spans for each proxy pipeline phase.
    Feeds to OTLPSpanExporter + JSONL file.

    Usage from proxy:
        span = emitter.start_span("orchesis.phase.cascade", trace_ctx)
        # ... do cascade work ...
        emitter.end_span(span, attributes={...})
    """

    def __init__(
        self,
        jsonl_path: str = ".orchesis/traces.jsonl",
        otlp_exporter: OTLPSpanExporter | None = None,
    ) -> None:
        self._jsonl_emitter = OTelEmitter(path=jsonl_path)
        self._otlp_exporter = otlp_exporter

    def start_span(
        self,
        operation: str,
        trace_ctx: TraceContext,
        parent_span_id: str | None = None,
        attributes: dict[str, str | int | float | bool] | None = None,
    ) -> SpanData:
        """Create a new span (not yet ended)."""
        return SpanData(
            trace_id=trace_ctx.trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent_span_id or trace_ctx.parent_span_id,
            operation=operation,
            start_time_ns=time.time_ns(),
            end_time_ns=0,
            status="OK",
            attributes=dict(attributes or {}),
            events=[],
        )

    def end_span(
        self,
        span: SpanData,
        status: str = "OK",
        attributes: dict[str, str | int | float | bool] | None = None,
    ) -> None:
        """End span and export to all destinations."""
        finished = SpanData(
            trace_id=span.trace_id,
            span_id=span.span_id,
            parent_span_id=span.parent_span_id,
            operation=span.operation,
            start_time_ns=span.start_time_ns,
            end_time_ns=time.time_ns(),
            status=status,
            attributes={**span.attributes, **(attributes or {})},
            events=span.events,
        )
        if self._otlp_exporter:
            self._otlp_exporter.export_span(finished)

    def create_request_span(
        self,
        trace_ctx: TraceContext,
        model: str,
        provider: str,
        session_id: str = "",
        agent_id: str = "",
    ) -> SpanData:
        """Create the root span for an LLM request with GenAI attrs."""
        return self.start_span(
            operation="orchesis.proxy.request",
            trace_ctx=trace_ctx,
            attributes={
                "gen_ai.system": provider,
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": model,
                "orchesis.session_id": session_id,
                "orchesis.agent_id": agent_id,
            },
        )

    def create_phase_span(
        self,
        phase_name: str,
        trace_ctx: TraceContext,
        parent_span_id: str,
    ) -> SpanData:
        """Create a child span for a proxy phase."""
        return self.start_span(
            operation=f"orchesis.phase.{phase_name}",
            trace_ctx=trace_ctx,
            parent_span_id=parent_span_id,
            attributes={"orchesis.proxy.phase": phase_name},
        )
