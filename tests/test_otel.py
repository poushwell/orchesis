from __future__ import annotations

import json

from orchesis.otel import OTelEmitter, SpanData, TraceContext
from orchesis.telemetry import DecisionEvent


def _event() -> DecisionEvent:
    return DecisionEvent(
        event_id="evt-1",
        timestamp="2026-01-01T00:00:00Z",
        agent_id="cursor",
        tool="read_file",
        params_hash="abc",
        cost=0.1,
        decision="DENY",
        reasons=["file_access: denied"],
        rules_checked=["budget_limit", "rate_limit", "file_access"],
        rules_triggered=["file_access"],
        evaluation_order=["identity_check", "budget_limit", "rate_limit", "file_access"],
        evaluation_duration_us=50,
        policy_version="pv-1",
        state_snapshot={
            "trace_id": "0123456789abcdef0123456789abcdef",
            "parent_span_id": "0123456789abcdef",
        },
    )


def test_span_data_has_required_fields() -> None:
    span = SpanData(
        trace_id="0123456789abcdef0123456789abcdef",
        span_id="0123456789abcdef",
        parent_span_id=None,
        operation="orchesis.evaluate",
        start_time_ns=1,
        end_time_ns=2,
        status="OK",
        attributes={},
        events=[],
    )
    assert len(span.trace_id) == 32
    assert len(span.span_id) == 16
    assert span.operation == "orchesis.evaluate"


def test_decision_to_span_mapping(tmp_path) -> None:
    emitter = OTelEmitter(path=str(tmp_path / "traces.jsonl"))
    span = emitter._decision_to_span(_event())
    assert span.attributes["orchesis.agent_id"] == "cursor"
    assert span.attributes["orchesis.tool"] == "read_file"
    assert span.attributes["orchesis.decision"] == "DENY"
    assert span.attributes["orchesis.policy_version"] == "pv-1"
    assert span.attributes["orchesis.evaluation_duration_us"] == 50


def test_otel_emitter_writes_jsonl(tmp_path) -> None:
    path = tmp_path / "traces.jsonl"
    emitter = OTelEmitter(path=str(path))
    emitter.emit(_event())
    line = path.read_text(encoding="utf-8").splitlines()[0]
    payload = json.loads(line)
    assert payload["operation"] == "orchesis.evaluate"
    assert payload["attributes"]["orchesis.tool"] == "read_file"


def test_span_events_per_rule(tmp_path) -> None:
    emitter = OTelEmitter(path=str(tmp_path / "traces.jsonl"))
    span = emitter._decision_to_span(_event())
    assert len(span.events) == 3
    assert all(item["name"] == "rule.checked" for item in span.events)


def test_trace_context_from_headers() -> None:
    headers = {"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
    context = TraceContext.from_headers(headers)
    assert context.trace_id == "0123456789abcdef0123456789abcdef"
    assert context.parent_span_id == "0123456789abcdef"


def test_trace_context_to_headers() -> None:
    context = TraceContext(
        trace_id="0123456789abcdef0123456789abcdef", parent_span_id="0123456789abcdef"
    )
    headers = context.to_headers()
    assert "traceparent" in headers
    assert headers["traceparent"].startswith("00-0123456789abcdef0123456789abcdef-")


def test_trace_context_generation() -> None:
    context = TraceContext.from_headers({})
    assert len(context.trace_id) == 32
