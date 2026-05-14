"""Tests for FlowXrayRecordPhase — Checkpoint 1 migration target."""

from __future__ import annotations

import asyncio

import pytest

from orchesis.phases import FlowXrayRecordPhase
from orchesis.pipeline import (
    Identity,
    InputSnapshot,
    PhaseRegistry,
    PipelineEngine,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)


class _FakeAnalyzer:
    def __init__(self):
        self.calls = []

    def record_request(self, *, session_id, model, messages, tools):
        self.calls.append({
            "session_id": session_id,
            "model": model,
            "messages": list(messages),
            "tools": list(tools),
        })
        return f"node-{len(self.calls)}"


def _ctx(*, tools=None, model="gpt-4", messages=None) -> RequestContext:
    return RequestContext(
        id=Identity("r1", "sess-1", "agent", "cust", "lite"),
        input=InputSnapshot(
            raw_body=b"",
            original_messages=tuple(messages or [{"role": "user", "content": "hi"}]),
            original_tools=tuple(tools or []),
            requested_model=model,
            requested_params={},
            provider_hint=None,
            headers={},
        ),
        processed=Processed(),
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


class TestFlowXrayRecordPhase:
    def test_records_node_id_into_processed_params(self):
        analyzer = _FakeAnalyzer()
        phase = FlowXrayRecordPhase(analyzer)
        ctx = _ctx()
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "pass"
        assert ctx.processed.params["flow_node_id"] == "node-1"
        assert analyzer.calls[0]["session_id"] == "sess-1"
        assert analyzer.calls[0]["model"] == "gpt-4"

    def test_skips_when_analyzer_none(self):
        phase = FlowXrayRecordPhase(None)
        result = asyncio.run(phase.execute(_ctx()))
        assert result.status == "skip"

    def test_tools_from_dict_shape(self):
        analyzer = _FakeAnalyzer()
        phase = FlowXrayRecordPhase(analyzer)
        ctx = _ctx(tools=[{"name": "search"}, {"name": "fetch"}, {}])
        asyncio.run(phase.execute(ctx))
        assert analyzer.calls[0]["tools"] == ["search", "fetch"]

    def test_tools_from_string_shape(self):
        analyzer = _FakeAnalyzer()
        phase = FlowXrayRecordPhase(analyzer)
        ctx = _ctx(tools=["alpha", "beta"])
        asyncio.run(phase.execute(ctx))
        assert analyzer.calls[0]["tools"] == ["alpha", "beta"]

    def test_runs_via_engine_with_registry(self):
        analyzer = _FakeAnalyzer()
        r = PhaseRegistry()
        r.register(FlowXrayRecordPhase(analyzer))
        r.reload()
        engine = PipelineEngine(r)
        ctx = _ctx()
        results = asyncio.run(engine.process(ctx))
        assert len(results) == 1
        assert results[0].status == "pass"
        assert ctx.processed.params["flow_node_id"] == "node-1"

    def test_engine_releases_refcount_after_request(self):
        analyzer = _FakeAnalyzer()
        r = PhaseRegistry()
        r.register(FlowXrayRecordPhase(analyzer))
        r.reload()
        engine = PipelineEngine(r)
        asyncio.run(engine.process(_ctx()))
        asyncio.run(engine.process(_ctx()))
        assert r.in_flight_count == 0
        assert len(analyzer.calls) == 2
