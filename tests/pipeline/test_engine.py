"""Engine smoke tests — minimal happy path + skip + timeout + contract."""

from __future__ import annotations

import asyncio

import pytest

from orchesis.pipeline import (
    Identity,
    InputSnapshot,
    Phase,
    PhaseRegistry,
    PhaseResult,
    PipelineEngine,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)
from tests.pipeline.conftest import make_phase


def _ctx() -> RequestContext:
    return RequestContext(
        id=Identity("r", "s", "a", "c", "lite"),
        input=InputSnapshot(b"", (), (), "m", {}, None, {}),
        processed=Processed(),
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


class TestEnginePass:
    def test_two_phases_run_in_order(self, make_ctx):
        calls: list[str] = []

        def fn(self, ctx):
            calls.append(self.name)
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("alpha", execute_fn=fn))
        r.register(make_phase("beta", after=("alpha",), execute_fn=fn))
        r.reload()

        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert calls == ["alpha", "beta"]
        assert all(res.status == "pass" for res in results)

    def test_zero_phases(self, make_ctx):
        r = PhaseRegistry()
        r.reload()
        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert results == []


class TestEngineSkip:
    def test_can_skip_skips_phase(self, make_ctx):
        calls: list[str] = []

        def fn(self, ctx):
            calls.append(self.name)
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("a", execute_fn=fn))
        r.register(make_phase("skipper", after=("a",), execute_fn=fn,
                              can_skip_fn=lambda self, ctx: True))
        r.register(make_phase("c", after=("skipper",), execute_fn=fn))
        r.reload()

        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert calls == ["a", "c"]
        # Skipped phase still has a result entry of status "skip".
        statuses = [r.status for r in results]
        assert "skip" in statuses


class TestEngineBlock:
    def test_block_short_circuits(self, make_ctx):
        calls: list[str] = []

        def first(self, ctx):
            calls.append(self.name)
            return PhaseResult(status="pass")

        def blocker(self, ctx):
            calls.append(self.name)
            return PhaseResult(status="block", reason="halt")

        def never(self, ctx):
            calls.append(self.name)
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("a", execute_fn=first))
        r.register(make_phase("b", after=("a",), execute_fn=blocker))
        r.register(make_phase("c", after=("b",), execute_fn=never))
        r.reload()

        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert calls == ["a", "b"]
        assert results[-1].status == "block"


class TestEngineTimeout:
    def test_slow_phase_times_out(self, make_ctx):
        async def slow_exec(self, ctx):
            await asyncio.sleep(0.5)
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("slow", execute_fn=slow_exec))
        # Override timeout via the Phase subclass directly.
        cls = type(r.build_graph().get("slow"))
        cls.timeout_seconds = 0.05  # type: ignore[attr-defined]
        r.reload()

        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert results[0].status == "block"
        assert "timed out" in results[0].reason


class TestEngineContractViolation:
    def test_undeclared_decision_blocks_phase(self, make_ctx):
        def emit(self, ctx):
            ctx.tracking.add_decision("pass")
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("noisy", execute_fn=emit))  # no appends_tracking
        r.reload()

        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert results[0].status == "block"
        assert "contract violation" in results[0].reason.lower()

    def test_declared_decision_passes(self, make_ctx):
        def emit(self, ctx):
            ctx.tracking.add_decision("pass", reason="all good")
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        r.register(make_phase("noisy", appends_tracking=("decisions",), execute_fn=emit))
        r.reload()

        engine = PipelineEngine(r)
        ctx = make_ctx()
        results = asyncio.run(engine.process(ctx))
        assert results[0].status == "pass"
        decisions = ctx.tracking.decisions
        assert len(decisions) == 1
        assert decisions[0].phase_name == "noisy"


class TestEngineReleaseUnderError:
    def test_refcount_released_on_exception(self, make_ctx):
        def boom(self, ctx):
            raise RuntimeError("kaboom")

        r = PhaseRegistry()
        r.register(make_phase("boom", execute_fn=boom))
        r.reload()
        engine = PipelineEngine(r)
        results = asyncio.run(engine.process(make_ctx()))
        assert results[0].status == "block"
        assert r.in_flight_count == 0
