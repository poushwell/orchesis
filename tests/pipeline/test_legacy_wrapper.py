"""Tests for `make_legacy_phase` factory and `_run_migrated_phase`.

Checkpoint 2 hybrid path: 9 wrapper plugins delegate to proxy `_phase_<name>`
methods. These tests verify the factory in isolation and the proxy bridge
end-to-end.
"""

from __future__ import annotations

import asyncio

import pytest

from orchesis.phases import make_legacy_phase
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


def _ctx(**params) -> RequestContext:
    proc = Processed()
    if params:
        proc.params.update(params)
    return RequestContext(
        id=Identity("r", "s", "a", "c", "lite"),
        input=InputSnapshot(b"", (), (), "m", {}, None, {}),
        processed=proc,
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


# ---------------------------------------------------------------------------
# make_legacy_phase factory
# ---------------------------------------------------------------------------


class TestMakeLegacyPhase:
    def test_phase_name_set(self):
        def fake(ctx):
            return True
        phase = make_legacy_phase("my_phase", fake)
        assert phase.name == "my_phase"

    def test_passes_when_legacy_returns_true(self):
        calls = []

        def fake(legacy_ctx):
            calls.append(legacy_ctx)
            return True

        phase = make_legacy_phase("p1", fake)
        ctx = _ctx(_legacy_ctx="MARKER")
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "pass"
        assert calls == ["MARKER"]

    def test_blocks_when_legacy_returns_false(self):
        phase = make_legacy_phase("p1", lambda c: False)
        ctx = _ctx(_legacy_ctx={})
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "block"

    def test_passes_when_legacy_returns_none(self):
        # Some legacy methods (e.g. send_response) return None; treat as pass.
        def fake(c):
            return None
        phase = make_legacy_phase("p_none", fake)
        ctx = _ctx(_legacy_ctx={})
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "pass"

    def test_blocks_when_legacy_ctx_missing(self):
        phase = make_legacy_phase("p1", lambda c: True)
        ctx = _ctx()  # no _legacy_ctx
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "block"
        assert "legacy context missing" in result.reason

    def test_catches_legacy_exception(self):
        def bad(c):
            raise RuntimeError("boom")

        phase = make_legacy_phase("p1", bad)
        ctx = _ctx(_legacy_ctx={})
        result = asyncio.run(phase.execute(ctx))
        assert result.status == "block"
        assert "RuntimeError" in result.reason
        assert "boom" in result.reason

    def test_ordering_constraints_propagated(self):
        phase = make_legacy_phase(
            "p2",
            lambda c: True,
            after=("p1",),
            before=("p3",),
        )
        assert phase.after == frozenset({"p1"})
        assert phase.before == frozenset({"p3"})

    def test_runs_through_engine(self):
        # Build a registry with two legacy wrappers in sequence and verify
        # the engine dispatches each correctly via process_one.
        order: list[str] = []

        def make_method(name: str):
            def _m(legacy_ctx):
                order.append(f"{name}:{legacy_ctx}")
                return True
            return _m

        r = PhaseRegistry()
        r.register(make_legacy_phase("alpha", make_method("alpha")))
        r.register(make_legacy_phase("beta", make_method("beta")))
        r.reload()
        eng = PipelineEngine(r)

        ctx = _ctx(_legacy_ctx="LCX")
        result_a = asyncio.run(eng.process_one("alpha", ctx))
        result_b = asyncio.run(eng.process_one("beta", ctx))
        assert result_a.status == "pass"
        assert result_b.status == "pass"
        assert order == ["alpha:LCX", "beta:LCX"]


# ---------------------------------------------------------------------------
# Proxy bridge — _run_migrated_phase end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture
def proxy_instance(tmp_path):
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    # Free port not strictly needed since we never start the HTTP server.
    cfg = HTTPProxyConfig(host="127.0.0.1", port=0)
    return LLMHTTPProxy(config=cfg)


class TestRunMigratedPhase:
    def test_all_migrated_phases_registered(self, proxy_instance):
        names = proxy_instance._phase_registry.current_graph.names
        for expected in (
            "parse",
            "experiment",
            "flow_xray_record",
            "cascade",
            "circuit_breaker",
            "loop_detection",
            "behavioral",
            "adaptive_detection",
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
            "send_response",
        ):
            assert expected in names, f"missing phase {expected!r}"

    def test_run_migrated_phase_returns_true_on_pass(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock

        legacy = _RequestContext(handler=MagicMock())
        # Replace _phase_experiment with a fake that returns True.
        proxy_instance._phase_experiment = lambda ctx: True  # type: ignore[method-assign]
        # Re-register the wrapper to bind the new method.
        proxy_instance._phase_registry.unregister("experiment")
        proxy_instance._phase_registry.register(
            make_legacy_phase("experiment", proxy_instance._phase_experiment)
        )
        proxy_instance._phase_registry.reload()
        assert proxy_instance._run_migrated_phase(legacy, "experiment") is True

    def test_run_migrated_phase_returns_false_on_block(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock

        legacy = _RequestContext(handler=MagicMock())
        proxy_instance._phase_experiment = lambda ctx: False  # type: ignore[method-assign]
        proxy_instance._phase_registry.unregister("experiment")
        proxy_instance._phase_registry.register(
            make_legacy_phase("experiment", proxy_instance._phase_experiment)
        )
        proxy_instance._phase_registry.reload()
        assert proxy_instance._run_migrated_phase(legacy, "experiment") is False

    def test_run_migrated_phase_caches_new_ctx(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock

        legacy = _RequestContext(handler=MagicMock())
        proxy_instance._phase_experiment = lambda ctx: True  # type: ignore[method-assign]
        proxy_instance._phase_registry.unregister("experiment")
        proxy_instance._phase_registry.register(
            make_legacy_phase("experiment", proxy_instance._phase_experiment)
        )
        proxy_instance._phase_registry.reload()

        proxy_instance._run_migrated_phase(legacy, "experiment")
        first_pl_ctx = getattr(legacy, "_pipeline_ctx", None)
        assert first_pl_ctx is not None
        proxy_instance._run_migrated_phase(legacy, "experiment")
        second_pl_ctx = getattr(legacy, "_pipeline_ctx", None)
        assert first_pl_ctx is second_pl_ctx, "pipeline ctx must be cached per request"

    def test_skip_phases_short_circuits(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock

        called = []

        def trap(ctx):
            called.append(ctx)
            return True

        proxy_instance._phase_experiment = trap  # type: ignore[method-assign]
        proxy_instance._phase_registry.unregister("experiment")
        proxy_instance._phase_registry.register(
            make_legacy_phase("experiment", proxy_instance._phase_experiment)
        )
        proxy_instance._phase_registry.reload()

        legacy = _RequestContext(handler=MagicMock(), skip_phases={"experiment"})
        assert proxy_instance._run_migrated_phase(legacy, "experiment") is True
        assert called == []  # phase method must not have been invoked
