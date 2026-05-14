"""Checkpoint 2 hot-reload integration test.

Simulates the SPEC §2.2 acceptance scenario:
  - Start 100 concurrent "requests" (each acquires the registry graph and
    runs one migrated phase).
  - Mid-flight, trigger pipeline reload.
  - Verify all 100 requests complete successfully.
  - Verify new requests started after reload see the new graph version.

In-process equivalent of the HTTP-level test. Real HTTP-level coverage
arrives in Checkpoint 3 once the engine drives the full request loop.
"""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import MagicMock

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


def _ctx() -> RequestContext:
    return RequestContext(
        id=Identity("r", "s", "a", "c", "lite"),
        input=InputSnapshot(b"", (), (), "m", {}, None, {}),
        processed=Processed(),
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


class TestHotReloadIntegration:
    def test_concurrent_requests_during_reload(self):
        """100 concurrent acquire/process/release while reload happens."""
        registry = PhaseRegistry()

        def make_phase(name: str):
            return make_legacy_phase(name, lambda c: True)

        for n in ("alpha", "bravo", "charlie", "delta"):
            registry.register(make_phase(n))
        registry.reload()
        engine = PipelineEngine(registry)

        results: list[bool] = []
        errors: list[Exception] = []
        ctx_lock = threading.Lock()

        def request_worker(phase_name: str):
            ctx = _ctx()
            ctx.processed.params["_legacy_ctx"] = MagicMock()
            try:
                # Simulate proxy's per-request flow: acquire, run, release
                # implicitly via process_one.
                r = asyncio.run(engine.process_one(phase_name, ctx))
                with ctx_lock:
                    results.append(r.status == "pass")
            except Exception as e:  # pragma: no cover
                with ctx_lock:
                    errors.append(e)

        # 100 workers, mostly running alpha; some reloads interleaved.
        workers: list[threading.Thread] = []
        for i in range(100):
            phase = ("alpha", "bravo", "charlie", "delta")[i % 4]
            workers.append(threading.Thread(target=request_worker, args=(phase,)))

        # Start half, reload, start the other half.
        for w in workers[:50]:
            w.start()

        # Reload mid-flight.
        time.sleep(0.02)
        registry.reload()

        for w in workers[50:]:
            w.start()

        for w in workers:
            w.join()

        assert not errors, f"errors during concurrent reload: {errors}"
        assert len(results) == 100
        assert all(results), "every request should succeed (pass)"

    def test_reload_swap_uses_new_phase_after(self):
        registry = PhaseRegistry()
        registry.register(make_legacy_phase("p", lambda c: True))
        registry.reload()
        engine = PipelineEngine(registry)

        # Before reload — phase p exists.
        ctx = _ctx()
        ctx.processed.params["_legacy_ctx"] = MagicMock()
        assert asyncio.run(engine.process_one("p", ctx)).status == "pass"

        # Replace p with a new method that returns False; reload.
        registry.unregister("p")
        registry.register(make_legacy_phase("p", lambda c: False))
        registry.reload()

        ctx2 = _ctx()
        ctx2.processed.params["_legacy_ctx"] = MagicMock()
        result = asyncio.run(engine.process_one("p", ctx2))
        assert result.status == "block"

    def test_in_flight_holds_old_snapshot_through_reload(self):
        """An in-flight graph reference survives reload."""
        registry = PhaseRegistry()
        registry.register(make_legacy_phase("p", lambda c: True))
        registry.reload()

        held = registry.acquire_for_request()
        try:
            # Reload while held.
            registry.register(make_legacy_phase("q", lambda c: True))
            registry.reload()
            # Held snapshot still has only p.
            assert "p" in held
            assert "q" not in held
            # Current graph has both.
            assert "p" in registry.current_graph
            assert "q" in registry.current_graph
            # Lingering snapshot recorded.
            assert registry.lingering_versions
        finally:
            registry.release(held)
        # After release, lingering set drained.
        assert registry.lingering_versions == ()
