"""Tests for PhaseRegistry — entry-point discovery, refcount, hot-reload."""

from __future__ import annotations

import threading

import pytest

from orchesis.pipeline import (
    PhaseGraphError,
    PhaseRegistry,
    PhaseRegistryError,
)
from tests.pipeline.conftest import make_phase


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegister:
    def test_empty_registry_has_empty_graph(self):
        r = PhaseRegistry()
        assert r.current_graph.names == ()

    def test_register_then_build(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.register(make_phase("b", after=("a",)))
        g = r.build_graph()
        assert g.names == ("a", "b")

    def test_duplicate_register_rejected(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        with pytest.raises(PhaseRegistryError, match="duplicate"):
            r.register(make_phase("a"))

    def test_unregister_removes(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.unregister("a")
        assert r.build_graph().names == ()

    def test_clear(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.register(make_phase("b"))
        r.clear()
        assert r.build_graph().names == ()


# ---------------------------------------------------------------------------
# Reload + acquire/release
# ---------------------------------------------------------------------------


class TestReload:
    def test_reload_increments_version(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        v0 = r.current_version
        v1 = r.reload()
        assert v1 > v0
        assert r.current_version == v1

    def test_reload_swaps_current_graph(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        first = r.current_graph
        assert first.names == ("a",)
        r.register(make_phase("b"))
        r.reload()
        assert r.current_graph.names == ("a", "b")
        assert r.current_graph is not first

    def test_reload_fails_on_cycle_preserves_existing(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        # Add cyclic phases.
        r.register(make_phase("x", after=("y",)))
        r.register(make_phase("y", after=("x",)))
        with pytest.raises(PhaseGraphError, match="cycle"):
            r.reload()
        # Previous graph still active.
        assert r.current_graph.names == ("a",)


class TestAcquireRelease:
    def test_acquire_returns_current_graph(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        g = r.acquire_for_request()
        assert g.names == ("a",)
        r.release(g)

    def test_in_flight_count_tracks(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        assert r.in_flight_count == 0
        g1 = r.acquire_for_request()
        assert r.in_flight_count == 1
        g2 = r.acquire_for_request()
        assert r.in_flight_count == 2
        r.release(g1)
        assert r.in_flight_count == 1
        r.release(g2)
        assert r.in_flight_count == 0

    def test_release_unknown_graph_no_op(self):
        r = PhaseRegistry()
        # Empty registry, but acquire works (returns empty graph).
        unrelated = r.acquire_for_request()
        r.release(unrelated)
        # Release a totally unrelated object — must not raise.
        r.release(unrelated)

    def test_lingering_snapshot_after_reload(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        g_old = r.acquire_for_request()
        # Reload while old graph held.
        r.register(make_phase("b", after=("a",)))
        r.reload()
        assert g_old.names == ("a",)
        assert r.current_graph.names == ("a", "b")
        assert r.in_flight_count == 1
        assert len(r.lingering_versions) == 1
        # Release drops lingering version.
        r.release(g_old)
        assert r.in_flight_count == 0
        assert r.lingering_versions == ()

    def test_multiple_reloads_lingering(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        held = r.acquire_for_request()
        for n in ("b", "c", "d"):
            r.register(make_phase(n, after=("a",)))
            r.reload()
        # Only one snapshot lingers — old empty between reloads has refcount 0.
        assert len(r.lingering_versions) == 1
        r.release(held)
        assert r.lingering_versions == ()


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_concurrent_acquire_release(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(200):
                    g = r.acquire_for_request()
                    r.release(g)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert r.in_flight_count == 0

    def test_concurrent_reload_with_in_flight(self):
        r = PhaseRegistry()
        r.register(make_phase("a"))
        r.reload()
        captured: list[tuple[str, ...]] = []
        errors: list[Exception] = []

        def reader():
            try:
                for _ in range(100):
                    g = r.acquire_for_request()
                    captured.append(g.names)
                    r.release(g)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        def reloader():
            try:
                for i in range(50):
                    r.reload()
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=reloader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        # All captured graphs must have been valid linearizations.
        assert all(names == ("a",) for names in captured)


# ---------------------------------------------------------------------------
# Entry-point discovery (loader injection)
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_loader_returns_zero(self):
        r = PhaseRegistry()
        loaded = r.discover(loader=lambda group: [])
        assert loaded == []
        assert r.build_graph().names == ()

    def test_loader_returns_phase_class(self):
        from orchesis.pipeline import Phase, PhaseResult

        class MyPhase(Phase):
            name = "my_plugin"

            async def execute(self, ctx):  # type: ignore[override]
                return PhaseResult(status="pass")

        class _Stub:
            def __init__(self, name: str, target: object):
                self.name = name
                self._target = target

            def load(self) -> object:
                return self._target

        r = PhaseRegistry()
        loaded = r.discover(loader=lambda group: [_Stub("my_plugin", MyPhase)])
        assert loaded == ["my_plugin"]
        g = r.build_graph()
        assert g.names == ("my_plugin",)

    def test_loader_rejects_non_phase(self):
        class _Stub:
            name = "bad"

            def load(self) -> object:
                return "not a Phase"

        r = PhaseRegistry()
        with pytest.raises(PhaseRegistryError, match="not a Phase"):
            r.discover(loader=lambda group: [_Stub()])

    def test_duplicate_via_discovery(self):
        from orchesis.pipeline import Phase, PhaseResult

        class MyPhase(Phase):
            name = "dup_test"

            async def execute(self, ctx):  # type: ignore[override]
                return PhaseResult(status="pass")

        class _Stub:
            def __init__(self):
                self.name = "dup_test"

            def load(self):
                return MyPhase

        r = PhaseRegistry()
        r.register(make_phase("dup_test"))
        with pytest.raises(PhaseRegistryError, match="duplicate"):
            r.discover(loader=lambda group: [_Stub()])
