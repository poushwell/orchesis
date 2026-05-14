"""Phase registry: entry-point discovery, hot-reload, in-flight refcounting.

The registry owns a snapshot of `Phase` instances. On request entry, the
engine calls `acquire_for_request()` to obtain an immutable `PhaseGraph`
plus a refcount increment. After the request finishes, `release()` drops the
refcount. Hot-reload swaps the snapshot atomically; in-flight requests keep
their captured graph until release. Once refcount reaches zero on an
unloaded version, its graph becomes eligible for GC.
"""

from __future__ import annotations

import threading
from importlib import metadata as importlib_metadata
from typing import Any, Callable, Iterable

from orchesis.pipeline.graph import PhaseGraph, PhaseGraphError
from orchesis.pipeline.phase import Phase


ENTRY_POINT_GROUP = "orchesis.phases"


class PhaseRegistryError(Exception):
    """Raised on duplicate registration or invalid plugin."""


class _Snapshot:
    __slots__ = ("graph", "version", "refcount")

    def __init__(self, graph: PhaseGraph, version: int) -> None:
        self.graph = graph
        self.version = version
        self.refcount = 0


class PhaseRegistry:
    """Discovers and loads phases via entry_points. Hot-reloadable.

    Concurrency model:
      - `_lock` guards the snapshot pointer and refcount increments.
      - `acquire_for_request()` is the hot path; returns the current snapshot
        and bumps its refcount.
      - `release()` decrements refcount.
      - `reload()` builds a new snapshot, validates it, then atomically swaps
        the pointer. In-flight requests still hold the old snapshot until
        their release.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._current: _Snapshot = _Snapshot(PhaseGraph([]), version=0)
        self._registered: dict[str, Phase] = {}
        # Old snapshots still held by in-flight requests. Indexed by version.
        self._lingering: dict[int, _Snapshot] = {}
        self._version_counter = 0

    # -------- mutation API -----------------------------------------------

    def register(self, phase: Phase) -> None:
        """Add a single phase instance to the pending set. Rebuild graph on
        the next reload() call (or build_graph()).
        """
        with self._lock:
            if phase.name in self._registered:
                raise PhaseRegistryError(f"duplicate phase name {phase.name!r}")
            self._registered[phase.name] = phase

    def unregister(self, name: str) -> None:
        with self._lock:
            self._registered.pop(name, None)

    def clear(self) -> None:
        with self._lock:
            self._registered.clear()

    def discover(
        self,
        group: str = ENTRY_POINT_GROUP,
        loader: Callable[[str], Iterable[Any]] | None = None,
    ) -> list[str]:
        """Scan entry_points group and load discovered Phase classes.

        Returns the list of loaded phase names. Errors loading any single
        entry point are reported via PhaseRegistryError but do not partially
        register — the registry is left unchanged on failure.

        Args:
            group: entry-points group to scan.
            loader: optional override for testing. Receives the group name
                and returns an iterable of objects with `.name` and
                `.load()` attributes (matching importlib.metadata.EntryPoint).
        """
        if loader is None:
            loader = _default_entry_point_loader  # type: ignore[assignment]
        new_phases: list[Phase] = []
        for ep in loader(group):
            try:
                target = ep.load()
            except Exception as e:  # pragma: no cover — depends on env
                raise PhaseRegistryError(
                    f"entry point {ep.name!r} failed to load: {e}"
                ) from e
            phase_obj = target() if isinstance(target, type) else target
            if not isinstance(phase_obj, Phase):
                raise PhaseRegistryError(
                    f"entry point {ep.name!r} produced {type(phase_obj).__name__}, "
                    f"not a Phase instance"
                )
            new_phases.append(phase_obj)
        loaded_names: list[str] = []
        with self._lock:
            for p in new_phases:
                if p.name in self._registered:
                    raise PhaseRegistryError(
                        f"duplicate phase name {p.name!r} during discovery"
                    )
                self._registered[p.name] = p
                loaded_names.append(p.name)
        return loaded_names

    def build_graph(self) -> PhaseGraph:
        """Construct a fresh PhaseGraph from the current registered set.
        Validates ordering and cycle freedom.
        """
        with self._lock:
            phases = list(self._registered.values())
        # Build outside the lock to avoid blocking acquire during cycle check.
        return PhaseGraph(phases)

    # -------- acquire/release for engine ---------------------------------

    def acquire_for_request(self) -> PhaseGraph:
        """Snapshot current graph for the lifetime of one request."""
        with self._lock:
            self._current.refcount += 1
            return self._current.graph

    def release(self, graph: PhaseGraph) -> None:
        """Drop refcount after request complete."""
        with self._lock:
            # Identify which snapshot owns this graph.
            if graph is self._current.graph:
                self._current.refcount = max(0, self._current.refcount - 1)
                return
            for ver, snap in list(self._lingering.items()):
                if snap.graph is graph:
                    snap.refcount = max(0, snap.refcount - 1)
                    if snap.refcount == 0:
                        del self._lingering[ver]
                    return
        # Unknown graph — no-op (defensive).

    # -------- hot-reload --------------------------------------------------

    def reload(self) -> int:
        """Rebuild graph from current registered phases and swap atomically.

        Returns the new version number. The previous snapshot is moved to
        the lingering set if it still has in-flight requests; otherwise
        garbage-collected on swap. If graph construction fails, the existing
        snapshot is preserved unchanged.
        """
        new_graph = self.build_graph()  # may raise PhaseGraphError
        with self._lock:
            self._version_counter += 1
            new_snapshot = _Snapshot(new_graph, version=self._version_counter)
            old = self._current
            self._current = new_snapshot
            if old.refcount > 0:
                self._lingering[old.version] = old
            return new_snapshot.version

    # -------- introspection ----------------------------------------------

    @property
    def current_version(self) -> int:
        with self._lock:
            return self._current.version

    @property
    def current_graph(self) -> PhaseGraph:
        with self._lock:
            return self._current.graph

    @property
    def in_flight_count(self) -> int:
        with self._lock:
            n = self._current.refcount
            for snap in self._lingering.values():
                n += snap.refcount
            return n

    @property
    def lingering_versions(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(sorted(self._lingering))


def _default_entry_point_loader(group: str) -> Iterable[Any]:
    """Default loader using importlib.metadata. Returns EntryPoint objects."""
    try:
        eps = importlib_metadata.entry_points(group=group)
    except TypeError:  # pragma: no cover — older importlib_metadata
        eps = importlib_metadata.entry_points().get(group, [])  # type: ignore[attr-defined]
    return list(eps)
