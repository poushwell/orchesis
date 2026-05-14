"""Phase graph: Kahn topological sort with lexicographic tie-break.

The graph linearizes phases respecting their `after`/`before` constraints.
Tie-break is lexicographic on phase name to ensure deterministic ordering
across registry snapshots — critical for the pipeline ordering snapshot test
introduced in Checkpoint 3 (SPEC §2.3).

Cycle detection runs at graph construction. Any unsatisfiable dependency or
cycle raises `PhaseGraphError` with a diagnostic.
"""

from __future__ import annotations

import heapq
from typing import Iterable, Sequence

from orchesis.pipeline.phase import Phase


class PhaseGraphError(Exception):
    """Raised when the phase graph cannot be linearized."""


class PhaseGraph:
    """Topologically sorted execution plan."""

    __slots__ = ("_phases_by_name", "_linearized")

    def __init__(self, phases: Iterable[Phase]):
        by_name: dict[str, Phase] = {}
        for p in phases:
            if p.name in by_name:
                raise PhaseGraphError(f"duplicate phase name {p.name!r}")
            by_name[p.name] = p
        self._phases_by_name = by_name
        self._linearized: tuple[Phase, ...] = tuple(self._linearize())

    @property
    def phases(self) -> tuple[Phase, ...]:
        return self._linearized

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self._linearized)

    def get(self, name: str) -> Phase:
        try:
            return self._phases_by_name[name]
        except KeyError as e:
            raise PhaseGraphError(f"unknown phase {name!r}") from e

    def __contains__(self, name: str) -> bool:
        return name in self._phases_by_name

    def __len__(self) -> int:
        return len(self._linearized)

    # ---- internal --------------------------------------------------------

    def _build_dep_graph(self) -> dict[str, set[str]]:
        """Return adjacency map `succ` where succ[a] = set of nodes b such
        that a must run before b (i.e., edge a → b).
        """
        names = set(self._phases_by_name)
        succ: dict[str, set[str]] = {n: set() for n in names}

        for name, phase in self._phases_by_name.items():
            for predecessor in phase.after:
                if predecessor not in names:
                    raise PhaseGraphError(
                        f"phase {name!r} declares after={predecessor!r} "
                        f"which is not registered"
                    )
                succ[predecessor].add(name)  # predecessor → name
            for successor in phase.before:
                if successor not in names:
                    raise PhaseGraphError(
                        f"phase {name!r} declares before={successor!r} "
                        f"which is not registered"
                    )
                succ[name].add(successor)  # name → successor

        return succ

    def _linearize(self) -> list[Phase]:
        if not self._phases_by_name:
            return []
        succ = self._build_dep_graph()
        in_degree: dict[str, int] = {n: 0 for n in self._phases_by_name}
        for src, sinks in succ.items():
            for s in sinks:
                in_degree[s] += 1

        # Min-heap on name for lex tie-break.
        ready: list[str] = [n for n, deg in in_degree.items() if deg == 0]
        heapq.heapify(ready)
        order: list[Phase] = []

        while ready:
            cur = heapq.heappop(ready)
            order.append(self._phases_by_name[cur])
            for nxt in sorted(succ[cur]):  # determinism: sorted iteration
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    heapq.heappush(ready, nxt)

        if len(order) != len(self._phases_by_name):
            remaining = [n for n, d in in_degree.items() if d > 0]
            cycle = self._extract_cycle(succ, remaining)
            raise PhaseGraphError(
                f"cycle detected in phase ordering: {' -> '.join(cycle)}"
            )
        return order

    @staticmethod
    def _extract_cycle(succ: dict[str, set[str]], candidates: Sequence[str]) -> list[str]:
        """Return a representative cycle path for diagnostics."""
        candidate_set = set(candidates)
        if not candidate_set:
            return []
        start = sorted(candidate_set)[0]
        path: list[str] = []
        seen: set[str] = set()
        cur = start
        while cur not in seen:
            seen.add(cur)
            path.append(cur)
            # Pick first successor that is also in candidates.
            choices = sorted(s for s in succ[cur] if s in candidate_set)
            if not choices:
                break
            cur = choices[0]
        path.append(cur)
        # Trim prefix not part of the cycle.
        if cur in path[:-1]:
            idx = path.index(cur)
            return path[idx:]
        return path


def linearize_phases(phases: Iterable[Phase]) -> tuple[Phase, ...]:
    """Convenience helper that returns the linearized order directly."""
    return PhaseGraph(phases).phases
