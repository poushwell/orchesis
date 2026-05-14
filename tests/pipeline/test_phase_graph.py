"""Tests for PhaseGraph — Kahn topological sort with lex tie-break.

Acceptance per SPEC §2.1 Checkpoint 1: minimum 30 tests covering simple
deps, complex deps, cycle detection, lex tie-break determinism, and error
cases (unknown deps, duplicate names).
"""

from __future__ import annotations

import pytest

from orchesis.pipeline import PhaseGraph, PhaseGraphError
from tests.pipeline.conftest import make_phase


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestEmptyAndSingle:
    def test_empty_graph(self):
        g = PhaseGraph([])
        assert len(g) == 0
        assert g.names == ()
        assert g.phases == ()

    def test_single_phase(self):
        p = make_phase("a")
        g = PhaseGraph([p])
        assert g.names == ("a",)
        assert g.phases == (p,)


class TestSimpleOrdering:
    def test_after_one(self):
        a = make_phase("a")
        b = make_phase("b", after=("a",))
        g = PhaseGraph([a, b])
        assert g.names == ("a", "b")

    def test_after_input_order_irrelevant(self):
        # Same constraints, different input order → same output.
        a = make_phase("a")
        b = make_phase("b", after=("a",))
        g1 = PhaseGraph([a, b])
        g2 = PhaseGraph([b, a])
        assert g1.names == g2.names

    def test_before_one(self):
        a = make_phase("a", before=("b",))
        b = make_phase("b")
        g = PhaseGraph([a, b])
        assert g.names == ("a", "b")

    def test_independent_phases_sorted_lex(self):
        c = make_phase("c")
        a = make_phase("a")
        b = make_phase("b")
        g = PhaseGraph([c, a, b])
        assert g.names == ("a", "b", "c")


class TestChainOrdering:
    def test_three_node_chain(self):
        a = make_phase("a")
        b = make_phase("b", after=("a",))
        c = make_phase("c", after=("b",))
        g = PhaseGraph([c, a, b])
        assert g.names == ("a", "b", "c")

    def test_long_chain(self):
        phases = [make_phase("p0")]
        for i in range(1, 10):
            phases.append(make_phase(f"p{i}", after=(f"p{i-1}",)))
        # Shuffle input order.
        import random
        random.Random(42).shuffle(phases)
        g = PhaseGraph(phases)
        assert g.names == tuple(f"p{i}" for i in range(10))


class TestDiamondOrdering:
    def test_diamond_two_middle(self):
        # a → b → d, a → c → d. b and c independent → lex order.
        a = make_phase("a")
        b = make_phase("b", after=("a",))
        c = make_phase("c", after=("a",))
        d = make_phase("d", after=("b", "c"))
        g = PhaseGraph([d, c, b, a])
        assert g.names == ("a", "b", "c", "d")

    def test_diamond_three_middle(self):
        a = make_phase("a")
        m1 = make_phase("m1", after=("a",))
        m2 = make_phase("m2", after=("a",))
        m3 = make_phase("m3", after=("a",))
        end = make_phase("end", after=("m1", "m2", "m3"))
        g = PhaseGraph([end, m3, m2, m1, a])
        assert g.names == ("a", "m1", "m2", "m3", "end")


class TestMixedAfterBefore:
    def test_combining_after_and_before(self):
        a = make_phase("a")
        b = make_phase("b", after=("a",), before=("c",))
        c = make_phase("c")
        g = PhaseGraph([c, b, a])
        assert g.names == ("a", "b", "c")

    def test_redundant_after_before_pair(self):
        # a says before=b, b says after=a — should not create duplicate edges.
        a = make_phase("a", before=("b",))
        b = make_phase("b", after=("a",))
        g = PhaseGraph([a, b])
        assert g.names == ("a", "b")


class TestLexTieBreak:
    def test_lex_tie_break_no_deps(self):
        phases = [make_phase(name) for name in ("zebra", "apple", "mango")]
        g = PhaseGraph(phases)
        assert g.names == ("apple", "mango", "zebra")

    def test_lex_tie_break_after_pivot(self):
        root = make_phase("root")
        x = make_phase("xray", after=("root",))
        y = make_phase("yankee", after=("root",))
        z = make_phase("alpha", after=("root",))
        g = PhaseGraph([y, x, root, z])
        assert g.names == ("root", "alpha", "xray", "yankee")

    def test_deterministic_across_invocations(self):
        names = ["a", "b", "c", "d", "e", "f"]
        phases = [make_phase(n, after=tuple(names[:i]) if i % 2 else ())
                  for i, n in enumerate(names)]
        import random
        order = list(phases)
        results = set()
        for seed in range(5):
            random.Random(seed).shuffle(order)
            results.add(PhaseGraph(order).names)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Cycle detection
# ---------------------------------------------------------------------------


class TestCycleDetection:
    def test_self_loop(self):
        a = make_phase("a", after=("a",))
        with pytest.raises(PhaseGraphError, match="cycle"):
            PhaseGraph([a])

    def test_two_node_cycle(self):
        a = make_phase("a", after=("b",))
        b = make_phase("b", after=("a",))
        with pytest.raises(PhaseGraphError, match="cycle"):
            PhaseGraph([a, b])

    def test_three_node_cycle(self):
        a = make_phase("a", after=("c",))
        b = make_phase("b", after=("a",))
        c = make_phase("c", after=("b",))
        with pytest.raises(PhaseGraphError, match="cycle"):
            PhaseGraph([a, b, c])

    def test_cycle_via_before(self):
        # a → b → a using before edges.
        a = make_phase("a", before=("b",))
        b = make_phase("b", before=("a",))
        with pytest.raises(PhaseGraphError, match="cycle"):
            PhaseGraph([a, b])

    def test_partial_cycle_with_acyclic_neighbours(self):
        # a → b → c → b (cycle on b,c), plus z independent.
        a = make_phase("a", before=("b",))
        b = make_phase("b", after=("c",))
        c = make_phase("c", after=("b",))
        z = make_phase("z")
        with pytest.raises(PhaseGraphError, match="cycle"):
            PhaseGraph([a, b, c, z])


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestErrors:
    def test_duplicate_name(self):
        a1 = make_phase("a")
        a2 = make_phase("a")
        with pytest.raises(PhaseGraphError, match="duplicate"):
            PhaseGraph([a1, a2])

    def test_unknown_after(self):
        b = make_phase("b", after=("ghost",))
        with pytest.raises(PhaseGraphError, match="ghost"):
            PhaseGraph([b])

    def test_unknown_before(self):
        a = make_phase("a", before=("ghost",))
        with pytest.raises(PhaseGraphError, match="ghost"):
            PhaseGraph([a])

    def test_get_unknown(self):
        g = PhaseGraph([make_phase("a")])
        with pytest.raises(PhaseGraphError, match="unknown phase"):
            g.get("missing")


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


class TestAccessors:
    def test_contains(self):
        g = PhaseGraph([make_phase("a"), make_phase("b")])
        assert "a" in g
        assert "z" not in g

    def test_get_returns_phase(self):
        a = make_phase("a")
        g = PhaseGraph([a])
        assert g.get("a") is a

    def test_len_matches_phases(self):
        g = PhaseGraph([make_phase("a"), make_phase("b"), make_phase("c")])
        assert len(g) == 3 == len(g.phases) == len(g.names)


# ---------------------------------------------------------------------------
# Phase ClassVar validation
# ---------------------------------------------------------------------------


class TestPhaseClassValidation:
    def test_invalid_name_rejected(self):
        from orchesis.pipeline import Phase

        with pytest.raises(TypeError, match="snake_case"):
            class BadName(Phase):
                name = "9bad"

                async def execute(self, ctx):  # type: ignore[override]
                    pass

    def test_appends_tracking_unknown_kind(self):
        from orchesis.pipeline import Phase

        with pytest.raises(TypeError, match="not in"):
            class BadAppends(Phase):
                name = "bad_appends"
                appends_tracking = frozenset({"unknown"})

                async def execute(self, ctx):  # type: ignore[override]
                    pass


# ---------------------------------------------------------------------------
# Stability — guards the snapshot test promised in SPEC §2.3 Checkpoint 3.
# ---------------------------------------------------------------------------


class TestStability:
    def test_identity_preserved(self):
        a = make_phase("a")
        b = make_phase("b", after=("a",))
        g = PhaseGraph([a, b])
        # Linearized phases are the same instances we passed in.
        assert g.phases[0] is a
        assert g.phases[1] is b

    def test_same_input_same_output_object_count(self):
        # Two independent constructions over the same set yield equal names.
        names = ["alpha", "beta", "gamma", "delta", "epsilon"]
        phases1 = [make_phase(n) for n in names]
        phases2 = [make_phase(n) for n in names]
        assert PhaseGraph(phases1).names == PhaseGraph(phases2).names

    def test_lingering_constraints_propagate(self):
        # Even when ordering is mostly determined by lex, an explicit after
        # constraint must still win against the lex preference.
        a = make_phase("alpha")
        b = make_phase("beta", after=("zulu",))
        z = make_phase("zulu")
        g = PhaseGraph([a, b, z])
        # 'beta' depends on 'zulu' so beta cannot precede zulu, even though
        # lex would put beta before zulu.
        names = g.names
        assert names.index("zulu") < names.index("beta")
