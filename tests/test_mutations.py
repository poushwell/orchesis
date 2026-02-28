from __future__ import annotations

from pathlib import Path

from orchesis.config import load_policy
from orchesis.corpus import RegressionCorpus
from orchesis.engine import evaluate
from orchesis.mutations import MutationEngine


def _seeded_corpus() -> RegressionCorpus:
    return RegressionCorpus(str(Path(__file__).parent / "corpus"))


def _production_policy() -> dict:
    return load_policy(Path(__file__).parent.parent / "examples" / "production_policy.yaml")


def test_mutation_engine_generates_mutations() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    mutations = engine.generate(100)
    assert len(mutations) == 100
    for item in mutations:
        assert item.original_id.startswith("BYPASS-")
        assert isinstance(item.category, str)
        assert isinstance(item.mutation_type, str)
        assert isinstance(item.request, dict)
        assert isinstance(item.description, str)


def test_mutations_deterministic_with_seed() -> None:
    first = MutationEngine(_seeded_corpus(), seed=123).generate(50)
    second = MutationEngine(_seeded_corpus(), seed=123).generate(50)
    assert [(m.original_id, m.mutation_type, m.description) for m in first] == [
        (m.original_id, m.mutation_type, m.description) for m in second
    ]


def test_encoding_mutations_produce_variants() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    entry = next(item for item in _seeded_corpus().load_all() if item.category == "path_traversal")
    variants = [m for m in engine._mutate_entry(entry) if m.mutation_type == "encoding"]
    assert variants
    assert all(m.request != entry.request for m in variants)


def test_unicode_mutations_produce_variants() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    entry = next(item for item in _seeded_corpus().load_all() if item.category == "sql_injection")
    variants = [m for m in engine._mutate_entry(entry) if m.mutation_type == "unicode"]
    assert variants
    assert all(m.request != entry.request for m in variants)


def test_combination_mutations_cross_categories() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    entry = _seeded_corpus().load_all()[0]
    combo = next(m for m in engine._mutate_entry(entry) if m.mutation_type == "combine")
    assert "path" in combo.request["params"]
    assert "query" in combo.request["params"]
    assert combo.request["cost"] == -1.0


def test_boundary_mutations_test_limits() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    entry = next(item for item in _seeded_corpus().load_all() if item.category == "cost_manipulation")
    variants = [m for m in engine._mutate_entry(entry) if m.mutation_type == "boundary"]
    costs = sorted({float(m.request["cost"]) for m in variants})
    assert costs == [1.999, 2.0, 2.001]


def test_no_mutation_bypasses_production_policy() -> None:
    engine = MutationEngine(_seeded_corpus(), seed=42)
    policy = _production_policy()
    mutations = engine.generate(500)
    allowed = 0
    for mutation in mutations:
        decision = evaluate(mutation.request, policy)
        if decision.allowed:
            allowed += 1
    assert allowed == 0
