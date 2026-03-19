from __future__ import annotations

from orchesis.context_quality_index import ContextQualityIndex


def test_coherence_computed() -> None:
    cqi = ContextQualityIndex()
    assert cqi.compute_coherence(1.2) == 1.0
    assert cqi.compute_coherence(-0.4) == 0.0


def test_freshness_decays() -> None:
    cqi = ContextQualityIndex()
    messages = [{"content": "old"}, {"content": "newer"}, {"content": "newest"}]
    low_decay = cqi.compute_freshness(messages, decay=0.01)
    high_decay = cqi.compute_freshness(messages, decay=1.0)
    assert high_decay > low_decay


def test_density_unique_ratio() -> None:
    cqi = ContextQualityIndex()
    messages = [{"content": "a a a b"}]
    assert cqi.compute_density(messages) == 0.5


def test_cqs_weighted_average() -> None:
    cqi = ContextQualityIndex()
    out = cqi.compute_cqs({"iacs": 0.8, "freshness": 0.7, "density": 0.6, "relevance": 0.5})
    expected = 0.35 * 0.8 + 0.25 * 0.7 + 0.2 * 0.6 + 0.2 * 0.5
    assert out["cqs"] == round(expected, 4)


def test_grade_assigned() -> None:
    cqi = ContextQualityIndex()
    assert cqi.compute_cqs({"iacs": 0.95, "freshness": 0.95, "density": 0.95, "relevance": 0.95})["grade"] == "A"
    assert cqi.compute_cqs({"iacs": 0.65, "freshness": 0.65, "density": 0.65, "relevance": 0.65})["grade"] == "B"
    assert cqi.compute_cqs({"iacs": 0.45, "freshness": 0.45, "density": 0.45, "relevance": 0.45})["grade"] == "C"
    assert cqi.compute_cqs({"iacs": 0.2, "freshness": 0.2, "density": 0.2, "relevance": 0.2})["grade"] == "D"


def test_weights_sum_to_one() -> None:
    cqi = ContextQualityIndex()
    assert round(sum(cqi.weights.values()), 6) == 1.0


def test_empty_messages_safe() -> None:
    cqi = ContextQualityIndex()
    assert cqi.compute_freshness([]) == 0.0
    assert cqi.compute_density([]) == 0.0


def test_high_quality_context() -> None:
    cqi = ContextQualityIndex()
    out = cqi.compute_cqs({"iacs": 0.92, "freshness": 0.90, "density": 0.88, "relevance": 0.93})
    assert out["cqs"] > 0.8
    assert out["grade"] == "A"

