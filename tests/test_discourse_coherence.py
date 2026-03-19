from __future__ import annotations

from orchesis.discourse_coherence import (
    compute_entity_continuity,
    compute_flow_coherence,
    compute_headedness,
    compute_iacs_full,
)


def _msg(text: str) -> dict:
    return {"role": "user", "content": text}


def test_fc_perfect_overlap() -> None:
    messages = [
        _msg("alpha beta gamma"),
        _msg("alpha beta gamma"),
        _msg("alpha beta gamma"),
    ]
    fc = compute_flow_coherence(messages)
    assert abs(fc - 1.0) < 1e-9


def test_ec_entity_continuity() -> None:
    messages = [
        _msg("Review File report.txt for Project 42"),
        _msg("Update report.txt and notify Project team 42"),
    ]
    ec = compute_entity_continuity(messages)
    assert ec > 0.0


def test_iacs_full_formula() -> None:
    messages = [
        _msg("Analyze context window pressure in report.txt for Batch 7"),
        _msg("Summarize context window pressure findings for Batch 7"),
        _msg("Produce final recommendations for Batch 7 in report.txt"),
    ]
    out = compute_iacs_full(messages)
    expected = round(
        0.40 * compute_flow_coherence(messages)
        + 0.35 * compute_entity_continuity(messages)
        + 0.25 * compute_headedness(messages),
        4,
    )
    assert out["iacs"] == expected
    assert {"iacs", "fc", "ec", "hc"}.issubset(set(out.keys()))
