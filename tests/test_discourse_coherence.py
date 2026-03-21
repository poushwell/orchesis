from __future__ import annotations

import time

from orchesis.discourse_coherence import (
    _preprocess_messages,
    compute_entity_continuity,
    compute_flow_coherence,
    compute_headedness,
    compute_iacs_full,
)


def _msg(text: str) -> dict:
    return {"role": "user", "content": text}


def test_preprocess_messages_basic() -> None:
    messages = [
        _msg("# Title\nAlpha beta gamma"),
        _msg("1. first\n2. second"),
        _msg("Review report.txt for Project 42"),
    ]

    prep = _preprocess_messages(messages)

    assert len(prep) == 3
    for item in prep:
        assert {"text", "tokens", "bigrams", "entities", "has_header", "has_list", "word_count"}.issubset(item)


def test_preprocess_messages_empty() -> None:
    assert _preprocess_messages([]) == []


def test_preprocess_multipart_content() -> None:
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Alpha"},
                {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}},
                {"type": "text", "text": "Beta"},
            ],
        }
    ]

    prep = _preprocess_messages(messages)

    assert prep[0]["text"] == "Alpha Beta"
    assert prep[0]["tokens"] == ["alpha", "beta"]


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


def test_flow_coherence_single_pass() -> None:
    messages = [
        _msg("alpha beta gamma delta"),
        _msg("beta gamma delta epsilon"),
        _msg("gamma delta epsilon zeta"),
    ]
    prep = _preprocess_messages(messages)

    assert compute_flow_coherence(messages, _preprocessed=prep) == compute_flow_coherence(messages)


def test_entity_continuity_single_pass() -> None:
    messages = [
        _msg("Review report.txt for Project 42"),
        _msg("Update report.txt and notify Project 42"),
    ]
    prep = _preprocess_messages(messages)

    assert compute_entity_continuity(messages, _preprocessed=prep) == compute_entity_continuity(messages)


def test_headedness_single_pass() -> None:
    messages = [
        _msg("# Header\nAlpha beta"),
        _msg("1. Item one\n2. Item two"),
        _msg("This message has enough words to count as structured content here"),
    ]
    prep = _preprocess_messages(messages)

    assert compute_headedness(messages, _preprocessed=prep) == compute_headedness(messages)


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


def test_iacs_full_result() -> None:
    out = compute_iacs_full(
        [
            _msg("# Context Review\nReview report.txt for Project 42"),
            _msg("1. Summarize Project 42 findings"),
            _msg("Deliver final Project 42 recommendation list"),
        ]
    )

    assert {"iacs", "fc", "ec", "hc"} == set(out.keys())
    assert all(isinstance(out[key], float) for key in out)


def test_iacs_performance() -> None:
    messages = [_msg(f"Message {idx} about Project {idx % 7} in report.txt") for idx in range(100)]

    start = time.perf_counter()
    out = compute_iacs_full(messages)
    elapsed = time.perf_counter() - start

    assert out["iacs"] >= 0.0
    assert elapsed < 0.5
