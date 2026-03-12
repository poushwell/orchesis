from __future__ import annotations

import random
import threading
import time
from typing import Any

from orchesis.entropy_detector import (
    EntropyBaseline,
    EntropyDetector,
    EntropyProfile,
    length_entropy,
    ngram_repetition,
    shannon_entropy,
    timing_entropy,
    tool_entropy,
    vocab_richness,
)


# Shannon entropy tests
def test_entropy_empty_string() -> None:
    assert shannon_entropy("") == 0.0


def test_entropy_single_word() -> None:
    assert shannon_entropy("hello") == 0.0


def test_entropy_uniform_distribution() -> None:
    text = "a b c d"
    assert round(shannon_entropy(text), 3) >= 1.9


def test_entropy_single_repeated_word() -> None:
    assert shannon_entropy("loop loop loop loop loop") == 0.0


def test_entropy_natural_text() -> None:
    text = "the assistant explains the result and provides a concise summary of the process"
    h = shannon_entropy(text)
    assert 2.0 <= h <= 4.5


def test_entropy_random_chars() -> None:
    text = "A1z9XqP8mN3vK7tB2yH6rJ5uC4dE0fG"
    assert shannon_entropy(text) > 3.0


# Message length entropy tests
def test_length_entropy_uniform() -> None:
    assert length_entropy([20, 20, 20, 20]) == 0.0


def test_length_entropy_varied() -> None:
    assert length_entropy([5, 20, 80, 300, 1200]) > 1.0


def test_length_entropy_bimodal() -> None:
    value = length_entropy([5, 6, 7, 800, 850, 900])
    assert value > 0.5


# Tool call entropy tests
def test_tool_entropy_single_tool() -> None:
    assert tool_entropy(["read_file"] * 10) == 0.0


def test_tool_entropy_diverse_tools() -> None:
    assert tool_entropy(["read_file", "write_file", "search", "execute"]) > 1.5


def test_tool_entropy_empty() -> None:
    assert tool_entropy([]) == 0.0


# Timing entropy tests
def test_timing_entropy_regular() -> None:
    assert timing_entropy([1.0, 1.0, 1.0, 1.0]) == 0.0


def test_timing_entropy_varied() -> None:
    assert timing_entropy([0.2, 2.0, 10.0, 45.0, 120.0]) > 1.0


def test_timing_entropy_single_interval() -> None:
    assert timing_entropy([2.0]) == 0.0


# Vocab richness tests
def test_vocab_richness_normal_text() -> None:
    value = vocab_richness("this is a simple sentence with repeated simple words")
    assert 0.3 <= value <= 0.9


def test_vocab_richness_repetitive() -> None:
    assert vocab_richness("heartbeat heartbeat heartbeat heartbeat") < 0.3


def test_vocab_richness_all_unique() -> None:
    assert vocab_richness("a b c d e f") == 1.0


# N-gram repetition tests
def test_ngram_repetition_no_repeats() -> None:
    assert ngram_repetition("a b c d e f g h", n=3) == 0.0


def test_ngram_repetition_heavy_loops() -> None:
    text = "read file now read file now read file now read file now"
    assert ngram_repetition(text, n=3) > 0.4


def test_ngram_repetition_natural_text() -> None:
    text = "the model wrote a response and then wrote another response for context"
    value = ngram_repetition(text, n=2)
    assert 0.0 <= value <= 0.5


# Baseline tests
def test_baseline_initial_no_anomaly() -> None:
    baseline = EntropyBaseline(window_size=20, sensitivity=2.0)
    profile = EntropyProfile(token_entropy=2.0, vocab_richness=0.5)
    is_anom, score, _ = baseline.is_anomalous(profile)
    assert not is_anom
    assert score == 0.0


def test_baseline_stable_then_spike() -> None:
    baseline = EntropyBaseline(window_size=20, sensitivity=2.0)
    for _ in range(15):
        baseline.update(EntropyProfile(token_entropy=2.0, tool_call_entropy=1.5, timing_entropy=1.0, repetition_score=0.2, vocab_richness=0.5, message_length_entropy=0.8))
    is_anom, score, _ = baseline.is_anomalous(
        EntropyProfile(token_entropy=5.0, tool_call_entropy=4.0, timing_entropy=4.0, repetition_score=0.0, vocab_richness=0.95, message_length_entropy=2.5)
    )
    assert is_anom
    assert score > 60


def test_baseline_stable_then_drop() -> None:
    baseline = EntropyBaseline(window_size=20, sensitivity=2.0)
    for _ in range(15):
        baseline.update(EntropyProfile(token_entropy=3.0, tool_call_entropy=2.0, timing_entropy=1.5, repetition_score=0.2, vocab_richness=0.6, message_length_entropy=1.0))
    is_anom, score, _ = baseline.is_anomalous(
        EntropyProfile(token_entropy=0.0, tool_call_entropy=0.0, timing_entropy=0.0, repetition_score=0.95, vocab_richness=0.05, message_length_entropy=0.0)
    )
    assert is_anom
    assert score > 60


def test_baseline_gradual_shift() -> None:
    baseline = EntropyBaseline(window_size=50, sensitivity=2.0)
    for i in range(40):
        baseline.update(
            EntropyProfile(
                token_entropy=2.0 + i * 0.01,
                tool_call_entropy=1.0 + i * 0.01,
                timing_entropy=1.2 + i * 0.005,
                repetition_score=0.25 - i * 0.001,
                vocab_richness=0.5 + i * 0.002,
                message_length_entropy=0.8 + i * 0.003,
            )
        )
    is_anom, score, _ = baseline.is_anomalous(
        EntropyProfile(
            token_entropy=2.45,
            tool_call_entropy=1.45,
            timing_entropy=1.35,
            repetition_score=0.20,
            vocab_richness=0.58,
            message_length_entropy=0.95,
        )
    )
    assert not is_anom
    assert score < 60


def test_baseline_window_rolls() -> None:
    baseline = EntropyBaseline(window_size=5, sensitivity=2.0)
    for i in range(20):
        baseline.update(EntropyProfile(token_entropy=float(i)))
    stats = baseline.as_dict()
    assert int(stats["token_entropy"]["n"]) == 5
    assert int(stats["observation_count"]) == 20


def test_baseline_min_observations() -> None:
    detector = EntropyDetector({"min_observations": 10})
    for _ in range(9):
        is_anom, _, _ = detector.check("a", {"messages": [{"role": "user", "content": "hello world"}], "timestamp": time.time()})
        assert not is_anom


# Combined score tests
def test_anomaly_score_normal_traffic() -> None:
    detector = EntropyDetector({"min_observations": 8})
    base = time.time()
    for i in range(12):
        detector.check(
            "agent-normal",
            {
                "messages": [{"role": "user", "content": "summarize this short issue for me"}],
                "tools": ["read_file", "search"],
                "timestamp": base + i * 3.0,
            },
        )
    is_anom, score, _ = detector.check(
        "agent-normal",
        {
            "messages": [{"role": "user", "content": "summarize this short issue for me"}],
            "tools": ["read_file", "search"],
            "timestamp": base + 100.0,
        },
    )
    assert not is_anom
    assert score < 30


def test_anomaly_score_loop_pattern() -> None:
    detector = EntropyDetector({"min_observations": 8})
    base = time.time()
    for i in range(10):
        detector.check(
            "agent-loop",
            {
                "messages": [{"role": "user", "content": f"normal message {i} with several words"}],
                "tools": ["read_file", "search", "write_file"],
                "timestamp": base + i * 5.0,
            },
        )
    is_anom, score, _ = detector.check(
        "agent-loop",
        {
            "messages": [{"role": "user", "content": "heartbeat heartbeat heartbeat heartbeat heartbeat"}],
            "tools": ["read_file", "read_file", "read_file"],
            "timestamp": base + 60.0,
        },
    )
    assert is_anom
    assert score > 70


def test_anomaly_score_injection_pattern() -> None:
    detector = EntropyDetector({"min_observations": 8})
    base = time.time()
    for i in range(10):
        detector.check(
            "agent-inj",
            {
                "messages": [{"role": "user", "content": "status status status status status status"}],
                "tools": ["search"],
                "timestamp": base + i * 4.0,
            },
        )
    payload = "ZXQxQmFzZTY0QmxvYjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    is_anom, score, _ = detector.check(
        "agent-inj",
        {"messages": [{"role": "user", "content": payload}], "tools": ["execute"], "timestamp": base + 100.0},
    )
    assert is_anom
    assert score > 60


def test_anomaly_score_heartbeat() -> None:
    detector = EntropyDetector({"min_observations": 8})
    base = time.time()
    contents = [
        "perform task and produce concise response",
        "perform task now",
        "perform task and produce concise response with extra context please",
    ]
    offsets = [0, 1, 4, 10, 11, 17, 30, 31, 60, 61]
    for i in range(10):
        detector.check(
            "agent-heartbeat",
            {
                "messages": [{"role": "user", "content": contents[i % len(contents)]}],
                "tools": ["search", "read_file"],
                "timestamp": base + offsets[i],
            },
        )
    is_anom, score, _ = detector.check(
        "agent-heartbeat",
        {"messages": [{"role": "user", "content": "hb hb hb hb hb hb"}], "tools": ["read_file"], "timestamp": base + 62.0},
    )
    assert is_anom
    assert score > 70


def test_anomaly_score_mixed() -> None:
    detector = EntropyDetector({"min_observations": 8})
    base = time.time()
    for i in range(12):
        detector.check(
            "agent-mixed",
            {
                "messages": [{"role": "user", "content": "normal planning text with stable semantics"}],
                "tools": ["search", "read_file"],
                "timestamp": base + i * 4.0,
            },
        )
    is_anom, score, _ = detector.check(
        "agent-mixed",
        {
            "messages": [{"role": "user", "content": "normal planning text with stable semantics"}],
            "tools": ["search", "read_file", "read_file"],
            "timestamp": base + 49.0,
        },
    )
    assert score >= 0
    assert score <= 100
    assert isinstance(is_anom, bool)


# Full pipeline tests
def test_check_builds_baseline_over_time() -> None:
    detector = EntropyDetector({"min_observations": 5})
    base = time.time()
    for i in range(6):
        detector.check("a", {"messages": [{"content": "hello world message"}], "timestamp": base + i})
    baseline = detector.get_baseline("a")
    assert baseline is not None
    assert int(baseline["observation_count"]) == 6


def test_check_flags_after_baseline_established() -> None:
    detector = EntropyDetector({"min_observations": 5})
    base = time.time()
    for i in range(8):
        detector.check("a", {"messages": [{"content": "stable text for baseline profiling"}], "tools": ["search"], "timestamp": base + i * 3})
    is_anom, score, _ = detector.check(
        "a",
        {"messages": [{"content": "X9$@# !! @@ random random random random random"}], "tools": ["execute"], "timestamp": base + 100},
    )
    assert is_anom
    assert score > 50


def test_check_multiple_agents_independent() -> None:
    detector = EntropyDetector({"min_observations": 3})
    base = time.time()
    for i in range(5):
        detector.check("agent-1", {"messages": [{"content": "alpha beta gamma"}], "timestamp": base + i})
        detector.check("agent-2", {"messages": [{"content": "one two three"}], "timestamp": base + i})
    all_baselines = detector.get_all_baselines()
    assert "agent-1" in all_baselines
    assert "agent-2" in all_baselines
    assert all_baselines["agent-1"]["observation_count"] == 5


def test_check_thread_safety() -> None:
    detector = EntropyDetector({"min_observations": 3})
    start = time.time()

    def _worker(agent: str) -> None:
        for i in range(50):
            detector.check(
                agent,
                {"messages": [{"content": f"worker message {i} for {agent}"}], "tools": ["search"], "timestamp": start + random.random() + i},
            )

    threads = [threading.Thread(target=_worker, args=(f"a{i%4}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stats = detector.get_all_baselines()
    assert len(stats) == 4
    assert sum(int(item["observation_count"]) for item in stats.values()) == 400


def test_get_baseline_returns_stats() -> None:
    detector = EntropyDetector({"min_observations": 2})
    detector.check("a", {"messages": [{"content": "one two three"}], "timestamp": time.time()})
    baseline = detector.get_baseline("a")
    assert baseline is not None
    assert "token_entropy" in baseline


def test_reset_clears_baseline() -> None:
    detector = EntropyDetector()
    detector.check("a", {"messages": [{"content": "hello world"}], "timestamp": time.time()})
    assert detector.get_baseline("a") is not None
    detector.reset("a")
    assert detector.get_baseline("a") is None


# Edge cases
def test_unicode_text_entropy() -> None:
    text = "Привет мир こんにちは 世界 مرحبا"
    assert shannon_entropy(text) > 1.0


def test_very_long_message() -> None:
    detector = EntropyDetector()
    text = "word " * 12000
    profile = detector.analyze_message(text)
    assert isinstance(profile.token_entropy, float)


def test_empty_request_data() -> None:
    detector = EntropyDetector()
    profile = detector.analyze_request({})
    assert profile.token_entropy == 0.0


def test_missing_fields_in_request() -> None:
    detector = EntropyDetector()
    profile = detector.analyze_request({"messages": [{"role": "user"}]})
    assert isinstance(profile.vocab_richness, float)

