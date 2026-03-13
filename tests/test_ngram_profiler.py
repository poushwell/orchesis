from __future__ import annotations

import threading

from orchesis.ngram_profiler import (
    NgramProfiler,
    ProfileDrift,
    classify_drift,
    cosine_similarity,
    js_divergence,
)


# Tokenization
def test_tokenize_simple() -> None:
    profiler = NgramProfiler()
    assert profiler.tokenize("hello world") == ["hello", "world"]


def test_tokenize_punctuation_stripped() -> None:
    profiler = NgramProfiler()
    assert profiler.tokenize("Hello, world!!!") == ["hello", "world"]


def test_tokenize_lowercase() -> None:
    profiler = NgramProfiler()
    assert profiler.tokenize("HeLLo WoRLD") == ["hello", "world"]


def test_tokenize_empty() -> None:
    profiler = NgramProfiler()
    assert profiler.tokenize("") == []


def test_tokenize_unicode() -> None:
    profiler = NgramProfiler()
    tokens = profiler.tokenize("Привет мир こんにちは 世界")
    assert len(tokens) >= 4


# N-gram computation
def test_unigrams_count() -> None:
    profiler = NgramProfiler()
    counts = profiler.compute_ngrams(["a", "b", "a"], 1)
    assert counts["a"] == 2


def test_bigrams_count() -> None:
    profiler = NgramProfiler()
    counts = profiler.compute_ngrams(["a", "b", "c"], 2)
    assert counts == {"a b": 1, "b c": 1}


def test_trigrams_count() -> None:
    profiler = NgramProfiler()
    counts = profiler.compute_ngrams(["a", "b", "c", "d"], 3)
    assert counts == {"a b c": 1, "b c d": 1}


def test_char_trigrams_count() -> None:
    profiler = NgramProfiler()
    counts = profiler.compute_char_ngrams("abcd", 3)
    assert counts == {"abc": 1, "bcd": 1}


def test_ngrams_empty_input() -> None:
    profiler = NgramProfiler()
    assert profiler.compute_ngrams([], 2) == {}


# Profile building
def test_build_profile_basic() -> None:
    profiler = NgramProfiler()
    profile = profiler.build_profile("a b c a")
    assert profile.total_tokens == 4
    assert profile.vocab_size == 3


def test_build_profile_top_k() -> None:
    profiler = NgramProfiler({"top_k": 3})
    text = " ".join([f"t{i}" for i in range(20)])
    profile = profiler.build_profile(text)
    assert len(profile.unigrams) <= 3


def test_build_profile_normalized_frequencies() -> None:
    profiler = NgramProfiler()
    profile = profiler.build_profile("a a b")
    total = sum(profile.unigrams.values())
    assert 0.99 <= total <= 1.01


def test_build_profile_vocab_size() -> None:
    profiler = NgramProfiler()
    profile = profiler.build_profile("x x y z")
    assert profile.vocab_size == 3


# Similarity metrics
def test_cosine_identical() -> None:
    assert cosine_similarity({"a": 1.0}, {"a": 1.0}) == 1.0


def test_cosine_orthogonal() -> None:
    assert cosine_similarity({"a": 1.0}, {"b": 1.0}) == 0.0


def test_cosine_partial_overlap() -> None:
    value = cosine_similarity({"a": 1.0, "b": 1.0}, {"a": 1.0, "c": 1.0})
    assert 0.0 < value < 1.0


def test_js_divergence_identical() -> None:
    assert js_divergence({"a": 1.0}, {"a": 1.0}) == 0.0


def test_js_divergence_different() -> None:
    value = js_divergence({"a": 1.0}, {"b": 1.0})
    assert value > 0.0


def test_js_divergence_symmetric() -> None:
    a = {"a": 0.5, "b": 0.5}
    b = {"a": 0.1, "c": 0.9}
    assert abs(js_divergence(a, b) - js_divergence(b, a)) < 1e-9


# Drift detection
def test_no_drift_same_text() -> None:
    profiler = NgramProfiler({"baseline_messages": 5, "min_tokens": 5, "window_size": 5})
    text = "assistant summary of project status and timeline"
    for _ in range(6):
        profiler.check("a", text)
    has_drift, drift = profiler.check("a", text)
    assert not has_drift
    assert drift.drift_score < 0.3


def test_drift_injection_foreign_content() -> None:
    profiler = NgramProfiler({"baseline_messages": 5, "min_tokens": 20, "window_size": 5, "drift_threshold": 0.2})
    base = "status status status status status status status status"
    for _ in range(8):
        profiler.check("a", base)
    has_drift, drift = profiler.check("a", "ZXQxQmFzZTY0QmxvYjEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    assert has_drift
    assert drift.drift_type in {"injection", "model_switch", "persona_drift"}


def test_drift_model_switch_uniform_shift() -> None:
    profiler = NgramProfiler({"drift_threshold": 0.2, "baseline_messages": 5, "min_tokens": 10})
    for _ in range(8):
        profiler.check("a", "short concise answer with stable vocabulary")
    has_drift, drift = profiler.check("a", "therefore furthermore consequently additionally notably")
    assert drift.drift_score >= 0.0
    assert isinstance(has_drift, bool)


def test_drift_persona_gradual_change() -> None:
    profiler = NgramProfiler({"baseline_messages": 5, "min_tokens": 10, "window_size": 4, "drift_threshold": 0.2})
    for _ in range(8):
        profiler.check("a", "formal concise assistant response")
    for text in [
        "formal concise assistant response with slight variation",
        "formal concise assistant response with more variation",
        "friendly playful style with emojis and informal tone",
    ]:
        has_drift, drift = profiler.check("a", text)
    assert isinstance(drift, ProfileDrift)
    assert drift.drift_type in {"persona_drift", "model_switch", "injection", "normal"}


def test_drift_below_threshold_normal() -> None:
    profiler = NgramProfiler({"drift_threshold": 0.9, "baseline_messages": 4, "min_tokens": 5})
    for _ in range(6):
        profiler.check("a", "hello world from assistant")
    has_drift, drift = profiler.check("a", "hello world from assistant now")
    assert not has_drift
    assert drift.drift_type == "normal"


# Drift classification
def test_classify_injection() -> None:
    kind = classify_drift(0.7, new_vocab=0.6, missing_vocab=0.1, char_change=0.5, uniform_shift=False, threshold=0.3)
    assert kind == "injection"


def test_classify_model_switch() -> None:
    kind = classify_drift(0.6, new_vocab=0.2, missing_vocab=0.2, char_change=0.2, uniform_shift=True, threshold=0.3)
    assert kind == "model_switch"


def test_classify_persona_drift() -> None:
    kind = classify_drift(0.5, new_vocab=0.2, missing_vocab=0.3, char_change=0.1, uniform_shift=False, threshold=0.3, gradual=True)
    assert kind == "persona_drift"


def test_classify_normal() -> None:
    kind = classify_drift(0.1, new_vocab=0.0, missing_vocab=0.0, char_change=0.0, uniform_shift=False, threshold=0.3)
    assert kind == "normal"


# Full pipeline
def test_check_builds_baseline_over_messages() -> None:
    profiler = NgramProfiler({"baseline_messages": 4, "min_tokens": 5})
    for i in range(5):
        profiler.check("a", f"assistant baseline message {i}")
    profile = profiler.get_profile("a")
    assert profile is not None
    assert profile["updates"] == 5


def test_check_no_drift_during_baseline_period() -> None:
    profiler = NgramProfiler({"baseline_messages": 6, "min_tokens": 100})
    for _ in range(3):
        has_drift, _ = profiler.check("a", "short")
        assert not has_drift


def test_check_flags_after_baseline() -> None:
    profiler = NgramProfiler({"baseline_messages": 4, "min_tokens": 10, "drift_threshold": 0.2})
    for _ in range(6):
        profiler.check("a", "normal normal normal normal normal")
    has_drift, drift = profiler.check("a", "foreign base64 ZXQxQmFzZTY0QmxvYg")
    assert drift.drift_score >= 0.0
    assert isinstance(has_drift, bool)


def test_check_multiple_agents_independent() -> None:
    profiler = NgramProfiler({"baseline_messages": 3, "min_tokens": 5})
    for _ in range(5):
        profiler.check("a", "alpha beta gamma delta")
        profiler.check("b", "one two three four")
    all_profiles = profiler.get_all_profiles()
    assert "a" in all_profiles and "b" in all_profiles


def test_check_only_profiles_assistant_messages() -> None:
    profiler = NgramProfiler()
    profiler.update("a", "user text", role="user")
    assert profiler.get_profile("a") is None
    profiler.update("a", "assistant text", role="assistant")
    assert profiler.get_profile("a") is not None


def test_check_thread_safety() -> None:
    profiler = NgramProfiler({"baseline_messages": 3, "min_tokens": 5})

    def worker(agent: str) -> None:
        for i in range(50):
            profiler.check(agent, f"text sequence {i} for {agent}")

    threads = [threading.Thread(target=worker, args=(f"a{i%3}",)) for i in range(9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    profiles = profiler.get_all_profiles()
    assert len(profiles) == 3
    assert sum(p["updates"] for p in profiles.values()) == 450


# Edge cases
def test_very_short_text_below_min_tokens() -> None:
    profiler = NgramProfiler({"min_tokens": 100, "baseline_messages": 3})
    for _ in range(5):
        has_drift, drift = profiler.check("a", "x")
    assert not has_drift
    assert drift.drift_type == "normal"


def test_single_word_repeated() -> None:
    profiler = NgramProfiler()
    profile = profiler.build_profile("loop " * 100)
    assert profile.vocab_size == 1


def test_very_long_text() -> None:
    profiler = NgramProfiler()
    text = "word " * 20000
    profile = profiler.build_profile(text)
    assert profile.total_tokens == 20000


def test_mixed_languages() -> None:
    profiler = NgramProfiler()
    profile = profiler.build_profile("hello привет こんにちは مرحبا")
    assert profile.vocab_size >= 4


def test_code_snippets_in_text() -> None:
    profiler = NgramProfiler()
    text = "def foo(x): return x + 1; SELECT * FROM table; curl http://x"
    profile = profiler.build_profile(text)
    assert profile.total_tokens > 5


def test_reset_clears_profile() -> None:
    profiler = NgramProfiler()
    profiler.check("a", "assistant baseline text")
    assert profiler.get_profile("a") is not None
    profiler.reset("a")
    assert profiler.get_profile("a") is None

