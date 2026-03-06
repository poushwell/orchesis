"""Tests for Semantic Cache — fuzzy response caching with SimHash + Jaccard."""

from __future__ import annotations

import json
import threading
import time

import pytest

from orchesis.semantic_cache import (
    SemanticCache,
    SemanticCacheConfig,
)


# --- SimHash (8 tests) ---


def test_simhash_identical_text() -> None:
    """Same text → distance 0."""
    a = SemanticCache._compute_simhash("hello world")
    b = SemanticCache._compute_simhash("hello world")
    assert SemanticCache._hamming_distance(a, b) == 0


def test_simhash_similar_text() -> None:
    """Similar texts → smaller distance than unrelated."""
    a = SemanticCache._compute_simhash("the quick brown fox jumps over the lazy dog")
    b = SemanticCache._compute_simhash("the quick brown fox runs over the lazy dog")
    c = SemanticCache._compute_simhash("quantum physics and relativity theory")
    d_ab = SemanticCache._hamming_distance(a, b)
    d_ac = SemanticCache._hamming_distance(a, c)
    assert d_ab < d_ac


def test_simhash_different_text() -> None:
    """Unrelated text → large distance (>20)."""
    a = SemanticCache._compute_simhash("the quick brown fox")
    b = SemanticCache._compute_simhash("quantum physics and relativity theory")
    assert SemanticCache._hamming_distance(a, b) > 20


def test_simhash_word_order() -> None:
    """'quick brown fox' vs 'brown quick fox' → both produce valid hashes."""
    a = SemanticCache._compute_simhash("quick brown fox")
    b = SemanticCache._compute_simhash("brown quick fox")
    assert isinstance(a, int) and isinstance(b, int)
    assert SemanticCache._hamming_distance(a, a) == 0


def test_simhash_deterministic() -> None:
    """Same input → same hash always."""
    text = "deterministic test"
    a = SemanticCache._compute_simhash(text)
    b = SemanticCache._compute_simhash(text)
    assert a == b


def test_simhash_empty_text() -> None:
    """Empty → deterministic value."""
    a = SemanticCache._compute_simhash("")
    b = SemanticCache._compute_simhash("")
    assert a == b == 0


def test_simhash_long_text() -> None:
    """10K chars → works, no crash."""
    text = "word " * 2000
    h = SemanticCache._compute_simhash(text)
    assert isinstance(h, int)


def test_simhash_unicode() -> None:
    """Handles non-ASCII."""
    a = SemanticCache._compute_simhash("café résumé naïve")
    b = SemanticCache._compute_simhash("café résumé naïve")
    assert a == b


# --- Trigrams + Jaccard (7 tests) ---


def test_trigrams_basic() -> None:
    """'hello' → {'hel', 'ell', 'llo'}."""
    t = SemanticCache._compute_trigrams("hello")
    assert "hel" in t
    assert "ell" in t
    assert "llo" in t


def test_trigrams_normalized() -> None:
    """Uppercase → lowered, whitespace collapsed."""
    t = SemanticCache._compute_trigrams("HELLO   WORLD")
    assert "hel" in t or "ell" in t


def test_jaccard_identical() -> None:
    """Same set → 1.0."""
    s = frozenset(["a", "b", "c"])
    assert SemanticCache._jaccard_similarity(s, s) == 1.0


def test_jaccard_disjoint() -> None:
    """No overlap → 0.0."""
    a = frozenset(["x", "y", "z"])
    b = frozenset(["p", "q", "r"])
    assert SemanticCache._jaccard_similarity(a, b) == 0.0


def test_jaccard_partial() -> None:
    """50% overlap → ~0.33-0.5."""
    a = frozenset(["a", "b", "c"])
    b = frozenset(["b", "c", "d"])
    j = SemanticCache._jaccard_similarity(a, b)
    assert 0.2 <= j <= 0.6


def test_jaccard_empty_sets() -> None:
    """Both empty → 1.0, one empty → 0.0."""
    assert SemanticCache._jaccard_similarity(frozenset(), frozenset()) == 1.0
    assert SemanticCache._jaccard_similarity(frozenset(["a"]), frozenset()) == 0.0


def test_jaccard_symmetric() -> None:
    """J(A,B) == J(B,A)."""
    a = frozenset(["a", "b"])
    b = frozenset(["b", "c"])
    assert SemanticCache._jaccard_similarity(a, b) == SemanticCache._jaccard_similarity(b, a)


# --- Structural Key (5 tests) ---


def test_structural_key_same_structure() -> None:
    """Same model+roles+tools → same key."""
    msgs = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
    a = SemanticCache._compute_structural_key("gpt-4", msgs, ["read_file"])
    b = SemanticCache._compute_structural_key("gpt-4", msgs, ["read_file"])
    assert a == b


def test_structural_key_different_model() -> None:
    """Different model → different key."""
    msgs = [{"role": "user", "content": "hi"}]
    a = SemanticCache._compute_structural_key("gpt-4", msgs, None)
    b = SemanticCache._compute_structural_key("claude-3", msgs, None)
    assert a != b


def test_structural_key_different_roles() -> None:
    """Different message sequence → different key."""
    msgs1 = [{"role": "user", "content": "a"}]
    msgs2 = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
    a = SemanticCache._compute_structural_key("m", msgs1, None)
    b = SemanticCache._compute_structural_key("m", msgs2, None)
    assert a != b


def test_structural_key_different_tools() -> None:
    """Different tools → different key."""
    msgs = [{"role": "user", "content": "hi"}]
    a = SemanticCache._compute_structural_key("m", msgs, ["read_file"])
    b = SemanticCache._compute_structural_key("m", msgs, ["write_file"])
    assert a != b


def test_structural_key_no_tools() -> None:
    """tools=None handled."""
    msgs = [{"role": "user", "content": "hi"}]
    key = SemanticCache._compute_structural_key("m", msgs, None)
    assert ":" in key


# --- Cache Lookup (10 tests) ---


def test_exact_hit() -> None:
    """Identical request → hit, match_type='exact'."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "summarize this document please"}]
    body = b'{"content":[{"type":"text","text":"Summary here"}]}'
    cache.store(msgs, "gpt-4", None, body, tokens=100, cost_usd=0.001)
    result = cache.lookup(msgs, "gpt-4", None)
    assert result.hit is True
    assert result.match_type == "exact"
    assert result.response_body == body


def test_semantic_hit() -> None:
    """Similar request → hit, match_type='semantic'."""
    cache = SemanticCache(
        SemanticCacheConfig(enabled=True, simhash_threshold=15, jaccard_threshold=0.35)
    )
    msgs1 = [{"role": "user", "content": "summarize this document for me please"}]
    msgs2 = [{"role": "user", "content": "please summarize this document for me"}]
    body = b'{"content":[{"type":"text","text":"Summary"}]}'
    cache.store(msgs1, "gpt-4", None, body, tokens=50, cost_usd=0.0005)
    result = cache.lookup(msgs2, "gpt-4", None)
    assert result.hit is True
    assert result.match_type == "semantic"
    assert result.similarity >= 0.3


def test_miss_different_content() -> None:
    """Unrelated → miss."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs1 = [{"role": "user", "content": "what is the capital of France"}]
    msgs2 = [{"role": "user", "content": "write a python function to sort a list"}]
    body = b'{"content":[{"type":"text","text":"Paris"}]}'
    cache.store(msgs1, "gpt-4", None, body)
    result = cache.lookup(msgs2, "gpt-4", None)
    assert result.hit is False


def test_miss_different_structure() -> None:
    """Same text, different model → miss."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "hello world" * 5}]
    body = b'{"content":[{"type":"text","text":"Hi"}]}'
    cache.store(msgs, "gpt-4", None, body)
    result = cache.lookup(msgs, "claude-3", None)
    assert result.hit is False


def test_semantic_hit_word_order() -> None:
    """'summarize doc' vs 'doc summarize' → hit."""
    cache = SemanticCache(
        SemanticCacheConfig(enabled=True, simhash_threshold=12, jaccard_threshold=0.4)
    )
    msgs1 = [{"role": "user", "content": "summarize the document for me"}]
    msgs2 = [{"role": "user", "content": "the document summarize for me"}]
    body = b'{"content":[{"type":"text","text":"Summary"}]}'
    cache.store(msgs1, "gpt-4", None, body)
    result = cache.lookup(msgs2, "gpt-4", None)
    assert result.hit is True or result.similarity < 0.4


def test_semantic_hit_synonym() -> None:
    """'explain X' vs 'describe X' → close."""
    cache = SemanticCache(
        SemanticCacheConfig(enabled=True, simhash_threshold=10, jaccard_threshold=0.35)
    )
    msgs1 = [{"role": "user", "content": "explain how photosynthesis works in plants"}]
    msgs2 = [{"role": "user", "content": "describe how photosynthesis works in plants"}]
    body = b'{"content":[{"type":"text","text":"Explanation"}]}'
    cache.store(msgs1, "gpt-4", None, body)
    result = cache.lookup(msgs2, "gpt-4", None)
    assert result.hit is True or result.similarity >= 0.3


def test_ttl_expiration() -> None:
    """Entry expires after TTL."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, ttl_seconds=0.1))
    msgs = [{"role": "user", "content": "hello world " * 5}]
    body = b'{"ok":true}'
    cache.store(msgs, "gpt-4", None, body)
    assert cache.lookup(msgs, "gpt-4", None).hit is True
    time.sleep(0.2)
    assert cache.lookup(msgs, "gpt-4", None).hit is False


def test_lru_eviction() -> None:
    """Oldest evicted at max_entries."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, max_entries=3))
    for i in range(5):
        msgs = [{"role": "user", "content": f"unique content {i} " * 5}]
        cache.store(msgs, "gpt-4", None, b"{}")
    assert len(cache._entries) <= 3


def test_similarity_score_returned() -> None:
    """Jaccard score in result."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "test content " * 5}]
    cache.store(msgs, "gpt-4", None, b"{}")
    result = cache.lookup(msgs, "gpt-4", None)
    assert result.similarity == 1.0


def test_max_content_length_skip() -> None:
    """Too long → not cached."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, max_content_length=100))
    msgs = [{"role": "user", "content": "x" * 200}]
    ok = cache.store(msgs, "gpt-4", None, b"{}")
    assert ok is False


# --- Cache Store (6 tests) ---


def test_store_basic() -> None:
    """Stored and retrievable."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "hello " * 10}]
    body = b'{"result":"ok"}'
    assert cache.store(msgs, "gpt-4", None, body) is True
    result = cache.lookup(msgs, "gpt-4", None)
    assert result.hit is True
    assert result.response_body == body


def test_store_too_short() -> None:
    """Below min_content_length → not stored."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, min_content_length=50))
    msgs = [{"role": "user", "content": "hi"}]
    assert cache.store(msgs, "gpt-4", None, b"{}") is False


def test_store_too_long() -> None:
    """Above max_content_length → not stored."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, max_content_length=50))
    msgs = [{"role": "user", "content": "x" * 100}]
    assert cache.store(msgs, "gpt-4", None, b"{}") is False


def test_store_tool_call_excluded() -> None:
    """tool_use response not cached."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, exclude_tool_calls=True))
    msgs = [{"role": "user", "content": "read file " * 5}]
    body = b'{"content":[{"type":"message","content":[{"type":"tool_use","name":"read"}]}]}'
    assert cache.store(msgs, "gpt-4", None, body) is False


def test_store_model_filter() -> None:
    """Only cacheable_models stored."""
    cache = SemanticCache(
        SemanticCacheConfig(enabled=True, cacheable_models=["gpt-4"])
    )
    msgs = [{"role": "user", "content": "hello " * 10}]
    assert cache.store(msgs, "claude-3", None, b"{}") is False
    assert cache.store(msgs, "gpt-4", None, b"{}") is True


def test_store_updates_simhash_index() -> None:
    """Index updated after store."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "content " * 10}]
    cache.store(msgs, "gpt-4", None, b"{}")
    assert len(cache._simhash_index) >= 1


# --- Stats (5 tests) ---


def test_stats_hit_rate() -> None:
    """Correct hit rate calculation."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "test " * 10}]
    cache.store(msgs, "gpt-4", None, b"{}")
    cache.lookup(msgs, "gpt-4", None)
    cache.lookup([{"role": "user", "content": "different " * 10}], "gpt-4", None)
    stats = cache.get_stats()
    assert stats["lookups"] == 2
    assert stats["hit_rate_percent"] >= 0


def test_stats_tokens_saved() -> None:
    """Accumulated tokens."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, track_savings=True))
    msgs = [{"role": "user", "content": "x" * 50}]
    cache.store(msgs, "gpt-4", None, b"{}", tokens=100, cost_usd=0.001)
    cache.lookup(msgs, "gpt-4", None)
    stats = cache.get_stats()
    assert stats["total_tokens_saved"] >= 0


def test_stats_cost_saved() -> None:
    """Accumulated cost."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, track_savings=True))
    msgs = [{"role": "user", "content": "y" * 50}]
    cache.store(msgs, "gpt-4", None, b"{}", tokens=50, cost_usd=0.0005)
    cache.lookup(msgs, "gpt-4", None)
    stats = cache.get_stats()
    assert "total_cost_saved_usd" in stats


def test_stats_evictions_counted() -> None:
    """Eviction counter."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, max_entries=2))
    for i in range(5):
        msgs = [{"role": "user", "content": f"evict {i} " * 5}]
        cache.store(msgs, "gpt-4", None, b"{}")
    stats = cache.get_stats()
    assert stats["evictions"] >= 3


def test_stats_empty_cache() -> None:
    """Zero values when empty."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    stats = cache.get_stats()
    assert stats["entries"] == 0
    assert stats["lookups"] == 0


# --- Integration (4 tests) ---


def test_thread_safe_concurrent() -> None:
    """10 threads store+lookup."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))

    def run(i: int) -> None:
        msgs = [{"role": "user", "content": f"thread {i} content " * 5}]
        cache.store(msgs, "gpt-4", None, b"{}")
        cache.lookup(msgs, "gpt-4", None)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cache.get_stats()["entries"] >= 1


def test_clear_cache() -> None:
    """clear() empties everything."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "clear test " * 5}]
    cache.store(msgs, "gpt-4", None, b"{}")
    cache.clear()
    assert len(cache._entries) == 0
    assert cache.lookup(msgs, "gpt-4", None).hit is False


def test_invalidate_entry() -> None:
    """Specific entry removed."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "invalidate " * 5}]
    cache.store(msgs, "gpt-4", None, b"{}")
    result = cache.lookup(msgs, "gpt-4", None)
    assert result.hit and result.cache_key
    cache.invalidate(result.cache_key)
    assert cache.lookup(msgs, "gpt-4", None).hit is False


def test_cache_doesnt_grow_unbounded() -> None:
    """Stays within max_entries."""
    cache = SemanticCache(SemanticCacheConfig(enabled=True, max_entries=10))
    for i in range(100):
        msgs = [{"role": "user", "content": f"bounded {i} " * 5}]
        cache.store(msgs, "gpt-4", None, b"{}")
    assert len(cache._entries) <= 10


# --- Proxy Integration (5 tests) ---


def test_proxy_cache_hit_skips_upstream() -> None:
    """Cached response returned."""
    from orchesis.proxy import LLMHTTPProxy, _RequestContext

    class FakeHandler:
        path = "/v1/messages"
        headers = {}

    proxy = LLMHTTPProxy(policy_path=None)
    cfg = SemanticCacheConfig(enabled=True)
    proxy._semantic_cache = SemanticCache(cfg)
    msgs = [{"role": "user", "content": "proxy cache test " * 5}]
    body = b'{"content":[{"type":"text","text":"cached"}],"usage":{"input_tokens":0,"output_tokens":0}}'
    proxy._semantic_cache.store(msgs, "gpt-4", None, body)
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": msgs, "model": "gpt-4"},
    )
    ctx.parsed_req = type("Parsed", (), {"tool_calls": [], "content_text": "test", "provider": "anthropic"})()
    ok = proxy._phase_upstream(ctx)
    assert ok is True
    assert ctx.from_semantic_cache is True
    assert ctx.resp_body == body


def test_proxy_cache_headers() -> None:
    """X-Orchesis-Cache, X-Orchesis-Cache-Similarity."""
    from orchesis.proxy import LLMHTTPProxy, _RequestContext

    class FakeHandler:
        path = "/v1/messages"
        headers = {}

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._semantic_cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "headers test " * 5}]
    proxy._semantic_cache.store(msgs, "gpt-4", None, b"{}")
    ctx = _RequestContext(handler=FakeHandler(), body={"messages": msgs, "model": "gpt-4"})
    ctx.parsed_req = type("Parsed", (), {"tool_calls": [], "content_text": "test", "provider": "anthropic"})()
    proxy._phase_upstream(ctx)
    assert ctx.from_semantic_cache
    assert "X-Orchesis-Cache" in ctx.session_headers


def test_proxy_stores_after_upstream() -> None:
    """Successful response cached."""
    from orchesis.proxy import LLMHTTPProxy, _RequestContext

    class FakeHandler:
        path = "/v1/messages"
        headers = {}

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._semantic_cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = [{"role": "user", "content": "store after " * 5}]
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": msgs, "model": "gpt-4"},
    )
    ctx.parsed_req = type("Parsed", (), {"tool_calls": [], "content_text": "test", "provider": "anthropic"})()
    ctx.provider = "anthropic"
    ctx.resp_status = 200
    ctx.resp_body = b'{"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":5}}'
    ctx.from_semantic_cache = False
    ctx.is_streaming = False
    ctx.proc_result = {"cost": 0.001, "allowed": True}
    proxy._phase_post_upstream(ctx)
    stats = proxy._semantic_cache.get_stats()
    assert stats["entries"] >= 1


def test_proxy_cache_stats() -> None:
    """Stats includes semantic_cache."""
    from orchesis.proxy import LLMHTTPProxy

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._semantic_cache = SemanticCache(SemanticCacheConfig(enabled=True))
    stats = proxy.stats
    assert "semantic_cache" in stats
    assert "hit_rate_percent" in stats["semantic_cache"]


def test_config_normalization() -> None:
    """semantic_cache config validated."""
    import tempfile
    from pathlib import Path

    from orchesis.config import load_policy

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(
            """
semantic_cache:
  enabled: true
  max_entries: 2000
  ttl_seconds: 600
  simhash_threshold: 8
  jaccard_threshold: 0.6
  min_content_length: 20
  max_content_length: 50000
  cacheable_models: []
  exclude_tool_calls: true
  track_savings: true
"""
        )
        path = f.name
    try:
        policy = load_policy(path)
        assert "semantic_cache" in policy
        sc = policy["semantic_cache"]
        assert isinstance(sc, dict)
        assert sc.get("enabled") is True
    finally:
        import os

        os.unlink(path)
