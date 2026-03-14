from __future__ import annotations

import time

from orchesis.semantic_cache import (
    HierarchicalCacheConfig,
    HierarchicalSemanticCache,
    SemanticCache,
    SemanticCacheConfig,
)


def _messages(text: str) -> list[dict[str, str]]:
    return [{"role": "user", "content": text}]


def test_l1_hit() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("hello world " * 5)
    assert cache.store(msgs, "gpt-4o", None, b'{"ok":1}', tokens=100, cost_usd=0.001)
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is True
    assert result.match_type == "l1_exact"


def test_l2_hit() -> None:
    cfg = HierarchicalCacheConfig(simhash_threshold=15, jaccard_threshold=0.35)
    cache = HierarchicalSemanticCache(cfg)
    msgs = _messages("the quick brown fox jumps over the lazy dog " * 2)
    assert cache.store(msgs, "gpt-4o", None, b'{"cached":true}', tokens=120, cost_usd=0.002)
    cache._l1.clear()
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is True
    assert result.match_type == "l2_semantic"


def test_l3_hit() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("long text " * 80)
    assert cache.store(msgs, "gpt-4o", None, b'{"tier":3}', tokens=800, cost_usd=0.01)
    cache._l1.clear()
    cache._l2.clear()
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is True
    assert result.match_type == "l3_exact"


def test_l2_promotes_to_l1() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("promote me " * 20)
    cache.store(msgs, "gpt-4o", None, b'{"x":1}', tokens=200, cost_usd=0.002)
    cache._l1.clear()
    r1 = cache.lookup(msgs, "gpt-4o", None)
    r2 = cache.lookup(msgs, "gpt-4o", None)
    assert r1.match_type == "l2_semantic"
    assert r2.match_type == "l1_exact"


def test_l3_promotes_to_l1() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("promote from l3 " * 50)
    cache.store(msgs, "gpt-4o", None, b'{"x":3}', tokens=900, cost_usd=0.02)
    cache._l1.clear()
    cache._l2.clear()
    r1 = cache.lookup(msgs, "gpt-4o", None)
    r2 = cache.lookup(msgs, "gpt-4o", None)
    assert r1.match_type == "l3_exact"
    assert r2.match_type == "l1_exact"


def test_miss() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    result = cache.lookup(_messages("nothing here " * 5), "gpt-4o", None)
    assert result.hit is False


def test_l3_min_tokens_threshold() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l3_min_tokens=500))
    msgs = _messages("short for l3 " * 30)
    cache.store(msgs, "gpt-4o", None, b'{"x":2}', tokens=200, cost_usd=0.001)
    assert len(cache._l3) == 0


def test_l1_ttl_eviction() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l1_ttl_seconds=0.1))
    msgs = _messages("ttl one " * 20)
    cache.store(msgs, "gpt-4o", None, b'{"x":1}', tokens=100, cost_usd=0.001)
    assert cache.lookup(msgs, "gpt-4o", None).hit is True
    time.sleep(0.12)
    cache._l2.clear()
    assert cache.lookup(msgs, "gpt-4o", None).hit is False


def test_l3_long_ttl() -> None:
    cfg = HierarchicalCacheConfig(l1_ttl_seconds=0.1, l3_ttl_seconds=10.0, l3_min_tokens=100)
    cache = HierarchicalSemanticCache(cfg)
    msgs = _messages("l3 survives " * 40)
    cache.store(msgs, "gpt-4o", None, b'{"x":3}', tokens=200, cost_usd=0.002)
    time.sleep(0.12)
    cache._l2.clear()
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is True
    assert result.match_type == "l3_exact"


def test_l1_lru_eviction() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l1_max_entries=2))
    m1 = _messages("a " * 30)
    m2 = _messages("b " * 30)
    m3 = _messages("c " * 30)
    cache.store(m1, "gpt-4o", None, b"1", tokens=10)
    cache.store(m2, "gpt-4o", None, b"2", tokens=10)
    cache.store(m3, "gpt-4o", None, b"3", tokens=10)
    cache._l2.clear()
    assert cache.lookup(m1, "gpt-4o", None).hit is False


def test_stats_l1_hits() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("stats l1 " * 20)
    cache.store(msgs, "gpt-4o", None, b"x", tokens=100)
    cache.lookup(msgs, "gpt-4o", None)
    assert cache.get_stats()["l1_hits"] >= 1


def test_stats_l2_hits() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    msgs = _messages("stats l2 " * 20)
    cache.store(msgs, "gpt-4o", None, b"x", tokens=100)
    cache._l1.clear()
    cache.lookup(msgs, "gpt-4o", None)
    assert cache.get_stats()["l2_hits"] >= 1


def test_stats_l3_hits() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l3_min_tokens=100))
    msgs = _messages("stats l3 " * 30)
    cache.store(msgs, "gpt-4o", None, b"x", tokens=200)
    cache._l1.clear()
    cache._l2.clear()
    cache.lookup(msgs, "gpt-4o", None)
    assert cache.get_stats()["l3_hits"] >= 1


def test_stats_hit_rate() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig())
    hit_msgs = _messages("hit rate " * 20)
    miss_msgs = _messages("miss rate " * 20)
    cache.store(hit_msgs, "gpt-4o", None, b"x", tokens=100)
    cache.lookup(hit_msgs, "gpt-4o", None)
    cache.lookup(miss_msgs, "gpt-4o", None)
    stats = cache.get_stats()
    assert 0.0 <= stats["hit_rate_percent"] <= 100.0


def test_clear() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l3_min_tokens=1))
    msgs = _messages("clear me " * 20)
    cache.store(msgs, "gpt-4o", None, b"x", tokens=200)
    cache.clear()
    assert cache.get_stats()["l1_entries"] == 0
    assert cache.get_stats()["l2_entries"] == 0
    assert cache.get_stats()["l3_entries"] == 0


def test_invalidate() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(l3_min_tokens=1))
    msgs = _messages("invalidate me " * 20)
    cache.store(msgs, "gpt-4o", None, b"x", tokens=200)
    content = SemanticCache._extract_content(msgs)
    key = SemanticCache._exact_hash(content, SemanticCache._compute_structural_key("gpt-4o", msgs, None))
    assert cache.invalidate(key) is True
    cache._l2.clear()
    assert cache.lookup(msgs, "gpt-4o", None).hit is False


def test_existing_semantic_cache_unchanged() -> None:
    cache = SemanticCache(SemanticCacheConfig(enabled=True))
    msgs = _messages("semantic unchanged " * 20)
    cache.store(msgs, "gpt-4o", None, b'{"ok":1}', tokens=100, cost_usd=0.001)
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is True
    assert result.match_type in {"exact", "semantic"}


def test_disabled() -> None:
    cache = HierarchicalSemanticCache(HierarchicalCacheConfig(enabled=False))
    msgs = _messages("disabled " * 20)
    assert cache.store(msgs, "gpt-4o", None, b"x", tokens=100) is False
    result = cache.lookup(msgs, "gpt-4o", None)
    assert result.hit is False

