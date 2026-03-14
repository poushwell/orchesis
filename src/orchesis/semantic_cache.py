"""Semantic Cache: fuzzy response caching using SimHash and trigram similarity."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SemanticCacheConfig:
    """Configuration for semantic cache."""

    enabled: bool = True
    max_entries: int = 2000
    ttl_seconds: float = 600.0
    simhash_threshold: int = 8
    jaccard_threshold: float = 0.6
    min_content_length: int = 20
    max_content_length: int = 50000
    cacheable_models: list[str] = field(default_factory=list)
    exclude_tool_calls: bool = True
    track_savings: bool = True


@dataclass
class CacheEntry:
    """A cached response with semantic key."""

    exact_hash: str
    simhash: int
    trigrams: frozenset[str]
    structural_key: str
    response_body: bytes
    created_at: float
    hit_count: int = 0
    last_hit: float = 0.0
    tokens_saved: int = 0
    cost_saved_usd: float = 0.0


@dataclass
class CacheLookupResult:
    """Result of a cache lookup."""

    hit: bool
    response_body: bytes = b""
    match_type: str = ""
    similarity: float = 0.0
    hamming_distance: int = 64
    cache_key: str = ""
    tokens_saved: int = 0
    cost_saved_usd: float = 0.0


@dataclass
class HierarchicalCacheConfig:
    l1_max_entries: int = 200
    l1_ttl_seconds: float = 60.0
    l2_max_entries: int = 2000
    l2_ttl_seconds: float = 600.0
    l3_max_entries: int = 10000
    l3_ttl_seconds: float = 86400.0
    l3_min_tokens: int = 500
    simhash_threshold: int = 8
    jaccard_threshold: float = 0.6
    min_content_length: int = 20
    max_content_length: int = 50000
    enabled: bool = True


class HierarchicalSemanticCache:
    """Three-tier cache: L1 exact, L2 semantic, L3 long-term exact."""

    def __init__(self, config: Optional[HierarchicalCacheConfig] = None) -> None:
        self._config = config or HierarchicalCacheConfig()
        self._l1: OrderedDict[str, CacheEntry] = OrderedDict()
        self._l3: OrderedDict[str, CacheEntry] = OrderedDict()
        self._l2 = SemanticCache(
            SemanticCacheConfig(
                enabled=self._config.enabled,
                max_entries=int(self._config.l2_max_entries),
                ttl_seconds=float(self._config.l2_ttl_seconds),
                simhash_threshold=int(self._config.simhash_threshold),
                jaccard_threshold=float(self._config.jaccard_threshold),
                min_content_length=int(self._config.min_content_length),
                max_content_length=int(self._config.max_content_length),
            )
        )
        self._lock = threading.Lock()
        self._l1_hits = 0
        self._l2_hits = 0
        self._l3_hits = 0
        self._misses = 0
        self._promotions = 0
        self._total_tokens_saved = 0
        self._total_cost_saved = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self._config.enabled)

    def lookup(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        tools: list[str] | None = None,
    ) -> CacheLookupResult:
        if not self._config.enabled:
            return CacheLookupResult(hit=False)
        content = SemanticCache._extract_content(messages)
        if len(content) < self._config.min_content_length:
            return CacheLookupResult(hit=False)
        if len(content) > self._config.max_content_length:
            return CacheLookupResult(hit=False)
        structural_key = SemanticCache._compute_structural_key(model, messages, tools)
        exact_hash = SemanticCache._exact_hash(content, structural_key)

        with self._lock:
            l1_entry = self._l1_lookup(exact_hash)
            if l1_entry is not None:
                self._l1_hits += 1
                self._total_tokens_saved += int(l1_entry.tokens_saved)
                self._total_cost_saved += float(l1_entry.cost_saved_usd)
                return CacheLookupResult(
                    hit=True,
                    response_body=l1_entry.response_body,
                    match_type="l1_exact",
                    similarity=1.0,
                    hamming_distance=0,
                    cache_key=exact_hash,
                    tokens_saved=int(l1_entry.tokens_saved),
                    cost_saved_usd=float(l1_entry.cost_saved_usd),
                )

        l2_result = self._l2.lookup(messages, model=model, tools=tools)
        if l2_result.hit:
            promoted = CacheEntry(
                exact_hash=exact_hash,
                simhash=SemanticCache._compute_simhash(content),
                trigrams=SemanticCache._compute_trigrams(content),
                structural_key=structural_key,
                response_body=l2_result.response_body,
                created_at=time.time(),
                tokens_saved=int(l2_result.tokens_saved),
                cost_saved_usd=float(l2_result.cost_saved_usd),
            )
            with self._lock:
                self._l2_hits += 1
                self._promotions += 1
                self._total_tokens_saved += int(l2_result.tokens_saved)
                self._total_cost_saved += float(l2_result.cost_saved_usd)
                self._l1_store(exact_hash, promoted)
            return CacheLookupResult(
                hit=True,
                response_body=l2_result.response_body,
                match_type="l2_semantic",
                similarity=float(l2_result.similarity),
                hamming_distance=int(l2_result.hamming_distance),
                cache_key=str(l2_result.cache_key or exact_hash),
                tokens_saved=int(l2_result.tokens_saved),
                cost_saved_usd=float(l2_result.cost_saved_usd),
            )

        with self._lock:
            l3_entry = self._l3_lookup(exact_hash)
            if l3_entry is not None:
                self._l3_hits += 1
                self._promotions += 1
                self._total_tokens_saved += int(l3_entry.tokens_saved)
                self._total_cost_saved += float(l3_entry.cost_saved_usd)
                promoted = CacheEntry(
                    exact_hash=exact_hash,
                    simhash=l3_entry.simhash,
                    trigrams=l3_entry.trigrams,
                    structural_key=l3_entry.structural_key,
                    response_body=l3_entry.response_body,
                    created_at=time.time(),
                    tokens_saved=int(l3_entry.tokens_saved),
                    cost_saved_usd=float(l3_entry.cost_saved_usd),
                )
                self._l1_store(exact_hash, promoted)
                return CacheLookupResult(
                    hit=True,
                    response_body=l3_entry.response_body,
                    match_type="l3_exact",
                    similarity=1.0,
                    hamming_distance=0,
                    cache_key=exact_hash,
                    tokens_saved=int(l3_entry.tokens_saved),
                    cost_saved_usd=float(l3_entry.cost_saved_usd),
                )
            self._misses += 1
        return CacheLookupResult(hit=False)

    def store(
        self,
        messages: list[dict[str, Any]],
        model: str,
        tools: list[str] | None,
        response_body: bytes,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> bool:
        if not self._config.enabled:
            return False
        content = SemanticCache._extract_content(messages)
        if len(content) < self._config.min_content_length:
            return False
        if len(content) > self._config.max_content_length:
            return False

        ok_l2 = self._l2.store(
            messages=messages,
            model=model,
            tools=tools,
            response_body=response_body,
            tokens=tokens,
            cost_usd=cost_usd,
        )
        if not ok_l2:
            return False

        structural_key = SemanticCache._compute_structural_key(model, messages, tools)
        exact_hash = SemanticCache._exact_hash(content, structural_key)
        entry = CacheEntry(
            exact_hash=exact_hash,
            simhash=SemanticCache._compute_simhash(content),
            trigrams=SemanticCache._compute_trigrams(content),
            structural_key=structural_key,
            response_body=response_body,
            created_at=time.time(),
            tokens_saved=int(tokens),
            cost_saved_usd=float(cost_usd),
        )
        with self._lock:
            self._l1_store(exact_hash, entry)
            if int(tokens) >= int(self._config.l3_min_tokens):
                self._l3_store(exact_hash, entry)
        return True

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            total_lookups = self._l1_hits + self._l2_hits + self._l3_hits + self._misses
            total_hits = self._l1_hits + self._l2_hits + self._l3_hits
            hit_rate = (float(total_hits) / float(total_lookups) * 100.0) if total_lookups > 0 else 0.0
            l1_entries = len(self._l1)
            l3_entries = len(self._l3)
            tokens_saved = int(self._total_tokens_saved)
            cost_saved = float(self._total_cost_saved)
        l2_stats = self._l2.get_stats()
        return {
            "enabled": self._config.enabled,
            "l1_hits": int(self._l1_hits),
            "l2_hits": int(self._l2_hits),
            "l3_hits": int(self._l3_hits),
            "misses": int(self._misses),
            "promotions": int(self._promotions),
            "l1_entries": l1_entries,
            "l2_entries": int(l2_stats.get("entries", 0)),
            "l3_entries": l3_entries,
            "hit_rate_percent": round(hit_rate, 2),
            "total_tokens_saved": tokens_saved,
            "total_cost_saved_usd": round(cost_saved, 4),
            "l2_stats": l2_stats,
        }

    def clear(self) -> None:
        with self._lock:
            self._l1.clear()
            self._l3.clear()
        self._l2.clear()

    def invalidate(self, exact_hash: str) -> bool:
        key = str(exact_hash or "")
        removed = False
        with self._lock:
            if key in self._l1:
                self._l1.pop(key, None)
                removed = True
            if key in self._l3:
                self._l3.pop(key, None)
                removed = True
        if self._l2.invalidate(key):
            removed = True
        return removed

    def _l1_lookup(self, exact_hash: str) -> CacheEntry | None:
        self._evict_expired_tier(self._l1, self._config.l1_ttl_seconds)
        entry = self._l1.get(exact_hash)
        if entry is None:
            return None
        entry.hit_count += 1
        entry.last_hit = time.time()
        self._l1.move_to_end(exact_hash)
        return entry

    def _l3_lookup(self, exact_hash: str) -> CacheEntry | None:
        self._evict_expired_tier(self._l3, self._config.l3_ttl_seconds)
        entry = self._l3.get(exact_hash)
        if entry is None:
            return None
        entry.hit_count += 1
        entry.last_hit = time.time()
        self._l3.move_to_end(exact_hash)
        return entry

    def _l1_store(self, exact_hash: str, entry: CacheEntry) -> None:
        self._evict_expired_tier(self._l1, self._config.l1_ttl_seconds)
        self._l1[exact_hash] = entry
        self._l1.move_to_end(exact_hash)
        while len(self._l1) > int(self._config.l1_max_entries):
            self._l1.popitem(last=False)

    def _l3_store(self, exact_hash: str, entry: CacheEntry) -> None:
        self._evict_expired_tier(self._l3, self._config.l3_ttl_seconds)
        self._l3[exact_hash] = entry
        self._l3.move_to_end(exact_hash)
        while len(self._l3) > int(self._config.l3_max_entries):
            self._l3.popitem(last=False)

    @staticmethod
    def _evict_expired_tier(tier_dict: OrderedDict[str, CacheEntry], ttl: float) -> int:
        if ttl <= 0:
            count = len(tier_dict)
            tier_dict.clear()
            return count
        now = time.time()
        expired = [key for key, item in tier_dict.items() if (now - float(item.created_at)) > float(ttl)]
        for key in expired:
            tier_dict.pop(key, None)
        return len(expired)


class SemanticCache:
    """
    Fuzzy response cache using SimHash + trigram Jaccard similarity.
    Two-stage lookup: exact O(1) → SimHash scan → Jaccard verify.
    No external dependencies.
    """

    def __init__(self, config: Optional[SemanticCacheConfig] = None) -> None:
        self._config = config or SemanticCacheConfig()
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()
        self._simhash_index: list[tuple[int, str]] = []
        self._lookups: int = 0
        self._exact_hits: int = 0
        self._semantic_hits: int = 0
        self._misses: int = 0
        self._total_tokens_saved: int = 0
        self._total_cost_saved: float = 0.0
        self._evictions: int = 0

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def lookup(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        tools: list[str] | None = None,
    ) -> CacheLookupResult:
        if not self._config.enabled:
            return CacheLookupResult(hit=False)
        content = self._extract_content(messages)
        if len(content) < self._config.min_content_length:
            return CacheLookupResult(hit=False)
        if len(content) > self._config.max_content_length:
            return CacheLookupResult(hit=False)
        structural_key = self._compute_structural_key(model, messages, tools)
        exact_hash = self._exact_hash(content, structural_key)
        simhash = self._compute_simhash(content)
        trigrams = self._compute_trigrams(content)
        with self._lock:
            self._evict_expired()
            self._lookups += 1
            entry = self._entries.get(exact_hash)
            if entry is not None:
                self._exact_hits += 1
                self._entries.move_to_end(exact_hash)
                return CacheLookupResult(
                    hit=True,
                    response_body=entry.response_body,
                    match_type="exact",
                    similarity=1.0,
                    hamming_distance=0,
                    cache_key=exact_hash,
                    tokens_saved=entry.tokens_saved,
                    cost_saved_usd=entry.cost_saved_usd,
                )
            if self._config.cacheable_models and model and model not in self._config.cacheable_models:
                self._misses += 1
                return CacheLookupResult(hit=False)
            best: tuple[float, int, CacheEntry] | None = None
            for sh, eh in self._simhash_index:
                if eh not in self._entries:
                    continue
                ent = self._entries[eh]
                if ent.structural_key != structural_key:
                    continue
                hd = self._hamming_distance(simhash, sh)
                if hd > self._config.simhash_threshold:
                    continue
                jacc = self._jaccard_similarity(trigrams, ent.trigrams)
                if jacc < self._config.jaccard_threshold:
                    continue
                if best is None or jacc > best[0]:
                    best = (jacc, hd, ent)
            if best is not None:
                jacc, hd, ent = best
                self._semantic_hits += 1
                if self._config.track_savings:
                    self._total_tokens_saved += ent.tokens_saved
                    self._total_cost_saved += ent.cost_saved_usd
                self._entries.move_to_end(ent.exact_hash)
                return CacheLookupResult(
                    hit=True,
                    response_body=ent.response_body,
                    match_type="semantic",
                    similarity=jacc,
                    hamming_distance=hd,
                    cache_key=ent.exact_hash,
                    tokens_saved=ent.tokens_saved,
                    cost_saved_usd=ent.cost_saved_usd,
                )
            self._misses += 1
            return CacheLookupResult(hit=False)

    def store(
        self,
        messages: list[dict[str, Any]],
        model: str,
        tools: list[str] | None,
        response_body: bytes,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> bool:
        if not self._config.enabled:
            return False
        content = self._extract_content(messages)
        if len(content) < self._config.min_content_length:
            return False
        if len(content) > self._config.max_content_length:
            return False
        if self._config.cacheable_models and model and model not in self._config.cacheable_models:
            return False
        if self._config.exclude_tool_calls:
            try:
                decoded = json.loads(response_body.decode("utf-8"))
                if isinstance(decoded, dict):
                    for msg in decoded.get("content", []) if isinstance(decoded.get("content"), list) else []:
                        if isinstance(msg, dict) and msg.get("type") == "message":
                            for block in msg.get("content", []) or []:
                                if isinstance(block, dict) and block.get("type") == "tool_use":
                                    return False
                    choices = decoded.get("choices", [])
                    if isinstance(choices, list) and choices:
                        msg = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
                        for tc in msg.get("tool_calls", []) or []:
                            if isinstance(tc, dict):
                                return False
            except Exception:
                pass
        structural_key = self._compute_structural_key(model, messages, tools)
        exact_hash = self._exact_hash(content, structural_key)
        simhash = self._compute_simhash(content)
        trigrams = self._compute_trigrams(content)
        with self._lock:
            self._evict_expired()
            if exact_hash in self._entries:
                self._simhash_index[:] = [
                    (sh, eh) for sh, eh in self._simhash_index if eh != exact_hash
                ]
            while len(self._entries) >= self._config.max_entries:
                self._evict_lru()
            entry = CacheEntry(
                exact_hash=exact_hash,
                simhash=simhash,
                trigrams=trigrams,
                structural_key=structural_key,
                response_body=response_body,
                created_at=time.time(),
                tokens_saved=tokens,
                cost_saved_usd=cost_usd,
            )
            self._entries[exact_hash] = entry
            self._entries.move_to_end(exact_hash)
            self._simhash_index.append((simhash, exact_hash))
        return True

    def invalidate(self, exact_hash: str) -> bool:
        with self._lock:
            if exact_hash in self._entries:
                self._entries.pop(exact_hash, None)
                self._simhash_index[:] = [(sh, eh) for sh, eh in self._simhash_index if eh != exact_hash]
                return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._simhash_index.clear()

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            total_hits = self._exact_hits + self._semantic_hits
            hit_rate = (total_hits / self._lookups * 100.0) if self._lookups > 0 else 0.0
            return {
                "enabled": self._config.enabled,
                "entries": len(self._entries),
                "max_entries": self._config.max_entries,
                "lookups": self._lookups,
                "exact_hits": self._exact_hits,
                "semantic_hits": self._semantic_hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 2),
                "total_tokens_saved": self._total_tokens_saved,
                "total_cost_saved_usd": round(self._total_cost_saved, 4),
                "evictions": self._evictions,
            }

    @staticmethod
    def _compute_simhash(text: str, hash_bits: int = 64) -> int:
        if not text or not text.strip():
            return 0
        words = re.findall(r"\b\w+\b", text.lower())
        if not words:
            return 0
        shingles: list[str] = []
        for i in range(len(words) - 2):
            shingles.append(" ".join(words[i : i + 3]))
        if not shingles:
            shingles = [" ".join(words)]
        weights = [0] * hash_bits
        for sh in shingles:
            h = hashlib.sha256(sh.encode("utf-8")).digest()
            bits = int.from_bytes(h[:8], "big") if len(h) >= 8 else 0
            for i in range(hash_bits):
                if (bits >> i) & 1:
                    weights[i] += 1
                else:
                    weights[i] -= 1
        result = 0
        for i in range(hash_bits):
            if weights[i] > 0:
                result |= 1 << i
        return result

    @staticmethod
    def _hamming_distance(a: int, b: int) -> int:
        return bin(a ^ b).count("1")

    @staticmethod
    def _compute_trigrams(text: str) -> frozenset[str]:
        normalized = re.sub(r"\s+", " ", text.lower().strip())
        normalized = re.sub(r"[^\w\s]", "", normalized)
        if len(normalized) < 3:
            return frozenset()
        return frozenset(normalized[i : i + 3] for i in range(len(normalized) - 2))

    @staticmethod
    def _jaccard_similarity(a: frozenset[str], b: frozenset[str]) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union > 0 else 0.0

    @staticmethod
    def _compute_structural_key(model: str, messages: list[dict], tools: list[str] | None) -> str:
        roles: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                r = str(msg.get("role", "")).lower()[:1] or "u"
                roles.append(r if r in ("u", "a", "s", "t") else "u")
        roles_str = ",".join(roles) if roles else "u"
        tools_str = ",".join(sorted(tools)) if tools else ""
        return f"{model or ''}:{roles_str}:{tools_str}"

    @staticmethod
    def _extract_content(messages: list[dict]) -> str:
        parts: list[str] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text", "") or block.get("content", "")
                        if isinstance(text, str):
                            parts.append(text)
        return " ".join(parts)

    @staticmethod
    def _exact_hash(text: str, structural_key: str) -> str:
        blob = f"{structural_key}:{text}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _evict_expired(self) -> int:
        now = time.time()
        expired = [
            eh
            for eh, ent in self._entries.items()
            if (now - ent.created_at) > self._config.ttl_seconds
        ]
        for eh in expired:
            self._entries.pop(eh, None)
            self._simhash_index[:] = [(sh, e) for sh, e in self._simhash_index if e != eh]
            self._evictions += 1
        return len(expired)

    def _evict_lru(self) -> None:
        if not self._entries:
            return
        oldest = next(iter(self._entries))
        self._entries.pop(oldest, None)
        self._simhash_index[:] = [(sh, e) for sh, e in self._simhash_index if e != oldest]
        self._evictions += 1
