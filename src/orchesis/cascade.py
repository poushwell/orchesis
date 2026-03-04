"""Adaptive model cascade routing with response cache."""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import threading
import time
from enum import IntEnum
from typing import Any

from orchesis.request_parser import ParsedRequest, ParsedResponse


class CascadeLevel(IntEnum):
    TRIVIAL = 0
    SIMPLE = 1
    MEDIUM = 2
    COMPLEX = 3


_LEVEL_NAME_TO_ENUM = {
    "trivial": CascadeLevel.TRIVIAL,
    "simple": CascadeLevel.SIMPLE,
    "medium": CascadeLevel.MEDIUM,
    "complex": CascadeLevel.COMPLEX,
}
_LEVEL_ENUM_TO_NAME = {value: key for key, value in _LEVEL_NAME_TO_ENUM.items()}


@dataclass
class CascadeDecision:
    model: str
    max_tokens: int
    cascade_level: CascadeLevel
    from_cache: bool = False
    cache_key: str = ""


class ResponseCache:
    """Simple in-memory LRU cache with TTL."""

    def __init__(self, ttl_seconds: int = 300, max_entries: int = 1000) -> None:
        self._ttl_seconds = max(1, int(ttl_seconds))
        self._max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._items: OrderedDict[str, tuple[float, bytes]] = OrderedDict()

    def get(self, key: str) -> bytes | None:
        now = time.time()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            ts, payload = item
            if (now - ts) > self._ttl_seconds:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return payload

    def set(self, key: str, value: bytes) -> None:
        with self._lock:
            self._items[key] = (time.time(), value)
            self._items.move_to_end(key)
            while len(self._items) > self._max_entries:
                self._items.popitem(last=False)

    def size(self) -> int:
        with self._lock:
            return len(self._items)


class CascadeClassifier:
    """Classify request complexity using stdlib heuristics."""

    _KEYWORDS = {
        "code": CascadeLevel.MEDIUM,
        "python": CascadeLevel.MEDIUM,
        "javascript": CascadeLevel.MEDIUM,
        "typescript": CascadeLevel.MEDIUM,
        "math": CascadeLevel.MEDIUM,
        "equation": CascadeLevel.MEDIUM,
        "analyze": CascadeLevel.MEDIUM,
        "compare": CascadeLevel.MEDIUM,
        "research": CascadeLevel.MEDIUM,
        "debug": CascadeLevel.MEDIUM,
        "refactor": CascadeLevel.COMPLEX,
        "multi-step": CascadeLevel.COMPLEX,
    }

    def __init__(self) -> None:
        self._task_history: dict[str, str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _approx_tokens(text: str) -> int:
        if not isinstance(text, str) or not text:
            return 0
        return max(0, int(len(text) / 4))

    def classify(self, parsed_request: ParsedRequest, context: dict[str, Any] | None = None) -> CascadeLevel:
        safe_context = context if isinstance(context, dict) else {}
        text = parsed_request.content_text if isinstance(parsed_request.content_text, str) else ""
        token_estimate = self._approx_tokens(text)
        tool_calls_count = len(parsed_request.tool_calls)
        tool_definitions_count = len(parsed_request.tool_definitions)

        if token_estimate == 0 and tool_calls_count == 0:
            return CascadeLevel.TRIVIAL

        level = CascadeLevel.SIMPLE

        if token_estimate > 2000:
            level = max(level, CascadeLevel.COMPLEX)
        elif token_estimate >= 500:
            level = max(level, CascadeLevel.MEDIUM)

        if tool_calls_count >= 3:
            level = max(level, CascadeLevel.COMPLEX)
        elif tool_calls_count >= 1:
            level = max(level, CascadeLevel.MEDIUM)

        if tool_definitions_count >= 20:
            level = max(level, CascadeLevel.MEDIUM)

        lowered = text.lower()
        for keyword, target_level in self._KEYWORDS.items():
            if keyword in lowered:
                level = max(level, target_level)

        task_id = safe_context.get("task_id")
        if isinstance(task_id, str) and task_id.strip():
            content_hash = hashlib.sha256(lowered.encode("utf-8")).hexdigest()
            with self._lock:
                previous_hash = self._task_history.get(task_id)
                self._task_history[task_id] = content_hash
            if isinstance(previous_hash, str) and previous_hash and previous_hash != content_hash:
                level = min(CascadeLevel.COMPLEX, CascadeLevel(level + 1))

        if bool(safe_context.get("previous_failed_attempts", False)):
            level = min(CascadeLevel.COMPLEX, CascadeLevel(level + 1))

        return level


class CascadeRouter:
    """Route requests to optimal model based on cascade level."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        safe_cfg = config if isinstance(config, dict) else {}
        self._enabled = bool(safe_cfg.get("enabled", False))
        self._levels = safe_cfg.get("levels") if isinstance(safe_cfg.get("levels"), dict) else {}
        auto = safe_cfg.get("auto_escalate")
        self._auto_escalate = auto if isinstance(auto, dict) else {}
        cache_cfg = safe_cfg.get("cache")
        self._cache_cfg = cache_cfg if isinstance(cache_cfg, dict) else {}

        self._classifier = CascadeClassifier()
        self._cache = ResponseCache(
            ttl_seconds=int(self._cache_cfg.get("ttl_seconds", 300)),
            max_entries=int(self._cache_cfg.get("max_entries", 1000)),
        )
        self._cache_enabled = bool(self._cache_cfg.get("enabled", True))
        self._requests_by_level: dict[str, int] = defaultdict(int)
        self._cache_hits_by_level: dict[str, int] = defaultdict(int)
        self._cache_lookups = 0
        self._cache_hits = 0
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _level_name(self, level: CascadeLevel) -> str:
        return _LEVEL_ENUM_TO_NAME.get(level, "simple")

    def _level_cfg(self, level: CascadeLevel) -> dict[str, Any]:
        return self._levels.get(self._level_name(level), {}) if isinstance(self._levels, dict) else {}

    def make_cache_key(self, parsed_request: ParsedRequest, model: str) -> str:
        msg = {
            "model": model,
            "messages": parsed_request.messages,
            "tool_definitions": parsed_request.tool_definitions,
        }
        raw = json.dumps(msg, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_cache(self, key: str, level: CascadeLevel) -> bytes | None:
        if not self._enabled or not self._cache_enabled:
            return None
        with self._lock:
            self._cache_lookups += 1
        payload = self._cache.get(key)
        if payload is not None:
            with self._lock:
                self._cache_hits += 1
                self._cache_hits_by_level[self._level_name(level)] += 1
        return payload

    def route(self, parsed_request: ParsedRequest, context: dict[str, Any] | None = None) -> CascadeDecision:
        if not self._enabled:
            model = parsed_request.model or "gpt-4o"
            max_tokens = int(parsed_request.raw_body.get("max_tokens", 0) or 0)
            return CascadeDecision(model=model, max_tokens=max_tokens, cascade_level=CascadeLevel.SIMPLE)

        level = self._classifier.classify(parsed_request, context=context)
        level_cfg = self._level_cfg(level)

        model = str(level_cfg.get("model", parsed_request.model or "gpt-4o"))
        max_tokens = int(level_cfg.get("max_tokens", parsed_request.raw_body.get("max_tokens", 0) or 0))
        if model == "" and parsed_request.model:
            model = parsed_request.model

        with self._lock:
            self._requests_by_level[self._level_name(level)] += 1

        return CascadeDecision(
            model=model,
            max_tokens=max_tokens,
            cascade_level=level,
            from_cache=False,
            cache_key=self.make_cache_key(parsed_request, model),
        )

    def classify(self, parsed_request: ParsedRequest, context: dict[str, Any] | None = None) -> CascadeLevel:
        return self._classifier.classify(parsed_request, context=context)

    def level_name(self, level: CascadeLevel) -> str:
        return self._level_name(level)

    def should_escalate(self, status_code: int, parsed_response: ParsedResponse | None = None) -> bool:
        if not self._enabled:
            return False
        if not bool(self._auto_escalate.get("enabled", False)):
            return False
        if bool(self._auto_escalate.get("on_error", True)) and status_code >= 400:
            return True
        if bool(self._auto_escalate.get("on_low_confidence", True)) and isinstance(parsed_response, ParsedResponse):
            stop_reason = (parsed_response.stop_reason or "").lower()
            if stop_reason in {"length", "max_tokens", "insufficient_confidence"}:
                return True
        return False

    def escalate(self, decision: CascadeDecision) -> CascadeDecision:
        next_level = min(CascadeLevel.COMPLEX, CascadeLevel(decision.cascade_level + 1))
        next_cfg = self._level_cfg(next_level)
        next_model = str(next_cfg.get("model", decision.model))
        next_max_tokens = int(next_cfg.get("max_tokens", decision.max_tokens))
        return CascadeDecision(
            model=next_model,
            max_tokens=next_max_tokens,
            cascade_level=next_level,
            from_cache=False,
            cache_key=decision.cache_key,
        )

    def cache_response(self, decision: CascadeDecision, response_body: bytes) -> None:
        if not self._enabled or not self._cache_enabled:
            return
        if decision.cascade_level not in {CascadeLevel.TRIVIAL, CascadeLevel.SIMPLE}:
            return
        if decision.cache_key:
            self._cache.set(decision.cache_key, response_body)

    def record_result(self, decision: CascadeDecision, parsed_response: ParsedResponse) -> None:
        _ = (decision, parsed_response)
        # Reserved for future adaptive tuning hooks.

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            lookups = self._cache_lookups
            hits = self._cache_hits
            hit_rate = (hits / lookups * 100.0) if lookups > 0 else 0.0
            return {
                "requests_by_level": dict(self._requests_by_level),
                "hits_by_level": dict(self._cache_hits_by_level),
                "cache_hit_rate_percent": round(hit_rate, 2),
                "cache_entries_count": self._cache.size(),
            }
