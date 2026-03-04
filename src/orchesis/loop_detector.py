"""Loop detection reliability layer with exact/fuzzy matching."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class LoopEvent:
    tool_name: str
    repetitions: int
    total_cost_wasted: float
    action_taken: str
    timestamp: float


@dataclass
class LoopDecision:
    action: str
    reason: str
    count: int
    estimated_cost_saved: float
    loop_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "repetitions": self.count,
            "message": self.reason,
            "saved_usd": self.estimated_cost_saved,
            "loop_type": self.loop_type,
        }


class LoopDetector:
    """Detect exact and fuzzy infinite loops for agent requests."""

    def __init__(
        self,
        warn_threshold: int = 5,
        block_threshold: int = 10,
        window_seconds: float = 300.0,
        similarity_check: bool = True,
        config: dict[str, Any] | None = None,
    ):
        safe_cfg = config if isinstance(config, dict) else {}
        exact_cfg = safe_cfg.get("exact") if isinstance(safe_cfg.get("exact"), dict) else {}
        fuzzy_cfg = safe_cfg.get("fuzzy") if isinstance(safe_cfg.get("fuzzy"), dict) else {}
        on_detect_cfg = safe_cfg.get("on_detect") if isinstance(safe_cfg.get("on_detect"), dict) else {}

        self._lock = threading.Lock()
        self._enabled = bool(safe_cfg.get("enabled", True))

        # New config (with legacy fallback)
        self._exact_threshold = int(exact_cfg.get("threshold", warn_threshold))
        self._exact_window = float(exact_cfg.get("window_seconds", window_seconds))
        self._exact_action = str(exact_cfg.get("action", "warn")).lower()

        self._fuzzy_threshold = int(fuzzy_cfg.get("threshold", block_threshold))
        self._fuzzy_window = float(fuzzy_cfg.get("window_seconds", window_seconds))
        self._fuzzy_action = str(fuzzy_cfg.get("action", "block")).lower()

        self._notify = bool(on_detect_cfg.get("notify", True))
        self._track_max_cost_saved = bool(on_detect_cfg.get("max_cost_saved", True))
        self._similarity_check = bool(similarity_check)

        # New loop pattern storage
        self._exact_patterns: dict[str, list[float]] = defaultdict(list)
        self._fuzzy_patterns: dict[str, list[float]] = defaultdict(list)
        self._exact_detections = 0
        self._fuzzy_detections = 0

        # Legacy API compatibility storage
        self._warn_threshold = int(warn_threshold)
        self._block_threshold = int(block_threshold)
        self._window = float(window_seconds)
        self._recent_calls: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._events: list[LoopEvent] = []
        self._total_saved: float = 0.0

    def reset(self) -> None:
        with self._lock:
            self._exact_patterns.clear()
            self._fuzzy_patterns.clear()
            self._recent_calls.clear()
            self._events.clear()
            self._exact_detections = 0
            self._fuzzy_detections = 0
            self._total_saved = 0.0

    @staticmethod
    def _json_dumps(value: Any) -> str:
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            return ""

    def _make_exact_hash(self, model: str, messages: list[dict[str, Any]]) -> str:
        blob = f"{model}:{self._json_dumps(messages)}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _make_fuzzy_hash(self, model: str, tool_calls: list[Any], prompt_length: int) -> str:
        tool_names: list[str] = []
        for item in tool_calls:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str):
                    tool_names.append(name.strip().lower())
            else:
                name = getattr(item, "name", "")
                if isinstance(name, str) and name:
                    tool_names.append(name.strip().lower())
        rounded_len = int(round(float(prompt_length) / 100.0) * 100)
        blob = f"{model}:{','.join(sorted(tool_names))}:{rounded_len}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @staticmethod
    def _prune(times: list[float], now: float, window_seconds: float) -> list[float]:
        return [ts for ts in times if (now - ts) <= window_seconds]

    def _estimate_cost_saved(self, parsed_request: dict[str, Any], count: int) -> float:
        text = str(parsed_request.get("content_text", ""))
        approx_tokens = max(1, int(len(text) / 4))
        # Conservative estimate for prevented request.
        estimate = (approx_tokens / 1000.0) * 0.01 * max(1, count)
        return round(estimate, 6)

    def check_request(self, parsed_request: dict[str, Any]) -> LoopDecision:
        if not self._enabled:
            return LoopDecision("allow", "", 1, 0.0, "none")

        model = str(parsed_request.get("model", "")).strip()
        messages = parsed_request.get("messages", [])
        safe_messages = messages if isinstance(messages, list) else []
        tool_calls = parsed_request.get("tool_calls", [])
        safe_tool_calls = tool_calls if isinstance(tool_calls, list) else []
        content_text = str(parsed_request.get("content_text", ""))
        prompt_len = len(content_text)
        now = time.monotonic()

        exact_hash = self._make_exact_hash(model, safe_messages)
        fuzzy_hash = self._make_fuzzy_hash(model, safe_tool_calls, prompt_len)

        with self._lock:
            exact_active = self._prune(self._exact_patterns.get(exact_hash, []), now, self._exact_window)
            exact_active.append(now)
            self._exact_patterns[exact_hash] = exact_active
            exact_count = len(exact_active)

            fuzzy_active = self._prune(self._fuzzy_patterns.get(fuzzy_hash, []), now, self._fuzzy_window)
            fuzzy_active.append(now)
            self._fuzzy_patterns[fuzzy_hash] = fuzzy_active
            fuzzy_count = len(fuzzy_active)

            # Auto cleanup for inactive keys
            for table, window in (
                (self._exact_patterns, self._exact_window),
                (self._fuzzy_patterns, self._fuzzy_window),
            ):
                expired = [key for key, times in table.items() if not self._prune(times, now, window)]
                for key in expired:
                    table.pop(key, None)

            exact_decision: LoopDecision | None = None
            fuzzy_decision: LoopDecision | None = None

            if exact_count >= self._exact_threshold:
                self._exact_detections += 1
                saved = self._estimate_cost_saved(parsed_request, exact_count) if self._track_max_cost_saved else 0.0
                reason = f"Exact loop detected: {exact_count}/{self._exact_threshold}"
                exact_decision = LoopDecision(self._exact_action, reason, exact_count, saved, "exact")

            if fuzzy_count >= self._fuzzy_threshold:
                self._fuzzy_detections += 1
                saved = self._estimate_cost_saved(parsed_request, fuzzy_count) if self._track_max_cost_saved else 0.0
                reason = f"Fuzzy loop detected: {fuzzy_count}/{self._fuzzy_threshold}"
                fuzzy_decision = LoopDecision(self._fuzzy_action, reason, fuzzy_count, saved, "fuzzy")

            # Choose strongest action: block > downgrade_model > warn.
            rank = {"allow": 0, "warn": 1, "downgrade_model": 2, "block": 3}
            chosen: LoopDecision | None = None
            for candidate in (exact_decision, fuzzy_decision):
                if candidate is None:
                    continue
                if chosen is None or rank.get(candidate.action, 0) > rank.get(chosen.action, 0):
                    chosen = candidate
            if chosen is not None:
                self._total_saved += max(0.0, float(chosen.estimated_cost_saved))
                return chosen

        return LoopDecision("allow", "", 1, 0.0, "none")

    # Legacy API (kept for compatibility with existing tests/callers).
    def _hash_params(self, params: dict[str, Any]) -> str:
        try:
            normalized = json.dumps(params, sort_keys=True, default=str)
            return hashlib.md5(normalized.encode("utf-8")).hexdigest()  # noqa: S324
        except Exception:
            return "unhashable"

    def check(self, tool_name: str, params: dict[str, Any], cost_per_call: float = 0.001) -> dict[str, Any]:
        now = time.time()
        params_hash = self._hash_params(params if isinstance(params, dict) else {})
        with self._lock:
            active = [(ts, h) for ts, h in self._recent_calls[tool_name] if (now - ts) < self._window]
            active.append((now, params_hash))
            self._recent_calls[tool_name] = active

            repetitions = (
                sum(1 for _ts, item_hash in active if item_hash == params_hash)
                if self._similarity_check
                else len(active)
            )

            if repetitions >= self._block_threshold:
                saved = float(cost_per_call)
                self._total_saved += saved
                self._events.append(
                    LoopEvent(
                        tool_name=tool_name,
                        repetitions=repetitions,
                        total_cost_wasted=float(repetitions) * float(cost_per_call),
                        action_taken="blocked",
                        timestamp=now,
                    )
                )
                return {
                    "action": "block",
                    "repetitions": repetitions,
                    "message": (
                        f"Loop detected: {tool_name} called {repetitions} times in "
                        f"{int(self._window)}s with similar params. Blocked to prevent waste."
                    ),
                    "saved_usd": saved,
                }

            if repetitions >= self._warn_threshold:
                self._events.append(
                    LoopEvent(
                        tool_name=tool_name,
                        repetitions=repetitions,
                        total_cost_wasted=float(repetitions) * float(cost_per_call),
                        action_taken="warned",
                        timestamp=now,
                    )
                )
                return {
                    "action": "warn",
                    "repetitions": repetitions,
                    "message": (
                        f"Warning: {tool_name} called {repetitions} times in "
                        f"{int(self._window)}s. You may be in a loop."
                    ),
                    "saved_usd": 0.0,
                }

        return {"action": "allow", "repetitions": 1, "message": "", "saved_usd": 0.0}

    @property
    def total_saved(self) -> float:
        with self._lock:
            return float(self._total_saved)

    @property
    def events(self) -> list[LoopEvent]:
        with self._lock:
            return list(self._events)

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            warned = sum(1 for item in self._events if item.action_taken == "warned")
            blocked = sum(1 for item in self._events if item.action_taken == "blocked")
            active_patterns = len(self._exact_patterns) + len(self._fuzzy_patterns)
            return {
                "total_cost_saved_usd": round(self._total_saved, 4),
                "total_saved_usd": round(self._total_saved, 4),  # legacy alias
                "total_loops_detected": len(self._events),
                "loops_warned": warned,
                "loops_blocked": blocked,
                "exact_detections": self._exact_detections,
                "fuzzy_detections": self._fuzzy_detections,
                "active_patterns_count": active_patterns,
                "active_patterns": active_patterns,  # legacy alias
                "notify": self._notify,
            }

