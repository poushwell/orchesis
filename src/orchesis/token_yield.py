"""Token Yield tracking utilities."""

from __future__ import annotations

import threading
from typing import Any


class TokenYieldTracker:
    """Tracks Token Yield = semantic value / total tokens per session."""

    def __init__(self, config: dict | None = None):
        _ = config
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _clamp_ratio(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def record(
        self,
        session_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        cache_hit: bool,
        unique_content_ratio: float,
    ) -> None:
        """Record one request's token yield data."""
        sid = str(session_id or "__default__")
        prompt = max(0, int(prompt_tokens))
        completion = max(0, int(completion_tokens))
        total = prompt + completion
        ratio = self._clamp_ratio(float(unique_content_ratio))
        semantic_tokens = int(round(total * ratio))
        cache_saved = total if bool(cache_hit) else 0
        with self._lock:
            bucket = self._sessions.setdefault(
                sid,
                {
                    "total_tokens": 0,
                    "semantic_tokens": 0,
                    "cache_savings": 0,
                    "iterations": 0,
                    "token_history": [],
                },
            )
            bucket["total_tokens"] = int(bucket["total_tokens"]) + total
            bucket["semantic_tokens"] = int(bucket["semantic_tokens"]) + semantic_tokens
            bucket["cache_savings"] = int(bucket["cache_savings"]) + cache_saved
            bucket["iterations"] = int(bucket["iterations"]) + 1
            history = bucket.get("token_history")
            if isinstance(history, list):
                history.append(total)
            else:
                bucket["token_history"] = [total]

    def get_yield(self, session_id: str) -> dict[str, Any]:
        """Returns Token Yield metrics for session."""
        sid = str(session_id or "__default__")
        with self._lock:
            raw = dict(self._sessions.get(sid, {}))
            history = list(raw.get("token_history", [])) if isinstance(raw.get("token_history"), list) else []
        total_tokens = int(raw.get("total_tokens", 0))
        semantic_tokens = int(raw.get("semantic_tokens", 0))
        cache_savings = int(raw.get("cache_savings", 0))
        iterations = int(raw.get("iterations", 0))
        token_yield = (semantic_tokens / float(total_tokens)) if total_tokens > 0 else 0.0
        token_yield = self._clamp_ratio(token_yield)
        waste_percent = self._clamp_ratio(1.0 - token_yield)
        return {
            "session_id": sid,
            "total_tokens": total_tokens,
            "semantic_tokens": semantic_tokens,
            "token_yield": round(token_yield, 6),
            "waste_percent": round(waste_percent, 6),
            "cache_savings": cache_savings,
            "iterations": iterations,
            "history": history,
            "context_collapse": self.context_collapse_detected(sid),
        }

    def get_global_stats(self) -> dict[str, Any]:
        """Aggregate across all sessions."""
        with self._lock:
            session_ids = list(self._sessions.keys())
        total_tokens = 0
        semantic_tokens = 0
        cache_savings = 0
        total_iterations = 0
        collapses = 0
        for sid in session_ids:
            item = self.get_yield(sid)
            total_tokens += int(item["total_tokens"])
            semantic_tokens += int(item["semantic_tokens"])
            cache_savings += int(item["cache_savings"])
            total_iterations += int(item["iterations"])
            if bool(item.get("context_collapse", False)):
                collapses += 1
        token_yield = (semantic_tokens / float(total_tokens)) if total_tokens > 0 else 0.0
        token_yield = self._clamp_ratio(token_yield)
        return {
            "sessions": len(session_ids),
            "total_tokens": int(total_tokens),
            "semantic_tokens": int(semantic_tokens),
            "token_yield": round(token_yield, 6),
            "waste_percent": round(self._clamp_ratio(1.0 - token_yield), 6),
            "cache_savings": int(cache_savings),
            "iterations": int(total_iterations),
            "context_collapses": int(collapses),
            "top_sessions": sorted(
                [self.get_yield(sid) for sid in session_ids],
                key=lambda item: int(item.get("total_tokens", 0)),
                reverse=True,
            )[:5],
        }

    def context_collapse_detected(self, session_id: str) -> bool:
        """True if token growth > 3x from iteration 1 to current."""
        sid = str(session_id or "__default__")
        with self._lock:
            bucket = self._sessions.get(sid, {})
            history = list(bucket.get("token_history", [])) if isinstance(bucket.get("token_history"), list) else []
        if len(history) < 2:
            return False
        first = max(1, int(history[0]))
        current = int(history[-1])
        return current > (3 * first)
