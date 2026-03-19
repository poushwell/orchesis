"""Semantic cache warming using historical request patterns."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import threading
from typing import Any


class CacheWarmer:
    """Pre-warms semantic cache with common query patterns."""

    def __init__(self, cache, config: dict | None = None):
        cfg = config or {}
        self.cache = cache
        self.min_frequency = int(cfg.get("min_frequency", 3))
        self.max_entries = int(cfg.get("max_entries", 100))
        self._lock = threading.Lock()
        self._last_candidates: list[dict[str, Any]] = []
        self._last_report: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "warmed": 0,
            "skipped": 0,
            "tokens_pre_cached": 0,
            "estimated_savings_per_run": 0.0,
            "candidate_count": 0,
            "min_frequency": self.min_frequency,
            "max_entries": self.max_entries,
            "schedule_interval_hours": None,
        }
        self._schedule_interval_hours: int | None = None

    def analyze_history(self, decisions_log: list) -> list[dict]:
        """Find frequently repeated queries."""
        grouped: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "frequency": 0,
                "last_seen": "",
                "token_sum": 0,
                "estimated_savings": 0.0,
                "model": "",
            }
        )
        for item in decisions_log:
            query = self._extract_query(item)
            if not query:
                continue
            ts = self._extract_timestamp(item)
            tokens = self._extract_tokens(item)
            cost = self._extract_cost(item)
            model = self._extract_model(item)
            bucket = grouped[query]
            bucket["frequency"] += 1
            if ts and (not bucket["last_seen"] or ts > bucket["last_seen"]):
                bucket["last_seen"] = ts
            bucket["token_sum"] += max(0, int(tokens))
            bucket["estimated_savings"] += max(0.0, float(cost))
            if model and not bucket["model"]:
                bucket["model"] = model

        out: list[dict[str, Any]] = []
        for query, data in grouped.items():
            freq = int(data["frequency"])
            if freq < max(1, int(self.min_frequency)):
                continue
            avg_tokens = int(round(float(data["token_sum"]) / float(freq))) if freq else 0
            out.append(
                {
                    "query": query,
                    "frequency": freq,
                    "last_seen": data["last_seen"] or "",
                    "avg_tokens": avg_tokens,
                    "estimated_savings": round(float(data["estimated_savings"]), 6),
                    "model": str(data["model"] or ""),
                }
            )
        out.sort(
            key=lambda row: (
                -int(row.get("frequency", 0)),
                -int(row.get("avg_tokens", 0)),
                str(row.get("query", "")),
            )
        )
        out = out[: max(1, int(self.max_entries))]
        with self._lock:
            self._last_candidates = list(out)
        return out

    def warm(self, candidates: list[dict]) -> dict:
        """Pre-populate cache with candidates."""
        warmed = 0
        skipped = 0
        tokens_pre_cached = 0
        estimated_savings = 0.0
        for candidate in candidates[: max(1, int(self.max_entries))]:
            if not isinstance(candidate, dict):
                skipped += 1
                continue
            query = str(candidate.get("query", "")).strip()
            if not query:
                skipped += 1
                continue
            model = str(candidate.get("model", "") or "gpt-4o-mini")
            avg_tokens = max(0, int(candidate.get("avg_tokens", 0) or 0))
            response_text = f"prewarmed:{query[:200]}"
            ok = False
            try:
                ok = bool(
                    self.cache.store(
                        messages=[{"role": "user", "content": query}],
                        model=model,
                        tools=[],
                        response_body=response_text.encode("utf-8"),
                        tokens=avg_tokens,
                        cost_usd=float(candidate.get("estimated_savings", 0.0) or 0.0),
                    )
                )
            except Exception:
                ok = False
            if ok:
                warmed += 1
                tokens_pre_cached += avg_tokens
                estimated_savings += max(0.0, float(candidate.get("estimated_savings", 0.0) or 0.0))
            else:
                skipped += 1

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "warmed": int(warmed),
            "skipped": int(skipped),
            "tokens_pre_cached": int(tokens_pre_cached),
            "estimated_savings_per_run": round(float(estimated_savings), 6),
            "candidate_count": int(len(candidates)),
            "min_frequency": int(self.min_frequency),
            "max_entries": int(self.max_entries),
            "schedule_interval_hours": self._schedule_interval_hours,
        }
        with self._lock:
            self._last_report = report
        return report

    def get_warming_report(self) -> dict:
        """Report on cache warming effectiveness."""
        with self._lock:
            return dict(self._last_report)

    def schedule_warming(self, interval_hours: int = 24) -> None:
        """Schedule periodic cache warming."""
        value = max(1, int(interval_hours))
        with self._lock:
            self._schedule_interval_hours = value
            self._last_report["schedule_interval_hours"] = value

    @staticmethod
    def _as_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        out: dict[str, Any] = {}
        for key in (
            "timestamp",
            "cost",
            "decision",
            "state_snapshot",
            "context",
            "query",
            "prompt",
            "messages",
            "model",
        ):
            if hasattr(item, key):
                out[key] = getattr(item, key)
        return out

    def _extract_query(self, item: Any) -> str:
        row = self._as_dict(item)
        for key in ("query", "prompt", "input", "text"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        state = row.get("state_snapshot")
        if isinstance(state, dict):
            for key in ("query", "prompt", "input", "content_text"):
                value = state.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            messages = state.get("messages")
            parsed = self._query_from_messages(messages)
            if parsed:
                return parsed

        context = row.get("context")
        if isinstance(context, dict):
            for key in ("query", "prompt", "input", "content_text"):
                value = context.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            messages = context.get("messages")
            parsed = self._query_from_messages(messages)
            if parsed:
                return parsed

        messages = row.get("messages")
        parsed = self._query_from_messages(messages)
        return parsed or ""

    @staticmethod
    def _query_from_messages(messages: Any) -> str:
        if not isinstance(messages, list):
            return ""
        for msg in reversed(messages):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip().lower()
            if role and role != "user":
                continue
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
        return ""

    def _extract_timestamp(self, item: Any) -> str:
        row = self._as_dict(item)
        ts = row.get("timestamp")
        if isinstance(ts, str) and ts.strip():
            return ts.strip()
        state = row.get("state_snapshot")
        if isinstance(state, dict):
            nested = state.get("timestamp")
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
        return ""

    def _extract_tokens(self, item: Any) -> int:
        row = self._as_dict(item)
        state = row.get("state_snapshot")
        if isinstance(state, dict):
            prompt_tokens = int(state.get("prompt_tokens", 0) or 0)
            completion_tokens = int(state.get("completion_tokens", 0) or 0)
            total = int(state.get("total_tokens", 0) or 0)
            if total > 0:
                return total
            if prompt_tokens > 0 or completion_tokens > 0:
                return prompt_tokens + completion_tokens
        return int(row.get("tokens", 0) or 0)

    def _extract_cost(self, item: Any) -> float:
        row = self._as_dict(item)
        value = row.get("cost", 0.0)
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _extract_model(self, item: Any) -> str:
        row = self._as_dict(item)
        model = row.get("model")
        if isinstance(model, str) and model.strip():
            return model.strip()
        state = row.get("state_snapshot")
        if isinstance(state, dict):
            nested = state.get("model")
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
        return ""
