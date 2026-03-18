"""Unified Context Importance (UCI) based context compression."""

from __future__ import annotations

import math
import re
import threading
from collections import Counter
from typing import Any


class UCICompressor:
    """Importance-based context retention using a weighted UCI score."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.w_shapley = float(cfg.get("w_shapley", 0.35))
        self.w_causal = float(cfg.get("w_causal", 0.25))
        self.w_tig = float(cfg.get("w_tig", 0.25))
        self.w_zipf = float(cfg.get("w_zipf", 0.15))
        self._lock = threading.Lock()
        self._stats = {
            "compressions": 0,
            "tokens_saved": 0,
            "total_original_tokens": 0,
            "total_compressed_tokens": 0,
        }

    def compute_uci(self, message: dict, context: list[dict]) -> float:
        """Compute UCI score for a message. Returns 0.0-1.0."""
        if not isinstance(message, dict):
            return 0.0
        total = max(1e-9, self.w_shapley + self.w_causal + self.w_tig + self.w_zipf)
        try:
            position = context.index(message)
        except ValueError:
            position = 0
        total_items = max(1, len(context))
        score = (
            self.w_shapley * self.shapley_value(message, context)
            + self.w_causal * self.causal_fan_out(message, context)
            + self.w_tig * self.tig_score(message, position, total_items)
            + self.w_zipf * self.zipf_weight(message)
        ) / total
        return max(0.0, min(1.0, float(score)))

    def shapley_value(self, message: dict, context: list[dict]) -> float:
        """Marginal contribution of message to context quality."""
        if not isinstance(message, dict) or not isinstance(context, list):
            return 0.0
        tokens = self._tokens(message.get("content"))
        if not tokens:
            return 0.0
        unique = set(tokens)
        base = min(1.0, len(unique) / 24.0)
        try:
            idx = context.index(message)
        except ValueError:
            idx = 0
        later = context[idx + 1 :]
        if not later:
            return round(base * 0.7, 6)
        overlap_scores: list[float] = []
        for row in later:
            if not isinstance(row, dict):
                continue
            row_tokens = set(self._tokens(row.get("content")))
            if not row_tokens:
                continue
            overlap = len(unique & row_tokens) / float(max(1, len(unique)))
            if overlap > 0:
                overlap_scores.append(overlap)
        if not overlap_scores:
            return round(base * 0.6, 6)
        referenced = sum(1 for item in overlap_scores if item >= 0.2) / float(len(overlap_scores))
        score = (0.45 * base) + (0.55 * referenced)
        return max(0.0, min(1.0, round(score, 6)))

    def causal_fan_out(self, message: dict, context: list[dict]) -> float:
        """How many later messages depend on this one."""
        if not isinstance(message, dict) or not isinstance(context, list):
            return 0.0
        tokens = set(self._tokens(message.get("content")))
        if not tokens:
            return 0.0
        try:
            idx = context.index(message)
        except ValueError:
            idx = 0
        later = [row for row in context[idx + 1 :] if isinstance(row, dict)]
        if not later:
            return 0.0
        dependent = 0
        for row in later:
            row_tokens = set(self._tokens(row.get("content")))
            if not row_tokens:
                continue
            if len(tokens & row_tokens) >= 1:
                dependent += 1
        return max(0.0, min(1.0, dependent / float(len(later))))

    def tig_score(self, message: dict, position: int, total: int) -> float:
        """Temporal Importance Gradient — recency decay."""
        _ = message
        total_count = max(1, int(total))
        pos = max(0, min(int(position), total_count - 1))
        # More recent messages are weighted higher.
        return max(0.0, min(1.0, (pos + 1) / float(total_count)))

    def zipf_weight(self, message: dict) -> float:
        """Token frequency Zipf weight — rare tokens = higher importance."""
        if not isinstance(message, dict):
            return 0.0
        tokens = self._tokens(message.get("content"))
        if not tokens:
            return 0.0
        freq = Counter(tokens)
        n = float(len(tokens))
        unique_ratio = len(freq) / n
        rare_ratio = sum(1 for _, count in freq.items() if count == 1) / float(max(1, len(freq)))
        # Zipf-inspired: more unique and singleton-heavy text carries high information density.
        score = 0.6 * rare_ratio + 0.4 * unique_ratio
        return max(0.0, min(1.0, score))

    def compress(self, messages: list[dict], budget_tokens: int) -> dict:
        """Compress messages using UCI scores. Keep highest-UCI messages."""
        if not isinstance(messages, list) or not messages:
            return {
                "messages": [],
                "original_count": 0,
                "compressed_count": 0,
                "tokens_saved": 0,
                "uci_scores": [],
            }
        budget = max(1, int(budget_tokens))
        original_tokens = self._estimate_tokens(messages)
        scores = [self.compute_uci(msg if isinstance(msg, dict) else {}, messages) for msg in messages]
        token_costs = [self._estimate_tokens([msg if isinstance(msg, dict) else {}]) for msg in messages]

        forced_idxs = {
            idx
            for idx, msg in enumerate(messages)
            if isinstance(msg, dict) and str(msg.get("role", "")).strip().lower() == "system"
        }
        ranked = sorted(
            range(len(messages)),
            key=lambda idx: (scores[idx], self.tig_score(messages[idx], idx, len(messages))),
            reverse=True,
        )

        selected: set[int] = set()
        selected_tokens = 0
        for idx in sorted(forced_idxs):
            selected.add(idx)
            selected_tokens += token_costs[idx]
        for idx in ranked:
            if idx in selected:
                continue
            if selected_tokens + token_costs[idx] > budget and selected:
                continue
            selected.add(idx)
            selected_tokens += token_costs[idx]
            if selected_tokens >= budget:
                break
        if not selected:
            selected.add(ranked[0] if ranked else 0)
            selected_tokens = token_costs[next(iter(selected))]

        kept_indices = sorted(selected)
        kept_messages = [messages[idx] for idx in kept_indices]
        compressed_tokens = self._estimate_tokens(kept_messages)
        saved = max(0, original_tokens - compressed_tokens)

        with self._lock:
            self._stats["compressions"] += 1
            self._stats["tokens_saved"] += int(saved)
            self._stats["total_original_tokens"] += int(original_tokens)
            self._stats["total_compressed_tokens"] += int(compressed_tokens)

        return {
            "messages": kept_messages,
            "original_count": len(messages),
            "compressed_count": len(kept_messages),
            "tokens_saved": int(saved),
            "uci_scores": [round(score, 6) for score in scores],
        }

    def get_stats(self) -> dict:
        with self._lock:
            compressions = int(self._stats.get("compressions", 0))
            tokens_saved = int(self._stats.get("tokens_saved", 0))
            total_original = int(self._stats.get("total_original_tokens", 0))
            total_compressed = int(self._stats.get("total_compressed_tokens", 0))
        avg_ratio = 1.0
        if total_original > 0:
            avg_ratio = max(0.0, min(1.0, total_compressed / float(total_original)))
        return {
            "compressions": compressions,
            "tokens_saved": tokens_saved,
            "avg_ratio": round(avg_ratio, 6),
        }

    @staticmethod
    def _tokens(value: Any) -> list[str]:
        if not isinstance(value, str):
            return []
        return [item for item in re.findall(r"[a-zA-Z0-9_]+", value.lower()) if item]

    @classmethod
    def _estimate_tokens(cls, messages: list[dict]) -> int:
        total = 0
        for row in messages:
            if not isinstance(row, dict):
                continue
            content = row.get("content", "")
            if not isinstance(content, str):
                content = str(content)
            words = cls._tokens(content)
            # Hybrid estimate to better match long unbroken strings and normal prose.
            total += max(1, int(math.ceil((len(content) / 4.0) + (len(words) * 0.25))))
        return total
