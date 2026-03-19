"""Relevance Theory (Sperber & Wilson 1986).

Communication succeeds when cognitive effects justify processing effort.
Relevance = cognitive_effects / processing_effort

Applied to context management:
- High relevance messages: keep (high effects, low effort)
- Low relevance messages: compress/remove (low effects, high effort)
"""

from __future__ import annotations

import threading
from typing import Any


class RelevanceScorer:
    """Relevance Theory scoring for context messages."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.effort_weight = float(cfg.get("effort_weight", 1.0))
        self.effect_weight = float(cfg.get("effect_weight", 1.0))
        self._scores: list[float] = []
        self._lock = threading.Lock()

    def compute_cognitive_effects(self, message: dict, context: list[dict]) -> float:
        """Estimate cognitive effects of message given context."""
        content = str(message.get("content", ""))
        if not content:
            return 0.0

        context_words: set[str] = set()
        for row in context:
            context_words.update(str(row.get("content", "")).lower().split())
        message_words = set(content.lower().split())
        total_words = max(1, len(content.split()))

        new_words = message_words - context_words
        novelty = len(new_words) / max(1, len(message_words))
        lexical_diversity = len(message_words) / total_words
        length_factor = min(1.0, len(content) / 500.0) * min(1.0, lexical_diversity)
        return round(min(1.0, novelty * 0.7 + length_factor * 0.3), 4)

    def compute_processing_effort(self, message: dict) -> float:
        """Estimate processing effort for message."""
        content = str(message.get("content", ""))
        if not content:
            return 0.0

        length_effort = min(1.0, len(content) / 2000.0)
        words = content.split()
        avg_word_len = sum(len(word) for word in words) / max(1, len(words))
        complexity = min(1.0, avg_word_len / 10.0)
        return round(min(1.0, length_effort * 0.6 + complexity * 0.4), 4)

    def score(self, message: dict, context: list[dict]) -> dict[str, Any]:
        """Compute relevance score for message."""
        effects = self.compute_cognitive_effects(message, context)
        effort = self.compute_processing_effort(message)

        relevance = (self.effect_weight * effects) / max(0.01, self.effort_weight * effort)
        relevance = min(1.0, relevance)

        result = {
            "relevance": round(relevance, 4),
            "cognitive_effects": effects,
            "processing_effort": effort,
            "keep": relevance > 0.3,
        }

        with self._lock:
            self._scores.append(float(relevance))
            if len(self._scores) > 10_000:
                self._scores = self._scores[-10_000:]
        return result

    def rank_messages(self, messages: list[dict]) -> list[dict[str, Any]]:
        """Rank messages by relevance score."""
        scored = [{"message": message, **self.score(message, messages[:index])} for index, message in enumerate(messages)]
        return sorted(scored, key=lambda row: -float(row["relevance"]))

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            if not self._scores:
                return {"scored": 0}
            return {
                "scored": len(self._scores),
                "avg_relevance": round(sum(self._scores) / len(self._scores), 4),
                "high_relevance_rate": round(sum(1 for score in self._scores if score > 0.3) / len(self._scores), 4),
            }
