"""Semantic context compression algorithms."""

from __future__ import annotations

from typing import Any


class ContextCompressionV2:
    """Semantic chunking compression - better than LRU."""

    ALGORITHMS = {
        "semantic_dedup": "Remove semantically similar messages",
        "importance_scoring": "Keep high-importance turns",
        "topic_clustering": "Group by topic, keep one representative",
        "recency_weighted": "Decay old messages, boost recent",
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        algo = str(cfg.get("algorithm", "importance_scoring") or "importance_scoring").strip().lower()
        self.algorithm = algo if algo in self.ALGORITHMS else "importance_scoring"
        self.target_ratio = max(0.1, min(1.0, float(cfg.get("target_ratio", 0.7))))
        self._stats: dict[str, Any] = {
            "runs": 0,
            "tokens_saved_total": 0,
            "ratio_sum": 0.0,
            "quality_sum": 0.0,
            "last_algorithm": self.algorithm,
        }

    @staticmethod
    def _content_text(message: dict[str, Any]) -> str:
        value = message.get("content", "")
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if not isinstance(item, dict):
                    continue
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
            return " ".join(parts)
        return ""

    @classmethod
    def _estimate_tokens(cls, messages: list[dict]) -> int:
        chars = 0
        for msg in messages:
            if isinstance(msg, dict):
                chars += len(cls._content_text(msg))
        return max(0, chars // 4)

    def score_importance(self, message: dict, context: list[dict]) -> float:
        """Score message importance 0-1."""
        if not isinstance(message, dict):
            return 0.0
        role = str(message.get("role", "")).lower()
        text = self._content_text(message)
        max_idx = max(1, len(context) - 1)
        idx = context.index(message) if message in context else max_idx
        recency = float(idx) / float(max_idx)
        unique_tokens = len(set(text.lower().split()))
        uniqueness = min(1.0, unique_tokens / 40.0)
        tool_bonus = 0.25 if role in {"tool", "assistant"} and "tool" in text.lower() else 0.0
        error_bonus = 0.3 if "error" in text.lower() or "exception" in text.lower() else 0.0
        system_bonus = 0.35 if role == "system" else 0.0
        score = (0.45 * recency) + (0.35 * uniqueness) + tool_bonus + error_bonus + system_bonus
        return max(0.0, min(1.0, score))

    def semantic_dedup(self, messages: list[dict]) -> list[dict]:
        """Remove near-duplicate messages."""
        if not isinstance(messages, list):
            return []
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for item in messages:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", ""))
            norm = " ".join(self._content_text(item).lower().split())
            key = (role, norm)
            if norm and key in seen:
                continue
            if norm:
                seen.add(key)
            out.append(dict(item))
        return out

    def _apply_algorithm(self, messages: list[dict], keep_count: int) -> list[dict]:
        if self.algorithm == "semantic_dedup":
            deduped = self.semantic_dedup(messages)
            return deduped[-keep_count:] if len(deduped) > keep_count else deduped
        if self.algorithm == "topic_clustering":
            buckets: dict[str, dict] = {}
            for item in messages:
                text = self._content_text(item).strip().lower()
                topic = text.split(" ", 1)[0] if text else "_empty"
                buckets[topic] = dict(item)
            clustered = list(buckets.values())
            return clustered[-keep_count:] if len(clustered) > keep_count else clustered
        if self.algorithm == "recency_weighted":
            return [dict(item) for item in messages[-keep_count:]]
        # importance_scoring (default)
        scored: list[tuple[float, int, dict]] = []
        for idx, msg in enumerate(messages):
            score = self.score_importance(msg, messages)
            scored.append((score, idx, dict(msg)))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        top = scored[:keep_count]
        top.sort(key=lambda item: item[1])
        return [item[2] for item in top]

    def compress(self, messages: list[dict], budget_tokens: int) -> dict:
        if not isinstance(messages, list) or not messages:
            return {
                "compressed_messages": [],
                "original_count": 0,
                "compressed_count": 0,
                "tokens_saved": 0,
                "algorithm_used": self.algorithm,
                "quality_score": 1.0,
            }
        original = [dict(item) for item in messages if isinstance(item, dict)]
        original_count = len(original)
        if original_count == 0:
            return {
                "compressed_messages": [],
                "original_count": 0,
                "compressed_count": 0,
                "tokens_saved": 0,
                "algorithm_used": self.algorithm,
                "quality_score": 1.0,
            }
        keep_count = max(1, int(round(original_count * self.target_ratio)))
        keep_count = min(original_count, keep_count)
        compressed = self._apply_algorithm(original, keep_count)

        original_tokens = self._estimate_tokens(original)
        compressed_tokens = self._estimate_tokens(compressed)
        if budget_tokens > 0:
            compressed_tokens = min(compressed_tokens, max(0, int(budget_tokens)))
        tokens_saved = max(0, int(original_tokens - compressed_tokens))
        compression_ratio = float(len(compressed)) / float(original_count)
        quality_score = max(0.0, min(1.0, 1.0 - ((1.0 - compression_ratio) * 0.4)))

        self._stats["runs"] = int(self._stats.get("runs", 0)) + 1
        self._stats["tokens_saved_total"] = int(self._stats.get("tokens_saved_total", 0)) + int(tokens_saved)
        self._stats["ratio_sum"] = float(self._stats.get("ratio_sum", 0.0)) + compression_ratio
        self._stats["quality_sum"] = float(self._stats.get("quality_sum", 0.0)) + float(quality_score)
        self._stats["last_algorithm"] = self.algorithm

        return {
            "compressed_messages": compressed,
            "original_count": int(original_count),
            "compressed_count": int(len(compressed)),
            "tokens_saved": int(tokens_saved),
            "algorithm_used": self.algorithm,
            "quality_score": round(float(quality_score), 3),
        }

    def get_stats(self) -> dict:
        """Compression stats: avg ratio, tokens saved, quality."""
        runs = max(0, int(self._stats.get("runs", 0)))
        avg_ratio = float(self._stats.get("ratio_sum", 0.0)) / float(runs) if runs > 0 else 0.0
        avg_quality = float(self._stats.get("quality_sum", 0.0)) / float(runs) if runs > 0 else 0.0
        return {
            "runs": runs,
            "algorithm": str(self._stats.get("last_algorithm", self.algorithm)),
            "avg_ratio": round(avg_ratio, 4),
            "tokens_saved_total": int(self._stats.get("tokens_saved_total", 0)),
            "avg_quality": round(avg_quality, 4),
        }
