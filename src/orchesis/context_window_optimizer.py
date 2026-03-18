"""Context window optimization helpers."""

from __future__ import annotations

from typing import Any


class ContextWindowOptimizer:
    """Optimizes context window usage across models."""

    MODEL_WINDOWS = {
        "gpt-4o": 128000,
        "gpt-4o-mini": 128000,
        "gpt-4-turbo": 128000,
        "claude-3-5-sonnet": 200000,
        "claude-3-opus": 200000,
        "gemini-1.5-pro": 1000000,
    }

    _PREFERRED_COST_ORDER = [
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4o",
        "claude-3-5-sonnet",
        "claude-3-opus",
        "gemini-1.5-pro",
    ]

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.safety_margin = float(cfg.get("safety_margin", 0.1))
        self.safety_margin = max(0.0, min(0.5, self.safety_margin))

    @staticmethod
    def _as_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        if hasattr(item, "__dict__"):
            raw = getattr(item, "__dict__", {})
            if isinstance(raw, dict):
                return raw
        return {}

    def _window_for(self, model: str) -> int:
        key = str(model or "").strip()
        return int(self.MODEL_WINDOWS.get(key, 128000))

    def _safe_limit(self, model: str) -> int:
        window = self._window_for(model)
        return max(1, int(window * (1.0 - self.safety_margin)))

    @staticmethod
    def _estimate_message_tokens(message: dict[str, Any]) -> int:
        row = message if isinstance(message, dict) else {}
        text = row.get("content", row.get("text", row.get("prompt", row.get("message", ""))))
        if not isinstance(text, str):
            text = ""
        return max(1, int(len(text) / 4) + 4)

    def _estimate_tokens(self, messages: list[dict]) -> int:
        return sum(self._estimate_message_tokens(self._as_dict(msg)) for msg in messages)

    def get_available_tokens(self, model: str, used_tokens: int) -> int:
        """How many tokens are safely available."""
        safe = self._safe_limit(model)
        return max(0, int(safe - max(0, int(used_tokens))))

    def recommend_model(self, required_tokens: int) -> str:
        """Recommend cheapest model that fits the context."""
        required = max(0, int(required_tokens))
        for model in self._PREFERRED_COST_ORDER:
            if self._safe_limit(model) >= required:
                return model
        return "gemini-1.5-pro"

    def optimize_for_model(self, messages: list[dict], model: str) -> dict:
        rows = [self._as_dict(msg) for msg in messages]
        original_tokens = self._estimate_tokens(rows)
        safe_limit = self._safe_limit(model)
        if original_tokens <= safe_limit:
            return {
                "messages": rows,
                "original_tokens": original_tokens,
                "optimized_tokens": original_tokens,
                "model": str(model or ""),
                "fits": True,
            }

        system_msgs = [msg for msg in rows if str(msg.get("role", "")).lower() == "system"]
        others = [msg for msg in rows if str(msg.get("role", "")).lower() != "system"]
        optimized = list(system_msgs)
        current = self._estimate_tokens(optimized)

        for msg in reversed(others):
            msg_tokens = self._estimate_message_tokens(msg)
            if current + msg_tokens > safe_limit:
                continue
            optimized.append(msg)
            current += msg_tokens
            if current >= safe_limit:
                break

        if not optimized and rows:
            optimized = [rows[-1]]
            current = self._estimate_tokens(optimized)

        return {
            "messages": optimized,
            "original_tokens": original_tokens,
            "optimized_tokens": current,
            "model": str(model or ""),
            "fits": current <= safe_limit,
        }

    def split_for_context(self, messages: list[dict], model: str) -> list[list[dict]]:
        """Split long context into chunks that fit model window."""
        rows = [self._as_dict(msg) for msg in messages]
        if not rows:
            return []
        limit = self._safe_limit(model)
        chunks: list[list[dict]] = []
        current: list[dict] = []
        current_tokens = 0

        for msg in rows:
            msg_tokens = self._estimate_message_tokens(msg)
            if msg_tokens > limit:
                text = str(msg.get("content", ""))
                if not text:
                    text = str(msg)
                slice_chars = max(40, int((limit - 8) * 4))
                for start in range(0, len(text), slice_chars):
                    piece = dict(msg)
                    piece["content"] = text[start : start + slice_chars]
                    piece_tokens = self._estimate_message_tokens(piece)
                    if current and current_tokens + piece_tokens > limit:
                        chunks.append(current)
                        current = []
                        current_tokens = 0
                    current.append(piece)
                    current_tokens += piece_tokens
                continue
            if current and current_tokens + msg_tokens > limit:
                chunks.append(current)
                current = []
                current_tokens = 0
            current.append(msg)
            current_tokens += msg_tokens
        if current:
            chunks.append(current)
        return chunks
