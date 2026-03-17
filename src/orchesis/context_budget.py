"""Progressive context degradation when nearing model context limits."""

from __future__ import annotations

from typing import Any


class ContextBudget:
    """Progressive context degradation: L0 -> L1 -> L2."""

    LEVELS = {
        "L0": {"threshold": 0.80, "strategy": "aggressive_compress"},
        "L1": {"threshold": 0.90, "strategy": "trim_old_turns"},
        "L2": {"threshold": 1.00, "strategy": "system_prompt_only"},
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.model_context_windows = (
            dict(cfg.get("model_context_windows"))
            if isinstance(cfg.get("model_context_windows"), dict)
            else {}
        )
        self._thresholds = {
            "L0": float(cfg.get("l0_threshold", self.LEVELS["L0"]["threshold"])),
            "L1": float(cfg.get("l1_threshold", self.LEVELS["L1"]["threshold"])),
            "L2": float(cfg.get("l2_threshold", self.LEVELS["L2"]["threshold"])),
        }
        self._events = {"normal": 0, "L0": 0, "L1": 0, "L2": 0}

    @staticmethod
    def estimate_tokens(messages: list[Any]) -> int:
        """Heuristic token estimate from message content."""
        if not isinstance(messages, list):
            return 0
        total_chars = 0
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text")
                        if isinstance(text, str):
                            total_chars += len(text)
        # Roughly ~4 chars/token for English-like text.
        return max(0, total_chars // 4)

    def check_level(self, used_tokens: int, max_tokens: int) -> str:
        """Returns 'normal', 'L0', 'L1', or 'L2'."""
        if max_tokens <= 0:
            self._events["normal"] += 1
            return "normal"
        ratio = max(0.0, float(used_tokens) / float(max_tokens))
        if ratio >= self._thresholds["L2"]:
            level = "L2"
        elif ratio >= self._thresholds["L1"]:
            level = "L1"
        elif ratio >= self._thresholds["L0"]:
            level = "L0"
        else:
            level = "normal"
        self._events[level] = self._events.get(level, 0) + 1
        return level

    def apply(self, messages: list, level: str, max_tokens: int) -> list:
        """Apply degradation strategy to messages."""
        _ = max_tokens
        if not isinstance(messages, list):
            return []
        if level == "normal":
            return list(messages)

        copied = [dict(item) if isinstance(item, dict) else item for item in messages]
        if level == "L2":
            system_only = [
                msg
                for msg in copied
                if isinstance(msg, dict) and str(msg.get("role", "")).strip().lower() == "system"
            ]
            return system_only[:1] if system_only else []

        if level == "L1":
            system_msgs = [
                msg
                for msg in copied
                if isinstance(msg, dict) and str(msg.get("role", "")).strip().lower() == "system"
            ]
            non_system = [
                msg
                for msg in copied
                if isinstance(msg, dict) and str(msg.get("role", "")).strip().lower() != "system"
            ]
            keep_recent = non_system[-4:]
            return system_msgs[:1] + keep_recent

        # L0: aggressively compress long message content while preserving structure.
        out: list[Any] = []
        for msg in copied:
            if not isinstance(msg, dict):
                continue
            item = dict(msg)
            content = item.get("content")
            if isinstance(content, str) and len(content) > 240:
                item["content"] = f"{content[:220]} ...[compressed]"
            out.append(item)
        return out

    def get_stats(self) -> dict:
        """Returns degradation events count per level."""
        return {
            "events": dict(self._events),
            "thresholds": dict(self._thresholds),
            "enabled": self.enabled,
        }

