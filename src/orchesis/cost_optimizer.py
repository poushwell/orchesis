"""Token-cost optimization utilities for request message payloads."""

from __future__ import annotations

import copy
import re
from typing import Any


class CostOptimizer:
    """Automatically reduces token costs through compression strategies."""

    STRATEGIES = {
        "dedup_system_prompt": "Remove duplicate system prompt content",
        "trim_whitespace": "Aggressive whitespace normalization",
        "remove_redundant_context": "Remove repeated context blocks",
        "compress_tool_results": "Summarize large tool call results",
        "prune_old_assistant": "Remove old assistant turns beyond N",
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.enabled_strategies = cfg.get("strategies", list(self.STRATEGIES.keys()))
        if not isinstance(self.enabled_strategies, list):
            self.enabled_strategies = list(self.STRATEGIES.keys())
        self.enabled_strategies = [item for item in self.enabled_strategies if item in self.STRATEGIES]
        self.max_assistant_turns = int(cfg.get("max_assistant_turns", 10))
        self.tool_result_max_chars = int(cfg.get("tool_result_max_chars", 2000))
        self._savings: dict[str, int] = {}

    def optimize(self, messages: list[dict]) -> tuple[list[dict], dict]:
        """Apply all enabled strategies. Returns (optimized_messages, stats)."""
        current = copy.deepcopy(messages if isinstance(messages, list) else [])
        original_tokens = self.estimate_tokens(current)
        applied: list[str] = []
        for strategy in self.enabled_strategies:
            before = self.estimate_tokens(current)
            if strategy == "dedup_system_prompt":
                current = self.dedup_system_prompt(current)
            elif strategy == "trim_whitespace":
                current = self.trim_whitespace(current)
            elif strategy == "remove_redundant_context":
                current = self.remove_redundant_context(current)
            elif strategy == "compress_tool_results":
                current = self.compress_tool_results(current)
            elif strategy == "prune_old_assistant":
                current = self.prune_old_assistant_turns(current)
            after = self.estimate_tokens(current)
            saved = max(0, before - after)
            if saved > 0:
                self._savings[strategy] = self._savings.get(strategy, 0) + saved
                applied.append(strategy)
        optimized_tokens = self.estimate_tokens(current)
        stats = {
            "original_tokens": int(original_tokens),
            "optimized_tokens": int(optimized_tokens),
            "savings": int(max(0, original_tokens - optimized_tokens)),
            "strategies_applied": applied,
        }
        return current, stats

    def dedup_system_prompt(self, messages: list[dict]) -> list[dict]:
        """Remove duplicate content from system prompt."""
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip().lower()
            content = msg.get("content", "")
            text = content if isinstance(content, str) else ""
            if role == "system":
                key = text.strip()
                if key in seen:
                    continue
                seen.add(key)
            out.append(dict(msg))
        return out

    def trim_whitespace(self, messages: list[dict]) -> list[dict]:
        """Normalize whitespace in all messages."""
        out: list[dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            item = dict(msg)
            content = item.get("content")
            if isinstance(content, str):
                item["content"] = re.sub(r"\s+", " ", content).strip()
            out.append(item)
        return out

    def remove_redundant_context(self, messages: list[dict]) -> list[dict]:
        """Remove repeated context blocks."""
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip().lower()
            content = msg.get("content", "")
            text = content if isinstance(content, str) else ""
            key = (role, text.strip())
            if key in seen:
                continue
            seen.add(key)
            out.append(dict(msg))
        return out

    def compress_tool_results(self, messages: list[dict]) -> list[dict]:
        """Truncate oversized tool call results."""
        out: list[dict[str, Any]] = []
        cap = max(1, int(self.tool_result_max_chars))
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            item = dict(msg)
            role = str(item.get("role", "")).strip().lower()
            has_tool_marker = "tool_call_id" in item or role == "tool"
            content = item.get("content")
            if has_tool_marker and isinstance(content, str) and len(content) > cap:
                item["content"] = content[:cap] + f"... [truncated {len(content) - cap} chars]"
            out.append(item)
        return out

    def prune_old_assistant_turns(self, messages: list[dict]) -> list[dict]:
        """Keep only last N assistant turns."""
        cap = max(1, int(self.max_assistant_turns))
        assistant_indices = [
            idx for idx, msg in enumerate(messages) if isinstance(msg, dict) and str(msg.get("role", "")).lower() == "assistant"
        ]
        keep = set(assistant_indices[-cap:])
        out: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip().lower()
            if role == "assistant" and idx not in keep:
                continue
            out.append(dict(msg))
        return out

    def estimate_tokens(self, messages: list[dict]) -> int:
        """Fast token estimation without tiktoken."""
        total_chars = 0
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text", "")
                        if isinstance(text, str):
                            total_chars += len(text)
        # Rough heuristic: ~4 chars per token.
        return max(0, int(round(total_chars / 4.0)))

    def get_savings_report(self) -> dict:
        """Total savings per strategy."""
        return dict(self._savings)
