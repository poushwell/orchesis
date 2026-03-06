"""Context Engine: intelligent context window management for AI agent proxy."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ContextStrategy(Enum):
    """Available context optimization strategies."""

    DEDUP = "dedup"
    TRIM_TOOL_RESULTS = "trim_tool_results"
    TRIM_SYSTEM_DUPS = "trim_system_dups"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUDGET = "token_budget"
    COMPRESS_TOOL_OUTPUTS = "compress_tool_outputs"


@dataclass
class ContextConfig:
    """Configuration for context engine."""

    enabled: bool = True
    strategies: list[str] = field(
        default_factory=lambda: ["dedup", "trim_tool_results", "trim_system_dups"]
    )
    max_context_tokens: int = 0
    token_budget_reserve: int = 4096
    sliding_window_size: int = 0
    preserve_system: bool = True
    max_tool_result_tokens: int = 2000
    tool_result_truncation_marker: str = (
        "\n... [truncated by Orchesis — {saved} tokens saved]"
    )
    dedup_window: int = 50
    track_savings: bool = True


@dataclass
class ContextResult:
    """Result of context optimization."""

    messages: list[dict[str, Any]]
    original_count: int
    final_count: int
    original_tokens: int
    final_tokens: int
    tokens_saved: int
    strategies_applied: list[str]
    details: dict[str, Any] = field(default_factory=dict)


class ContextEngine:
    """
    Optimizes message context before sending to LLM.
    Thread-safe, zero dependencies, O(N) per message array.
    """

    def __init__(self, config: Optional[ContextConfig] = None) -> None:
        self._config = config or ContextConfig()
        self._lock = threading.Lock()
        self._total_tokens_saved: int = 0
        self._total_messages_removed: int = 0
        self._total_optimizations: int = 0
        self._strategy_hits: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def optimize(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        max_tokens: int = 0,
    ) -> ContextResult:
        if not self._config.enabled or not messages:
            return ContextResult(
                messages=list(messages),
                original_count=len(messages),
                final_count=len(messages),
                original_tokens=self._estimate_tokens(messages),
                final_tokens=self._estimate_tokens(messages),
                tokens_saved=0,
                strategies_applied=[],
            )
        result_messages = [dict(m) for m in messages]
        original_tokens = self._estimate_tokens(result_messages)
        original_count = len(result_messages)
        applied: list[str] = []
        details: dict[str, Any] = {}
        active = self._config.strategies

        if "dedup" in active:
            before = len(result_messages)
            result_messages = self._strategy_dedup(result_messages)
            if before > len(result_messages):
                applied.append("dedup")
                details["dedup_removed"] = before - len(result_messages)

        if "trim_system_dups" in active:
            before = len(result_messages)
            result_messages = self._strategy_trim_system_dups(result_messages)
            if before > len(result_messages):
                applied.append("trim_system_dups")
                details["system_dups_removed"] = before - len(result_messages)

        if "trim_tool_results" in active:
            result_messages, tokens_trimmed = self._strategy_trim_tool_results(
                result_messages
            )
            if tokens_trimmed > 0:
                applied.append("trim_tool_results")
                details["tool_tokens_trimmed"] = tokens_trimmed

        if "compress_tool_outputs" in active:
            result_messages, tokens_compressed = self._strategy_compress_tool_outputs(
                result_messages
            )
            if tokens_compressed > 0:
                applied.append("compress_tool_outputs")
                details["tool_tokens_compressed"] = tokens_compressed

        if "sliding_window" in active and self._config.sliding_window_size > 0:
            before = len(result_messages)
            result_messages = self._strategy_sliding_window(result_messages)
            if before > len(result_messages):
                applied.append("sliding_window")
                details["window_removed"] = before - len(result_messages)

        if "token_budget" in active:
            budget = max_tokens or self._config.max_context_tokens
            if budget > 0:
                before_tokens = self._estimate_tokens(result_messages)
                result_messages = self._strategy_token_budget(
                    result_messages, budget - self._config.token_budget_reserve
                )
                after_tokens = self._estimate_tokens(result_messages)
                if before_tokens > after_tokens:
                    applied.append("token_budget")
                    details["budget_tokens_removed"] = before_tokens - after_tokens

        final_tokens = self._estimate_tokens(result_messages)
        tokens_saved = max(0, original_tokens - final_tokens)

        if applied and self._config.track_savings:
            with self._lock:
                self._total_tokens_saved += tokens_saved
                self._total_messages_removed += original_count - len(result_messages)
                self._total_optimizations += 1
                for s in applied:
                    self._strategy_hits[s] = self._strategy_hits.get(s, 0) + 1

        return ContextResult(
            messages=result_messages,
            original_count=original_count,
            final_count=len(result_messages),
            original_tokens=original_tokens,
            final_tokens=final_tokens,
            tokens_saved=tokens_saved,
            strategies_applied=applied,
            details=details,
        )

    def _strategy_dedup(self, messages: list[dict]) -> list[dict]:
        window = self._config.dedup_window
        result: list[dict] = []
        for msg in messages:
            if str(msg.get("role", "")).lower() == "system":
                result.append(msg)
                continue
            h = self._hash_message(msg)
            start = max(0, len(result) - window)
            found_dup = False
            for j in range(start, len(result)):
                if self._hash_message(result[j]) == h:
                    found_dup = True
                    break
            if not found_dup:
                result.append(msg)
        return result

    def _strategy_trim_system_dups(self, messages: list[dict]) -> list[dict]:
        seen_hashes: set[str] = set()
        result: list[dict] = []
        for msg in messages:
            role = str(msg.get("role", "")).lower()
            if role != "system":
                result.append(msg)
                continue
            h = self._hash_message(msg)
            if h not in seen_hashes:
                seen_hashes.add(h)
                result.append(msg)
        return result

    def _strategy_trim_tool_results(self, messages: list[dict]) -> tuple[list[dict], int]:
        max_tok = self._config.max_tool_result_tokens
        marker = self._config.tool_result_truncation_marker
        total_trimmed = 0
        result: list[dict] = []
        for msg in list(messages):
            m = dict(msg)
            content = m.get("content", "")
            role = str(m.get("role", "")).lower()
            if role == "tool" and isinstance(content, str):
                tok = self._chars_to_tokens(content)
                if tok > max_tok:
                    saved = tok - max_tok
                    keep_chars = max_tok * 4
                    truncated = content[:keep_chars] + marker.format(saved=saved)
                    m["content"] = truncated
                    total_trimmed += saved
            elif isinstance(content, list):
                new_blocks: list[dict] = []
                for block in content:
                    b = dict(block)
                    text = b.get("text", "") or b.get("content", "")
                    if isinstance(text, str) and block.get("type") == "tool_result":
                        tok = self._chars_to_tokens(text)
                        if tok > max_tok:
                            saved = tok - max_tok
                            keep_chars = max_tok * 4
                            truncated = text[:keep_chars] + marker.format(saved=saved)
                            if "text" in b:
                                b["text"] = truncated
                            else:
                                b["content"] = truncated
                            total_trimmed += saved
                    new_blocks.append(b)
                m["content"] = new_blocks
            result.append(m)
        return result, total_trimmed

    def _strategy_compress_tool_outputs(
        self, messages: list[dict]
    ) -> tuple[list[dict], int]:
        threshold = self._config.max_tool_result_tokens * 4
        head_tok = 500
        tail_tok = 500
        total_saved = 0
        result: list[dict] = []
        for msg in list(messages):
            m = dict(msg)
            content = m.get("content", "")
            role = str(m.get("role", "")).lower()
            if role == "tool" and isinstance(content, str):
                tok = self._chars_to_tokens(content)
                if tok > threshold:
                    head_chars = head_tok * 4
                    tail_chars = tail_tok * 4
                    mid = "... [middle section removed by Orchesis] ..."
                    if len(content) <= head_chars + tail_chars:
                        result.append(m)
                        continue
                    compressed = (
                        content[:head_chars]
                        + "\n"
                        + mid
                        + "\n"
                        + content[-tail_chars:]
                    )
                    total_saved += tok - self._chars_to_tokens(compressed)
                    m["content"] = compressed
            elif isinstance(content, list):
                new_blocks: list[dict] = []
                for block in content:
                    b = dict(block)
                    text = b.get("text", "") or b.get("content", "")
                    if isinstance(text, str) and block.get("type") == "tool_result":
                        tok = self._chars_to_tokens(text)
                        if tok > threshold:
                            head_chars = head_tok * 4
                            tail_chars = tail_tok * 4
                            mid = "... [middle section removed by Orchesis] ..."
                            if len(text) > head_chars + tail_chars:
                                compressed = (
                                    text[:head_chars]
                                    + "\n"
                                    + mid
                                    + "\n"
                                    + text[-tail_chars:]
                                )
                                total_saved += tok - self._chars_to_tokens(compressed)
                                if "text" in b:
                                    b["text"] = compressed
                                else:
                                    b["content"] = compressed
                    new_blocks.append(b)
                m["content"] = new_blocks
            result.append(m)
        return result, total_saved

    def _strategy_sliding_window(self, messages: list[dict]) -> list[dict]:
        n = self._config.sliding_window_size
        if n <= 0:
            return messages
        systems: list[dict] = []
        others: list[dict] = []
        for msg in messages:
            if self._config.preserve_system and str(msg.get("role", "")).lower() == "system":
                systems.append(msg)
            else:
                others.append(msg)
        keep = max(0, n - len(systems))
        trimmed = others[-keep:] if len(others) > keep else others
        return systems + trimmed

    def _strategy_token_budget(self, messages: list[dict], budget: int) -> list[dict]:
        if budget <= 0:
            return messages
        total = self._estimate_tokens(messages)
        if total <= budget:
            return messages
        systems: list[dict] = []
        others: list[dict] = []
        for msg in messages:
            if str(msg.get("role", "")).lower() == "system":
                systems.append(msg)
            else:
                others.append(msg)
        if not others:
            return messages
        last_user_idx = -1
        for i in range(len(others) - 1, -1, -1):
            if str(others[i].get("role", "")).lower() == "user":
                last_user_idx = i
                break
        while total > budget and len(others) > 1:
            remove_idx = 0
            if remove_idx == last_user_idx:
                remove_idx = 1
                if remove_idx >= len(others):
                    break
            others.pop(remove_idx)
            if last_user_idx > remove_idx:
                last_user_idx -= 1
            total = self._estimate_tokens(systems + others)
        return systems + others

    @staticmethod
    def _chars_to_tokens(text: str) -> int:
        return max(0, len(text) // 4)

    @staticmethod
    def _estimate_tokens(messages: list[dict]) -> int:
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += len(content) // 4
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text", "") or block.get("content", "")
                        if isinstance(text, str):
                            total += len(text) // 4
            total += 4
        return max(0, total)

    @staticmethod
    def _hash_message(msg: dict) -> str:
        role = str(msg.get("role", ""))
        content = msg.get("content", "")
        if isinstance(content, list):
            content = json.dumps(content, sort_keys=True, ensure_ascii=False)
        elif not isinstance(content, str):
            content = str(content)
        blob = f"{role}:{content}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._config.enabled,
                "total_tokens_saved": self._total_tokens_saved,
                "total_messages_removed": self._total_messages_removed,
                "total_optimizations": self._total_optimizations,
                "strategy_hits": dict(self._strategy_hits),
                "strategies_active": list(self._config.strategies),
            }

    def reset_stats(self) -> None:
        with self._lock:
            self._total_tokens_saved = 0
            self._total_messages_removed = 0
            self._total_optimizations = 0
            self._strategy_hits.clear()
