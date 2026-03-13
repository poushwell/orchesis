"""Context optimization for reducing token waste."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import threading
from typing import Any, Optional

from orchesis.message_chain import validate_tool_chain

MODEL_CONTEXT_WINDOWS = {
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
    "o1": 200_000,
    "o1-mini": 128_000,
    "o3": 200_000,
    "o3-mini": 200_000,
    "claude-sonnet-4-20250514": 200_000,
    "claude-opus-4-20250514": 200_000,
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "gemini-2.0-flash": 1_000_000,
    "gemini-2.0-pro": 2_000_000,
    "gemini-1.5-pro": 2_000_000,
    "gemini-1.5-flash": 1_000_000,
    "_default": 128_000,
}

TOKEN_CHARS_RATIO = {
    "gpt": 4.0,
    "claude": 3.5,
    "gemini": 4.0,
    "_default": 4.0,
}

_ACK_PREFIXES = (
    "sure",
    "understood",
    "ok",
    "okay",
    "got it",
    "i can help",
    "i will do that",
    "absolutely",
    "certainly",
)


@dataclass
class OptimizationResult:
    """Result of context optimization."""

    original_tokens: int
    optimized_tokens: int
    savings_percent: float
    optimizations_applied: list[str] = field(default_factory=list)
    messages_removed: int = 0
    messages_merged: int = 0
    system_prompt_cached: bool = False


class ContextOptimizer:
    """Context compressor for AI agent requests."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.dedup_system_prompt = bool(cfg.get("dedup_system_prompt", True))
        self.remove_stale_messages = bool(cfg.get("remove_stale_messages", True))
        self.dedup_tool_definitions = bool(cfg.get("dedup_tool_definitions", True))
        self.remove_ack_messages = bool(cfg.get("remove_ack_messages", True))
        self.merge_consecutive = bool(cfg.get("merge_consecutive", True))
        self.max_context_ratio = max(0.1, min(1.0, float(cfg.get("max_context_ratio", 0.7))))
        self.stale_message_age = max(3, int(cfg.get("stale_message_age", 10)))
        self.min_message_length = max(1, int(cfg.get("min_message_length", 5)))
        self.never_remove_system = bool(cfg.get("never_remove_system", True))
        self.never_remove_last_n = max(0, int(cfg.get("never_remove_last_n", 3)))
        self.preserve_tool_chains = bool(cfg.get("preserve_tool_chains", True))
        self._lock = threading.Lock()
        self._system_hash_by_agent: dict[str, str] = {}
        self._tool_hash_by_agent: dict[str, str] = {}
        self._stats = {
            "requests_optimized": 0,
            "total_original_tokens": 0,
            "total_optimized_tokens": 0,
            "messages_removed": 0,
            "messages_merged": 0,
            "system_prompt_cache_hits": 0,
            "tool_schema_repeats": 0,
        }

    @staticmethod
    def _ratio_for_model(model: str) -> float:
        value = str(model or "").lower()
        for key, ratio in TOKEN_CHARS_RATIO.items():
            if key != "_default" and key in value:
                return ratio
        return TOKEN_CHARS_RATIO["_default"]

    @staticmethod
    def _copy_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in messages:
            if not isinstance(item, dict):
                continue
            out.append(dict(item))
        return out

    @staticmethod
    def _looks_structured(text: str) -> bool:
        t = text or ""
        return "```" in t or "http://" in t or "https://" in t or "{" in t or "[" in t

    @staticmethod
    def _is_ack_message(msg: dict[str, Any], *, is_last_assistant: bool) -> bool:
        if str(msg.get("role", "")).lower() != "assistant":
            return False
        if is_last_assistant:
            return False
        if msg.get("tool_calls"):
            return False
        text = str(msg.get("content", "") or "").strip()
        if not text:
            return False
        lower = text.lower()
        words = lower.split()
        if len(words) > 20:
            return False
        if any(ch.isdigit() for ch in text):
            return False
        if "http://" in lower or "https://" in lower or "```" in lower:
            return False
        return lower.startswith(_ACK_PREFIXES)

    def estimate_tokens(self, messages: list[dict], tools: list | None = None, model: str = "") -> int:
        if not messages and not tools:
            return 0
        ratio = self._ratio_for_model(model)
        total = 0.0
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            content = str(msg.get("content", "") or "")
            total += len(content) / ratio + 4.0
            if isinstance(msg.get("tool_calls"), list):
                for call in msg.get("tool_calls", []):
                    try:
                        total += len(json.dumps(call, ensure_ascii=False)) / ratio + 2.0
                    except Exception:
                        total += 2.0
        if isinstance(tools, list):
            for tool in tools:
                try:
                    total += len(json.dumps(tool, ensure_ascii=False)) / ratio + 4.0
                except Exception:
                    total += 4.0
        return int(max(0.0, round(total)))

    def _dedup_system_prompt(self, messages: list[dict[str, Any]], agent_id: str, result: OptimizationResult) -> list[dict[str, Any]]:
        first_kept = False
        seen_hashes: set[str] = set()
        out: list[dict[str, Any]] = []
        for msg in messages:
            role = str(msg.get("role", "")).lower()
            if role != "system":
                out.append(msg)
                continue
            content = str(msg.get("content", "") or "")
            digest = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
            if not first_kept:
                first_kept = True
                seen_hashes.add(digest)
                out.append(msg)
                continue
            if digest in seen_hashes:
                result.messages_removed += 1
                continue
            seen_hashes.add(digest)
            out.append(msg)
        if agent_id and first_kept:
            first_system = next((m for m in out if str(m.get("role", "")).lower() == "system"), None)
            if isinstance(first_system, dict):
                digest = hashlib.sha256(str(first_system.get("content", "")).encode("utf-8", errors="ignore")).hexdigest()
                with self._lock:
                    prev = self._system_hash_by_agent.get(agent_id)
                    self._system_hash_by_agent[agent_id] = digest
                    if prev == digest:
                        result.system_prompt_cached = True
                        self._stats["system_prompt_cache_hits"] += 1
        return out

    def _remove_stale_messages(self, messages: list[dict[str, Any]], result: OptimizationResult) -> list[dict[str, Any]]:
        if len(messages) <= self.never_remove_last_n + 1:
            return messages
        keep_from = max(0, len(messages) - self.never_remove_last_n)
        out: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            role = str(msg.get("role", "")).lower()
            content = str(msg.get("content", "") or "")
            is_last_n = idx >= keep_from
            if self.never_remove_system and role == "system":
                out.append(msg)
                continue
            if is_last_n:
                out.append(msg)
                continue
            if msg.get("tool_calls") or role == "tool":
                out.append(msg)
                continue
            if self._looks_structured(content):
                out.append(msg)
                continue
            age = len(messages) - idx - 1
            if age >= self.stale_message_age and len(content.strip().split()) < self.min_message_length:
                result.messages_removed += 1
                continue
            out.append(msg)
        return out

    def _dedup_tool_definitions(self, tools: list | None, agent_id: str) -> None:
        if not agent_id or not isinstance(tools, list):
            return
        try:
            digest = hashlib.sha256(json.dumps(tools, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        except Exception:
            return
        with self._lock:
            prev = self._tool_hash_by_agent.get(agent_id)
            self._tool_hash_by_agent[agent_id] = digest
            if prev == digest:
                self._stats["tool_schema_repeats"] += 1

    def _remove_ack_messages(self, messages: list[dict[str, Any]], result: OptimizationResult) -> list[dict[str, Any]]:
        last_assistant_idx = -1
        for i, msg in enumerate(messages):
            if str(msg.get("role", "")).lower() == "assistant":
                last_assistant_idx = i
        out: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            if self._is_ack_message(msg, is_last_assistant=(idx == last_assistant_idx)):
                result.messages_removed += 1
                continue
            out.append(msg)
        return out

    def _merge_consecutive(self, messages: list[dict[str, Any]], result: OptimizationResult) -> list[dict[str, Any]]:
        if not messages:
            return messages
        out: list[dict[str, Any]] = []
        roles = {str(m.get("role", "")).lower() for m in messages if isinstance(m, dict)}
        if len(roles) == 1 and len(messages) >= self.never_remove_last_n:
            return messages
        current_idx = 0
        current = dict(messages[0])
        for idx, nxt in enumerate(messages[1:], start=1):
            c_role = str(current.get("role", "")).lower()
            n_role = str(nxt.get("role", "")).lower()
            c_words = len(str(current.get("content", "") or "").split())
            n_words = len(str(nxt.get("content", "") or "").split())
            if (
                c_role
                and c_role == n_role
                and not current.get("tool_calls")
                and not nxt.get("tool_calls")
                and c_role != "tool"
                and c_role != "system"
                and not (c_role == "assistant" and (c_words > 30 or n_words > 30))
            ):
                c_text = str(current.get("content", "") or "")
                n_text = str(nxt.get("content", "") or "")
                current["content"] = f"{c_text}\n{n_text}".strip()
                result.messages_merged += 1
                continue
            out.append(current)
            current_idx = idx
            current = dict(nxt)
        out.append(current)
        return out

    def optimize(
        self,
        messages: list[dict],
        model: str = "",
        tools: list | None = None,
        agent_id: str | None = None,
    ) -> tuple[list[dict], OptimizationResult]:
        safe_messages = self._copy_messages(messages if isinstance(messages, list) else [])
        original_tokens = self.estimate_tokens(safe_messages, tools, model=model)
        result = OptimizationResult(
            original_tokens=original_tokens,
            optimized_tokens=original_tokens,
            savings_percent=0.0,
        )
        if not self.enabled or not safe_messages:
            return safe_messages, result

        if self.dedup_system_prompt:
            safe_messages = self._dedup_system_prompt(safe_messages, str(agent_id or ""), result)
            result.optimizations_applied.append("system_prompt_dedup")
        if self.remove_stale_messages:
            safe_messages = self._remove_stale_messages(safe_messages, result)
            result.optimizations_applied.append("stale_message_removal")
        if self.remove_ack_messages:
            safe_messages = self._remove_ack_messages(safe_messages, result)
            result.optimizations_applied.append("ack_message_removal")
        if self.merge_consecutive:
            safe_messages = self._merge_consecutive(safe_messages, result)
            result.optimizations_applied.append("consecutive_merge")
        if self.preserve_tool_chains:
            safe_messages = validate_tool_chain(safe_messages)
        if self.dedup_tool_definitions:
            self._dedup_tool_definitions(tools, str(agent_id or ""))
            result.optimizations_applied.append("tool_definition_tracking")

        optimized_tokens = self.estimate_tokens(safe_messages, tools, model=model)
        result.optimized_tokens = optimized_tokens
        if result.original_tokens > 0:
            result.savings_percent = round(
                max(0.0, min(100.0, ((result.original_tokens - optimized_tokens) / float(result.original_tokens)) * 100.0)),
                3,
            )
        else:
            result.savings_percent = 0.0

        with self._lock:
            self._stats["requests_optimized"] += 1
            self._stats["total_original_tokens"] += result.original_tokens
            self._stats["total_optimized_tokens"] += result.optimized_tokens
            self._stats["messages_removed"] += result.messages_removed
            self._stats["messages_merged"] += result.messages_merged
        return safe_messages, result

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            count = int(self._stats["requests_optimized"])
            orig = int(self._stats["total_original_tokens"])
            opt = int(self._stats["total_optimized_tokens"])
            savings = 0.0 if orig <= 0 else ((orig - opt) / float(orig)) * 100.0
            return {
                **self._stats,
                "average_savings_percent": round(max(0.0, savings), 3),
                "requests_optimized": count,
            }

    def reset_stats(self) -> None:
        with self._lock:
            self._stats = {
                "requests_optimized": 0,
                "total_original_tokens": 0,
                "total_optimized_tokens": 0,
                "messages_removed": 0,
                "messages_merged": 0,
                "system_prompt_cache_hits": 0,
                "tool_schema_repeats": 0,
            }
