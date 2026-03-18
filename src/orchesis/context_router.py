"""Context compression strategy router."""

from __future__ import annotations

import threading
from typing import Any


class ContextStrategyRouter:
    """Routes context compression strategy based on task type."""

    TASK_TYPES = {
        "coding": ["code", "debug", "implement", "function", "class"],
        "research": ["search", "web_fetch", "browse", "find"],
        "planning": ["plan", "schedule", "organize", "breakdown"],
        "writing": ["write", "draft", "compose", "edit"],
        "analysis": ["analyze", "compare", "evaluate", "review"],
        "unknown": [],
    }

    STRATEGIES = {
        "coding": "preserve_structure",
        "research": "summarize_old",
        "planning": "hierarchical",
        "writing": "preserve_recent",
        "analysis": "balanced",
        "unknown": "balanced",
    }

    def __init__(self) -> None:
        self._stats: dict[str, int] = {name: 0 for name in self.TASK_TYPES}
        self._lock = threading.Lock()

    @staticmethod
    def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
        total_chars = 0
        for item in messages:
            if not isinstance(item, dict):
                continue
            content = item.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text", "")
                        if isinstance(text, str):
                            total_chars += len(text)
        return max(0, total_chars // 4)

    @staticmethod
    def _has_code_block(item: dict[str, Any]) -> bool:
        content = item.get("content", "")
        if isinstance(content, str):
            return "```" in content or "def " in content or "class " in content
        return False

    def classify(self, messages: list[dict], tools_used: list[str]) -> str:
        """Returns task type string."""
        tools_text = " ".join(str(name).lower() for name in tools_used if isinstance(name, str))
        msg_text = " ".join(
            str(item.get("content", "")).lower()
            for item in messages
            if isinstance(item, dict)
        )
        corpus = f"{tools_text} {msg_text}".strip()
        best_type = "unknown"
        best_score = 0
        for task_type, keywords in self.TASK_TYPES.items():
            if task_type == "unknown":
                continue
            score = 0
            for keyword in keywords:
                if keyword in corpus:
                    score += 1
            if score > best_score:
                best_score = score
                best_type = task_type
        with self._lock:
            self._stats[best_type] = self._stats.get(best_type, 0) + 1
        return best_type

    def get_strategy(self, task_type: str) -> str:
        """Returns compression strategy for task type."""
        if not isinstance(task_type, str):
            return self.STRATEGIES["unknown"]
        return self.STRATEGIES.get(task_type, self.STRATEGIES["unknown"])

    def apply_strategy(
        self,
        messages: list[dict],
        strategy: str,
        max_tokens: int,
    ) -> list[dict]:
        """Apply compression strategy to messages."""
        if not isinstance(messages, list):
            return []
        safe_messages = [dict(item) for item in messages if isinstance(item, dict)]
        if max_tokens <= 0 or self._estimate_tokens(safe_messages) <= max_tokens:
            return safe_messages

        system_messages = [item for item in safe_messages if item.get("role") == "system"]
        non_system = [item for item in safe_messages if item.get("role") != "system"]

        def _finalize(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if self._estimate_tokens(msgs) <= max_tokens:
                return msgs
            result: list[dict[str, Any]] = []
            # Always keep first system message if any.
            if system_messages:
                result.append(system_messages[0])
            # Keep newest messages within budget.
            budget = max_tokens - self._estimate_tokens(result)
            kept: list[dict[str, Any]] = []
            used = 0
            for item in reversed(msgs):
                if item.get("role") == "system":
                    continue
                size = self._estimate_tokens([item])
                if used + size <= budget:
                    kept.append(item)
                    used += size
            result.extend(reversed(kept))
            return result

        if strategy == "preserve_structure":
            keep: list[dict[str, Any]] = []
            for item in non_system:
                if item.get("role") == "tool" or item.get("tool_calls") or self._has_code_block(item):
                    keep.append(item)
            tail = non_system[-6:] if len(non_system) > 6 else non_system
            merged = system_messages + keep + [item for item in tail if item not in keep]
            return _finalize(merged)

        if strategy == "summarize_old":
            recent = non_system[-8:] if len(non_system) > 8 else non_system
            dropped = max(0, len(non_system) - len(recent))
            summary: list[dict[str, Any]] = []
            if dropped > 0:
                summary = [{"role": "assistant", "content": f"Summary: {dropped} older messages condensed."}]
            finalized = _finalize(system_messages + summary + recent)
            if summary and not any(
                "Summary:" in str(item.get("content", ""))
                for item in finalized
                if isinstance(item, dict)
            ):
                # Preserve at least a short summary marker for research strategy.
                if len(finalized) > 1:
                    finalized[1] = summary[0]
                elif finalized:
                    finalized.append(summary[0])
                else:
                    finalized = summary
            return finalized

        if strategy == "hierarchical":
            head = non_system[:2]
            tail = non_system[-6:] if len(non_system) > 6 else non_system
            middle_count = max(0, len(non_system) - len(head) - len(tail))
            summary: list[dict[str, Any]] = []
            if middle_count > 0:
                summary = [{"role": "assistant", "content": f"Plan summary: {middle_count} detailed messages compressed."}]
            merged = system_messages + head + summary + tail
            return _finalize(merged)

        if strategy == "preserve_recent":
            recent = non_system[-12:] if len(non_system) > 12 else non_system
            return _finalize(system_messages + recent)

        # balanced / fallback
        return _finalize(system_messages + non_system[-10:])

    def get_stats(self) -> dict:
        """Returns task type distribution."""
        with self._lock:
            snapshot = dict(self._stats)
        total = sum(snapshot.values())
        return {"total_classifications": total, "distribution": snapshot}
