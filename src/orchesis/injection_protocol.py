"""Context injection decision and application protocol."""

from __future__ import annotations

import threading
import time
from hashlib import sha1
from typing import Any


class ContextInjectionProtocol:
    """Formal model for when and how much context to inject.

    NLCE Layer 2 - answers: when to inject, what to inject, how much.
    Based on UCI scores + session state + budget constraints.
    """

    INJECTION_STRATEGIES = {
        "proactive": "Inject before context degrades",
        "reactive": "Inject when quality drops below threshold",
        "scheduled": "Inject every N requests",
        "adaptive": "Use Kalman state to decide",
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        strategy = str(cfg.get("strategy", "adaptive")).strip().lower()
        self.strategy = strategy if strategy in self.INJECTION_STRATEGIES else "adaptive"
        self.quality_threshold = float(cfg.get("quality_threshold", 0.6))
        self.max_injection_tokens = int(cfg.get("max_tokens", 500))
        self._lock = threading.Lock()
        self._injection_log: list[dict[str, Any]] = []
        self._prevented_failures = 0

    @staticmethod
    def _estimate_tokens(items: list[dict]) -> int:
        chars = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            content = item.get("content", "")
            if isinstance(content, str):
                chars += len(content)
        return max(0, chars // 4)

    def should_inject(self, session_state: dict, metrics: dict) -> dict:
        """Decide whether to inject context."""
        sess = session_state if isinstance(session_state, dict) else {}
        m = metrics if isinstance(metrics, dict) else {}
        quality = float(m.get("quality_score", 1.0) or 1.0)
        budget_level = str(m.get("budget_level", "normal")).upper()
        request_count = int(sess.get("request_count", 0) or 0)

        inject = False
        reason = "quality_healthy"
        urgency = "low"

        if self.strategy in {"reactive", "adaptive"} and quality < self.quality_threshold:
            inject = True
            reason = "quality_below_threshold"
        elif self.strategy == "scheduled" and request_count > 0 and request_count % 5 == 0:
            inject = True
            reason = "scheduled_interval"
        elif self.strategy == "proactive" and budget_level in {"L1", "L2"}:
            inject = True
            reason = "budget_preemptive"
        elif self.strategy == "adaptive" and budget_level in {"L1", "L2"}:
            inject = True
            reason = "adaptive_budget_pressure"

        if inject:
            if quality < max(0.3, self.quality_threshold - 0.2):
                urgency = "critical"
            elif quality < self.quality_threshold:
                urgency = "high"
            elif budget_level in {"L1", "L2"}:
                urgency = "medium"
            else:
                urgency = "low"
        return {"inject": inject, "reason": reason, "urgency": urgency}

    def select_content(self, available_context: list[dict], budget: int) -> list[dict]:
        """Select what to inject given token budget."""
        if not isinstance(available_context, list) or not available_context:
            return []
        token_budget = max(0, min(int(budget or 0), int(self.max_injection_tokens)))
        if token_budget <= 0:
            return []
        selected: list[dict[str, Any]] = []
        used = 0
        for item in available_context:
            if not isinstance(item, dict):
                continue
            text = item.get("content")
            if not isinstance(text, str) or not text.strip():
                continue
            role = str(item.get("role", "system") or "system").lower()
            if role not in {"assistant", "system"}:
                continue
            token_cost = max(1, len(text) // 4)
            if used + token_cost > token_budget:
                continue
            selected.append({"role": "system", "content": text.strip()})
            used += token_cost
        return selected

    def inject(self, messages: list[dict], injection: list[dict]) -> dict:
        """Apply injection. Returns modified messages + report."""
        base = [dict(item) for item in messages if isinstance(item, dict)] if isinstance(messages, list) else []
        extra = [dict(item) for item in injection if isinstance(item, dict)] if isinstance(injection, list) else []
        if not extra:
            return {
                "messages": base,
                "injected_count": 0,
                "tokens_injected": 0,
                "injection_id": "",
            }
        # Inject as system hints before most recent user message.
        insert_at = len(base)
        for idx in range(len(base) - 1, -1, -1):
            role = str(base[idx].get("role", "")).lower()
            if role == "user":
                insert_at = idx
                break
        merged = base[:insert_at] + extra + base[insert_at:]
        tokens = self._estimate_tokens(extra)
        seed = f"{time.time_ns()}:{len(extra)}:{tokens}:{insert_at}"
        injection_id = sha1(seed.encode("utf-8")).hexdigest()[:12]
        log_row = {
            "injection_id": injection_id,
            "injected_count": len(extra),
            "tokens_injected": tokens,
            "strategy": self.strategy,
            "timestamp": time.time(),
        }
        with self._lock:
            self._injection_log.append(log_row)
            if len(self._injection_log) > 5000:
                del self._injection_log[:-5000]
            if tokens > 0:
                self._prevented_failures += 1
        return {
            "messages": merged,
            "injected_count": len(extra),
            "tokens_injected": tokens,
            "injection_id": injection_id,
        }

    def get_injection_stats(self) -> dict:
        with self._lock:
            rows = list(self._injection_log)
            prevented = int(self._prevented_failures)
        total = len(rows)
        avg_tokens = (sum(int(item.get("tokens_injected", 0) or 0) for item in rows) / float(total)) if total > 0 else 0.0
        return {
            "total_injections": int(total),
            "avg_tokens_injected": round(avg_tokens, 3),
            "strategy": self.strategy,
            "prevented_failures": prevented,
        }
