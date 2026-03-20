"""Pluggable evaluator interface for custom policy checks."""

from __future__ import annotations

import re
import threading
import time
from abc import ABC, abstractmethod


class BaseEvaluator(ABC):
    """Custom evaluator interface."""

    @abstractmethod
    def evaluate(self, request: dict, context: dict) -> "EvaluatorResult":
        """Return allow/deny/warn decision."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Evaluator identifier."""


class EvaluatorResult:
    def __init__(self, action: str, reason: str, metadata: dict | None = None):
        assert action in ("allow", "deny", "warn")
        self.action = action
        self.reason = reason
        self.metadata = metadata or {}


class KeywordBlockEvaluator(BaseEvaluator):
    def __init__(self, keywords: list[str] | None = None, action: str = "deny"):
        self._keywords = [str(item) for item in (keywords or []) if isinstance(item, str) and item.strip()]
        self._action = action if action in ("allow", "deny", "warn") else "deny"

    @property
    def name(self) -> str:
        return "keyword_block"

    def evaluate(self, request: dict, context: dict) -> EvaluatorResult:
        _ = context
        haystack = f"{request.get('tool', '')} {request.get('params', '')} {request.get('context', '')}".lower()
        for keyword in self._keywords:
            if keyword.lower() in haystack:
                return EvaluatorResult(
                    self._action,
                    f"{self.name}: matched keyword '{keyword}'",
                    metadata={"keyword": keyword},
                )
        return EvaluatorResult("allow", f"{self.name}: pass")


class RateLimitEvaluator(BaseEvaluator):
    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0, action: str = "deny"):
        self._max_requests = max(1, int(max_requests))
        self._window_seconds = max(1.0, float(window_seconds))
        self._action = action if action in ("allow", "deny", "warn") else "deny"
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "rate_limit"

    def evaluate(self, request: dict, context: dict) -> EvaluatorResult:
        _ = request, context
        now = time.monotonic()
        with self._lock:
            self._timestamps = [ts for ts in self._timestamps if (now - ts) <= self._window_seconds]
            self._timestamps.append(now)
            current = len(self._timestamps)
        if current > self._max_requests:
            return EvaluatorResult(
                self._action,
                f"{self.name}: {current}>{self._max_requests} in {int(self._window_seconds)}s",
                metadata={"count": current},
            )
        return EvaluatorResult("allow", f"{self.name}: pass", metadata={"count": current})


class AllowlistEvaluator(BaseEvaluator):
    def __init__(self, patterns: list[str] | None = None, action: str = "deny"):
        self._patterns = [str(item) for item in (patterns or []) if isinstance(item, str) and item.strip()]
        self._compiled = [re.compile(pattern) for pattern in self._patterns]
        self._action = action if action in ("allow", "deny", "warn") else "deny"

    @property
    def name(self) -> str:
        return "allowlist"

    def evaluate(self, request: dict, context: dict) -> EvaluatorResult:
        _ = context
        params = request.get("params")
        parts: list[str] = []
        if isinstance(params, dict):
            for value in params.values():
                if isinstance(value, str):
                    parts.append(value)
        elif isinstance(params, str):
            parts.append(params)
        base_text = " ".join(parts).strip()
        text = base_text if base_text else str(request.get("tool", "")).strip()
        if not self._compiled:
            return EvaluatorResult("allow", f"{self.name}: pass")
        if any(pattern.search(text) for pattern in self._compiled):
            return EvaluatorResult("allow", f"{self.name}: pass")
        return EvaluatorResult(self._action, f"{self.name}: not allowlisted")


class EvaluatorRegistry:
    """Register and run custom evaluators."""

    def __init__(self):
        self._evaluators: list[BaseEvaluator] = []

    def register(self, evaluator: BaseEvaluator) -> None:
        if not isinstance(evaluator, BaseEvaluator):
            raise TypeError("evaluator must implement BaseEvaluator")
        self._evaluators.append(evaluator)

    def run_all(self, request: dict, context: dict) -> list[EvaluatorResult]:
        results: list[EvaluatorResult] = []
        for evaluator in self._evaluators:
            try:
                results.append(evaluator.evaluate(request, context))
            except Exception as error:  # noqa: BLE001
                results.append(
                    EvaluatorResult(
                        "warn",
                        f"{evaluator.name}: internal_error {error}",
                        metadata={"evaluator": evaluator.name},
                    )
                )
        return results

    def load_from_config(self, config: dict) -> None:
        """Load evaluators from orchesis.yaml evaluators section."""
        raw_items = config.get("evaluators") if isinstance(config, dict) else None
        items = raw_items if isinstance(raw_items, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            ev_type = str(item.get("type", "")).strip().lower()
            if ev_type == "keyword_block":
                self.register(
                    KeywordBlockEvaluator(
                        keywords=item.get("keywords") if isinstance(item.get("keywords"), list) else [],
                        action=str(item.get("action", "deny")).strip().lower(),
                    )
                )
            elif ev_type == "allowlist":
                self.register(
                    AllowlistEvaluator(
                        patterns=item.get("patterns") if isinstance(item.get("patterns"), list) else [],
                        action=str(item.get("action", "deny")).strip().lower(),
                    )
                )
            elif ev_type == "rate_limit":
                self.register(
                    RateLimitEvaluator(
                        max_requests=int(item.get("max_requests", 60)),
                        window_seconds=float(item.get("window_seconds", 60.0)),
                        action=str(item.get("action", "deny")).strip().lower(),
                    )
                )
