"""Behavioral fingerprint (Context DNA) for agents."""

from __future__ import annotations

import math
import time
from typing import Any


class ContextDNA:
    """Behavioral fingerprint per agent."""

    DIMENSIONS = [
        "avg_prompt_length",
        "tool_call_frequency",
        "model_switch_rate",
        "session_duration_avg",
        "topic_distribution",
        "cache_hit_rate",
        "error_rate",
    ]

    def __init__(self, agent_id: str, config: dict | None = None):
        self.agent_id = str(agent_id or "").strip() or "unknown"
        self.config = dict(config) if isinstance(config, dict) else {}
        self.baseline: dict | None = None
        self.cold_start = True
        self._observations: list[dict[str, Any]] = []
        self._created_at = float(time.time())
        self._first_observed_at: float | None = None
        self._stddevs: dict[str, float] = {}

    def _is_cold_start(self) -> bool:
        if self._first_observed_at is None:
            return True
        return (time.time() - self._first_observed_at) < 86400.0

    @staticmethod
    def _extract_prompt_length(request: dict[str, Any]) -> float:
        messages = request.get("messages")
        if isinstance(messages, list):
            total = 0
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content", "")
                if isinstance(content, str):
                    total += len(content)
            return float(total)
        content = request.get("content", "")
        if isinstance(content, str):
            return float(len(content))
        return 0.0

    @staticmethod
    def _extract_topic(request: dict[str, Any]) -> str:
        topic = request.get("topic")
        if isinstance(topic, str) and topic.strip():
            return topic.strip().lower()
        return "unknown"

    @staticmethod
    def _extract_tool_calls(request: dict[str, Any]) -> int:
        tool_calls = request.get("tool_calls")
        if isinstance(tool_calls, list):
            return len(tool_calls)
        tools = request.get("tools")
        if isinstance(tools, list):
            return len(tools)
        tool_name = request.get("tool_name") or request.get("tool")
        if isinstance(tool_name, str) and tool_name.strip():
            return 1
        return 0

    def observe(self, request: dict, decision: dict) -> None:
        """Record one request/decision pair."""
        req = request if isinstance(request, dict) else {}
        dec = decision if isinstance(decision, dict) else {}
        now = time.time()
        if self._first_observed_at is None:
            self._first_observed_at = now
        obs = {
            "timestamp": now,
            "prompt_length": self._extract_prompt_length(req),
            "tool_calls": self._extract_tool_calls(req),
            "model": str(req.get("model", "") or ""),
            "session_duration": float(dec.get("duration_ms", 0.0) or 0.0),
            "topic": self._extract_topic(req),
            "cache_hit": 1.0 if bool(dec.get("cache_hit", False)) else 0.0,
            "error": 1.0
            if (bool(dec.get("error", False)) or str(dec.get("decision", "")).upper() == "DENY")
            else 0.0,
        }
        self._observations.append(obs)
        self.cold_start = self._is_cold_start()

    @staticmethod
    def _mean(values: list[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / float(len(values))

    @staticmethod
    def _std(values: list[float], mean: float) -> float:
        if len(values) <= 1:
            return 0.0
        var = sum((v - mean) ** 2 for v in values) / float(len(values))
        return math.sqrt(max(0.0, var))

    def compute_baseline(self) -> dict:
        """Compute baseline vector from observations."""
        if not self._observations:
            self.baseline = {dim: ({} if dim == "topic_distribution" else 0.0) for dim in self.DIMENSIONS}
            self._stddevs = {dim: 0.0 for dim in self.DIMENSIONS if dim != "topic_distribution"}
            return dict(self.baseline)

        prompt_lengths = [float(item.get("prompt_length", 0.0) or 0.0) for item in self._observations]
        tool_calls = [float(item.get("tool_calls", 0.0) or 0.0) for item in self._observations]
        durations = [float(item.get("session_duration", 0.0) or 0.0) for item in self._observations]
        cache_hits = [float(item.get("cache_hit", 0.0) or 0.0) for item in self._observations]
        errors = [float(item.get("error", 0.0) or 0.0) for item in self._observations]

        models = [str(item.get("model", "") or "") for item in self._observations]
        switches = 0
        prev = ""
        for model in models:
            if model and prev and model != prev:
                switches += 1
            if model:
                prev = model
        model_switch_rate = float(switches) / float(max(1, len(models) - 1))

        topic_counts: dict[str, int] = {}
        for item in self._observations:
            topic = str(item.get("topic", "unknown") or "unknown")
            topic_counts[topic] = topic_counts.get(topic, 0) + 1
        total_topics = float(sum(topic_counts.values()) or 1.0)
        topic_distribution = {topic: count / total_topics for topic, count in topic_counts.items()}

        baseline = {
            "avg_prompt_length": self._mean(prompt_lengths),
            "tool_call_frequency": self._mean(tool_calls),
            "model_switch_rate": model_switch_rate,
            "session_duration_avg": self._mean(durations),
            "topic_distribution": topic_distribution,
            "cache_hit_rate": self._mean(cache_hits),
            "error_rate": self._mean(errors),
        }
        self._stddevs = {
            "avg_prompt_length": self._std(prompt_lengths, baseline["avg_prompt_length"]),
            "tool_call_frequency": self._std(tool_calls, baseline["tool_call_frequency"]),
            "model_switch_rate": 0.0,
            "session_duration_avg": self._std(durations, baseline["session_duration_avg"]),
            "cache_hit_rate": self._std(cache_hits, baseline["cache_hit_rate"]),
            "error_rate": self._std(errors, baseline["error_rate"]),
        }
        self.baseline = baseline
        self.cold_start = self._is_cold_start()
        return dict(baseline)

    def anomaly_score(self, current: dict) -> float:
        """Returns 0.0-1.0. >0.5 = anomalous (>2σ deviation)."""
        if self.baseline is None:
            self.compute_baseline()
        baseline = self.baseline or {}
        now_vec = current if isinstance(current, dict) else {}
        numeric_dims = [
            "avg_prompt_length",
            "tool_call_frequency",
            "model_switch_rate",
            "session_duration_avg",
            "cache_hit_rate",
            "error_rate",
        ]
        if not numeric_dims:
            return 0.0
        anomalous_dims = 0
        for dim in numeric_dims:
            b = float(baseline.get(dim, 0.0) or 0.0)
            c = float(now_vec.get(dim, b) or 0.0)
            sigma = float(self._stddevs.get(dim, 0.0) or 0.0)
            if sigma <= 1e-9:
                if abs(c - b) >= max(0.25, abs(b) * 0.5):
                    anomalous_dims += 1
                continue
            if abs(c - b) > (2.0 * sigma):
                anomalous_dims += 1
        return max(0.0, min(1.0, float(anomalous_dims) / float(len(numeric_dims))))

    def export(self) -> dict:
        """Export DNA for storage/display."""
        if self.baseline is None:
            self.compute_baseline()
        return {
            "agent_id": self.agent_id,
            "baseline": dict(self.baseline or {}),
            "cold_start": bool(self.cold_start),
            "created_at": float(self._created_at),
            "first_observed_at": self._first_observed_at,
            "observations": [dict(item) for item in self._observations],
            "stddevs": dict(self._stddevs),
        }

    def load(self, data: dict) -> None:
        """Load previously saved DNA."""
        payload = data if isinstance(data, dict) else {}
        self.agent_id = str(payload.get("agent_id", self.agent_id) or self.agent_id)
        baseline = payload.get("baseline")
        self.baseline = dict(baseline) if isinstance(baseline, dict) else None
        self.cold_start = bool(payload.get("cold_start", True))
        self._created_at = float(payload.get("created_at", time.time()) or time.time())
        first_obs = payload.get("first_observed_at")
        self._first_observed_at = float(first_obs) if isinstance(first_obs, int | float) else None
        observations = payload.get("observations")
        self._observations = [dict(item) for item in observations] if isinstance(observations, list) else []
        stddevs = payload.get("stddevs")
        self._stddevs = dict(stddevs) if isinstance(stddevs, dict) else {}

