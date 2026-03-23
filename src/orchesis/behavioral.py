"""Agent behavioral fingerprinting and anomaly detection."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import json
import math
import threading
import time
from typing import Any


@dataclass
class DimensionConfig:
    z_threshold: float = 3.0
    action: str = "warn"  # warn | block | log


@dataclass
class BehavioralConfig:
    enabled: bool = False
    learning_window: int = 20
    error_window_size: int = 50
    dimensions: dict[str, DimensionConfig] = field(default_factory=dict)
    persist_baselines: bool = False
    persist_path: str = ".orchesis/baselines.json"


@dataclass
class AnomalyDetail:
    dimension: str
    z_score: float
    baseline_mean: float
    current_value: float
    action: str


@dataclass
class BehavioralDecision:
    action: str  # allow | warn | block | learning
    anomaly_score: float
    anomalies: list[AnomalyDetail]
    state: str  # learning | monitoring


class RunningStats:
    """Welford online stats with O(1) memory."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._min = float("inf")
        self._max = float("-inf")

    def update(self, value: float) -> None:
        x = float(value)
        with self._lock:
            self._count += 1
            delta = x - self._mean
            self._mean += delta / self._count
            delta2 = x - self._mean
            self._m2 += delta * delta2
            if x < self._min:
                self._min = x
            if x > self._max:
                self._max = x

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def mean(self) -> float:
        with self._lock:
            return self._mean if self._count > 0 else 0.0

    @property
    def variance(self) -> float:
        with self._lock:
            if self._count <= 1:
                return 0.0
            return self._m2 / (self._count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def min(self) -> float:
        with self._lock:
            return 0.0 if self._count == 0 else self._min

    @property
    def max(self) -> float:
        with self._lock:
            return 0.0 if self._count == 0 else self._max

    def z_score(self, value: float) -> float:
        with self._lock:
            if self._count <= 1:
                return 0.0
            std = math.sqrt(self._m2 / (self._count - 1))
            if std == 0.0:
                return 0.0
            return (float(value) - self._mean) / std


class BehavioralFingerprint:
    """Per-agent behavioral baseline profile."""

    def __init__(self, learning_window: int = 20, error_window_size: int = 50) -> None:
        self._lock = threading.Lock()
        self._learning_window = max(1, int(learning_window))
        self.request_frequency = RunningStats()
        self.prompt_tokens = RunningStats()
        self.completion_tokens = RunningStats()
        self.cost_per_request = RunningStats()
        self.tool_count = RunningStats()
        self.error_rate = RunningStats()

        self.model_distribution: dict[str, int] = {}
        self.tool_distribution: dict[str, int] = {}
        self.total_requests = 0
        self.total_cost = 0.0
        now = time.monotonic()
        self.first_seen = now
        self.last_seen = now
        self._error_window: deque[int] = deque(maxlen=max(1, int(error_window_size)))

    def is_learning(self) -> bool:
        with self._lock:
            return self.total_requests < self._learning_window

    def last_seen_monotonic(self) -> float:
        with self._lock:
            return float(self.last_seen)

    @staticmethod
    def _estimate_prompt_tokens(messages: Any) -> int:
        try:
            serialized = json.dumps(messages if isinstance(messages, list) else [], ensure_ascii=False, sort_keys=True)
        except Exception:
            serialized = ""
        return max(0, len(serialized) // 4)

    def update(self, request_data: dict[str, Any]) -> None:
        now = time.monotonic()
        messages = request_data.get("messages", [])
        tools = request_data.get("tools", [])
        model = str(request_data.get("model", "")).strip()
        estimated_cost = float(request_data.get("estimated_cost", 0.0) or 0.0)
        is_error = bool(request_data.get("is_error", False))
        completion_tokens = int(request_data.get("completion_tokens", 0) or 0)

        prompt_tokens = self._estimate_prompt_tokens(messages)
        tool_count = len(tools) if isinstance(tools, list) else 0

        with self._lock:
            if self.total_requests > 0:
                interval = max(0.0001, now - self.last_seen)
                self.request_frequency.update(60.0 / interval)
            self.last_seen = now
            self.total_requests += 1
            self.total_cost += estimated_cost

            self.prompt_tokens.update(prompt_tokens)
            self.cost_per_request.update(estimated_cost)
            self.tool_count.update(float(tool_count))
            if completion_tokens > 0:
                self.completion_tokens.update(float(completion_tokens))

            self._error_window.append(1 if is_error else 0)
            self.error_rate.update(sum(self._error_window) / max(1, len(self._error_window)))

            if model:
                self.model_distribution[model] = self.model_distribution.get(model, 0) + 1
            if isinstance(tools, list):
                for item in tools:
                    name = ""
                    if isinstance(item, str):
                        name = item
                    elif isinstance(item, dict):
                        raw_name = item.get("name")
                        if isinstance(raw_name, str):
                            name = raw_name
                    if name:
                        self.tool_distribution[name] = self.tool_distribution.get(name, 0) + 1

    def record_response_only(self, is_error: bool, completion_tokens: int = 0) -> None:
        """Update response-only dimensions without mutating request baselines."""
        with self._lock:
            self.last_seen = time.monotonic()
            self._error_window.append(1 if is_error else 0)
            self.error_rate.update(sum(self._error_window) / max(1, len(self._error_window)))
            if completion_tokens > 0:
                self.completion_tokens.update(float(completion_tokens))

    def get_profile(self) -> dict[str, Any]:
        with self._lock:
            state = "learning" if self.total_requests < self._learning_window else "monitoring"
            return {
                "state": state,
                "total_requests": self.total_requests,
                "total_cost": round(self.total_cost, 8),
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "model_distribution": dict(self.model_distribution),
                "tool_distribution": dict(self.tool_distribution),
                "dimensions": {
                    "request_frequency": _stats_snapshot(self.request_frequency),
                    "prompt_tokens": _stats_snapshot(self.prompt_tokens),
                    "completion_tokens": _stats_snapshot(self.completion_tokens),
                    "cost_per_request": _stats_snapshot(self.cost_per_request),
                    "tool_count": _stats_snapshot(self.tool_count),
                    "error_rate": _stats_snapshot(self.error_rate),
                },
            }


def _stats_snapshot(stats: RunningStats) -> dict[str, float | int]:
    return {
        "count": stats.count,
        "mean": round(stats.mean, 8),
        "variance": round(stats.variance, 8),
        "std": round(stats.std, 8),
        "min": round(stats.min, 8),
        "max": round(stats.max, 8),
    }


DEFAULT_DIMENSIONS: dict[str, dict[str, Any]] = {
    "request_frequency": {"z_threshold": 3.0, "action": "warn"},
    "prompt_tokens": {"z_threshold": 3.5, "action": "warn"},
    "cost_per_request": {"z_threshold": 4.0, "action": "block"},
    "tool_count": {"z_threshold": 3.0, "action": "warn"},
    "error_rate": {"z_threshold": 3.0, "action": "warn"},
}


def extract_agent_id(request_data: dict[str, Any]) -> str:
    headers = request_data.get("headers", {})
    if isinstance(headers, dict):
        for key in ("x-agent-id", "x-orchesis-agent-id", "X-Agent-Id", "X-Orchesis-Agent-Id"):
            value = headers.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        auth = headers.get("authorization") or headers.get("Authorization")
        if isinstance(auth, str) and auth.strip():
            token = auth.strip().split()[-1]
            model = str(request_data.get("model", "unknown")).strip() or "unknown"
            return f"{token[:8]}:{model}"
    return "default"


class BehavioralDetector:
    """Anomaly detection over per-agent behavioral baselines."""

    _ACTION_SEVERITY = {"allow": 0, "log": 1, "warn": 2, "block": 3}

    def __init__(
        self,
        config: BehavioralConfig | dict[str, Any] | None = None,
        *,
        max_agents: int = 1000,
    ) -> None:
        if isinstance(config, BehavioralConfig):
            cfg = config
        else:
            cfg_map = config if isinstance(config, dict) else {}
            dim_cfg_in = cfg_map.get("dimensions", {})
            dims: dict[str, DimensionConfig] = {}
            for name, default in DEFAULT_DIMENSIONS.items():
                current = dim_cfg_in.get(name, {}) if isinstance(dim_cfg_in, dict) else {}
                if not isinstance(current, dict):
                    current = {}
                dims[name] = DimensionConfig(
                    z_threshold=float(current.get("z_threshold", default["z_threshold"])),
                    action=str(current.get("action", default["action"])).lower(),
                )
            cfg = BehavioralConfig(
                enabled=bool(cfg_map.get("enabled", False)),
                learning_window=int(cfg_map.get("learning_window", 20)),
                error_window_size=int(cfg_map.get("error_window_size", 50)),
                dimensions=dims,
                persist_baselines=bool(cfg_map.get("persist_baselines", False)),
                persist_path=str(cfg_map.get("persist_path", ".orchesis/baselines.json")),
            )
        self._config = cfg
        self._lock = threading.Lock()
        self._max_agents = max(1, int(max_agents))
        self._agents: dict[str, BehavioralFingerprint] = {}
        self._total_anomalies_detected = 0
        self._anomalies_by_dimension: Counter[str] = Counter()

    @property
    def enabled(self) -> bool:
        return bool(self._config.enabled)

    def _get_or_create(self, agent_id: str) -> BehavioralFingerprint:
        with self._lock:
            profile = self._agents.get(agent_id)
            if profile is None:
                profile = BehavioralFingerprint(
                    learning_window=self._config.learning_window,
                    error_window_size=self._config.error_window_size,
                )
                self._agents[agent_id] = profile
            while len(self._agents) > self._max_agents:
                others = [(aid, fp) for aid, fp in self._agents.items() if aid != agent_id]
                if not others:
                    break
                others.sort(key=lambda kv: kv[1].last_seen_monotonic())
                drop_n = max(1, int(len(self._agents) * 0.2))
                for aid, _ in others[:drop_n]:
                    self._agents.pop(aid, None)
                if len(self._agents) <= self._max_agents:
                    break
            return self._agents[agent_id]

    def check_request(self, agent_id: str, request_data: dict[str, Any]) -> BehavioralDecision:
        profile = self._get_or_create(agent_id)
        if profile.is_learning():
            profile.update(request_data)
            return BehavioralDecision(action="learning", anomaly_score=0.0, anomalies=[], state="learning")
        now = time.monotonic()
        elapsed = now - profile.last_seen
        current_freq = 60.0 / max(0.001, elapsed) if profile.total_requests > 0 else 0.0

        dimensions_map = {
            "request_frequency": profile.request_frequency,
            "prompt_tokens": profile.prompt_tokens,
            "cost_per_request": profile.cost_per_request,
            "tool_count": profile.tool_count,
            "error_rate": profile.error_rate,
        }
        current_values = {
            "request_frequency": current_freq,
            "prompt_tokens": float(BehavioralFingerprint._estimate_prompt_tokens(request_data.get("messages", []))),
            "cost_per_request": float(request_data.get("estimated_cost", 0.0) or 0.0),
            "tool_count": float(len(request_data.get("tools", []) if isinstance(request_data.get("tools"), list) else [])),
            "error_rate": 1.0 if bool(request_data.get("is_error", False)) else 0.0,
        }

        anomalies: list[AnomalyDetail] = []
        highest_action = "allow"
        max_abs_z = 0.0
        for dimension, stats in dimensions_map.items():
            dim_cfg = self._config.dimensions.get(dimension)
            if dim_cfg is None:
                continue
            current = current_values.get(dimension, 0.0)
            z = stats.z_score(current)
            abs_z = abs(z)
            if abs_z > max_abs_z:
                max_abs_z = abs_z
            if abs_z >= float(dim_cfg.z_threshold):
                anomalies.append(
                    AnomalyDetail(
                        dimension=dimension,
                        z_score=round(z, 6),
                        baseline_mean=round(stats.mean, 6),
                        current_value=round(float(current), 6),
                        action=dim_cfg.action,
                    )
                )
                if self._ACTION_SEVERITY.get(dim_cfg.action, 0) > self._ACTION_SEVERITY.get(highest_action, 0):
                    highest_action = dim_cfg.action

        profile.update(request_data)

        if anomalies:
            with self._lock:
                self._total_anomalies_detected += len(anomalies)
                for item in anomalies:
                    self._anomalies_by_dimension[item.dimension] += 1

        if highest_action == "log":
            highest_action = "allow"
        score = max(0.0, min(1.0, max_abs_z / 10.0))
        return BehavioralDecision(
            action=highest_action if anomalies else "allow",
            anomaly_score=round(score, 6),
            anomalies=anomalies,
            state="monitoring",
        )

    def record_response(self, agent_id: str, is_error: bool, completion_tokens: int = 0) -> None:
        profile = self._get_or_create(agent_id)
        profile.record_response_only(bool(is_error), int(completion_tokens))

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            learning = 0
            for profile in self._agents.values():
                if profile.is_learning():
                    learning += 1
            monitored = len(self._agents) - learning
            return {
                "agents_monitored": monitored,
                "agents_learning": learning,
                "total_anomalies_detected": self._total_anomalies_detected,
                "anomalies_by_dimension": dict(self._anomalies_by_dimension),
            }

    def get_agent_profile(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            profile = self._agents.get(agent_id)
        if profile is None:
            return None
        return profile.get_profile()

    def reset(self, agent_id: str | None = None) -> None:
        with self._lock:
            if isinstance(agent_id, str):
                self._agents.pop(agent_id, None)
            else:
                self._agents.clear()
            if agent_id is None:
                self._total_anomalies_detected = 0
                self._anomalies_by_dimension.clear()

    def cleanup_stale_agents(self, max_age_seconds: float = 3600.0) -> int:
        """Remove agents idle longer than max_age_seconds (monotonic clock). Returns count removed."""
        now = time.monotonic()
        max_age = max(0.0, float(max_age_seconds))
        with self._lock:
            stale_ids = [
                aid
                for aid, fp in list(self._agents.items())
                if now - fp.last_seen_monotonic() > max_age
            ]
            for aid in stale_ids:
                self._agents.pop(aid, None)
            return len(stale_ids)
