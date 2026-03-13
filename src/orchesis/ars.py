"""Agent Reliability Score (ARS) - unified 0-100 reliability metric."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentMetrics:
    """Raw metrics collected per agent."""

    agent_id: str
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    total_requests: int = 0
    loop_flagged_requests: int = 0
    total_cost_usd: float = 0.0
    budget_ceiling_usd: float = 50.0
    latencies_ms: list[float] = field(default_factory=list)
    token_counts: list[int] = field(default_factory=list)
    clean_terminations: int = 0
    dirty_terminations: int = 0
    requests_with_threats: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class ARSResult:
    """Computed ARS for an agent."""

    agent_id: str
    score: float
    grade: str
    components: dict[str, float]
    sample_size: int
    confidence: str
    computed_at: float = 0.0


class AgentReliabilityScore:
    """Compute and track ARS for all agents."""

    DEFAULT_WEIGHTS = {
        "task_completion": 20,
        "loop_freedom": 15,
        "cost_efficiency": 15,
        "latency_health": 10,
        "context_stability": 10,
        "termination_quality": 15,
        "security_compliance": 15,
    }

    def __init__(
        self,
        weights: dict[str, int] | None = None,
        latency_baseline_ms: float = 2000.0,
        max_latencies_stored: int = 1000,
        max_token_counts_stored: int = 1000,
        max_agents: int = 10_000,
        enabled: bool = True,
    ) -> None:
        self._weights = self.DEFAULT_WEIGHTS.copy()
        if isinstance(weights, dict):
            for key, value in weights.items():
                if key in self._weights and isinstance(value, int | float):
                    self._weights[key] = int(value)
        self._latency_baseline = max(100.0, float(latency_baseline_ms))
        self._max_latencies = max(100, int(max_latencies_stored))
        self._max_tokens = max(100, int(max_token_counts_stored))
        self._max_agents = max(1, int(max_agents))
        self._enabled = bool(enabled)
        self._lock = threading.Lock()
        self._agents: dict[str, AgentMetrics] = {}
        self._stats = {"total_updates": 0, "total_computes": 0, "agents_tracked": 0, "evictions": 0}

    @property
    def enabled(self) -> bool:
        return self._enabled

    def update(
        self,
        agent_id: str,
        *,
        is_session_end: bool = False,
        session_success: bool | None = None,
        loop_flagged: bool = False,
        cost_usd: float = 0.0,
        latency_ms: float = 0.0,
        token_count: int = 0,
        clean_termination: bool | None = None,
        has_threat: bool = False,
    ) -> None:
        if not self._enabled or not agent_id:
            return
        now = time.time()
        with self._lock:
            metrics = self._agents.get(agent_id)
            if metrics is None:
                if len(self._agents) >= self._max_agents:
                    oldest_agent_id = min(
                        self._agents,
                        key=lambda aid: float(self._agents[aid].last_seen or self._agents[aid].first_seen or 0.0),
                    )
                    self._agents.pop(oldest_agent_id, None)
                    self._stats["evictions"] += 1
                metrics = AgentMetrics(agent_id=agent_id, first_seen=now, last_seen=now)
                self._agents[agent_id] = metrics
                self._stats["agents_tracked"] += 1
            metrics.last_seen = now
            metrics.total_requests += 1
            self._stats["total_updates"] += 1

            if is_session_end and session_success is not None:
                metrics.total_sessions += 1
                if bool(session_success):
                    metrics.successful_sessions += 1
                else:
                    metrics.failed_sessions += 1

            if loop_flagged:
                metrics.loop_flagged_requests += 1

            metrics.total_cost_usd += float(max(0.0, cost_usd))

            if latency_ms > 0:
                metrics.latencies_ms.append(float(latency_ms))
                if len(metrics.latencies_ms) > self._max_latencies:
                    metrics.latencies_ms = metrics.latencies_ms[-self._max_latencies :]

            if token_count > 0:
                metrics.token_counts.append(int(token_count))
                if len(metrics.token_counts) > self._max_tokens:
                    metrics.token_counts = metrics.token_counts[-self._max_tokens :]

            if clean_termination is not None:
                if clean_termination:
                    metrics.clean_terminations += 1
                else:
                    metrics.dirty_terminations += 1

            if has_threat:
                metrics.requests_with_threats += 1

    def compute(self, agent_id: str) -> ARSResult | None:
        if not self._enabled:
            return None
        with self._lock:
            metrics = self._agents.get(agent_id)
            if metrics is None:
                return None
            self._stats["total_computes"] += 1
            components = {
                "task_completion": self._score_task_completion(metrics),
                "loop_freedom": self._score_loop_freedom(metrics),
                "cost_efficiency": self._score_cost_efficiency(metrics),
                "latency_health": self._score_latency_health(metrics),
                "context_stability": self._score_context_stability(metrics),
                "termination_quality": self._score_termination_quality(metrics),
                "security_compliance": self._score_security_compliance(metrics),
            }
            total_weight = sum(self._weights.values()) or 1
            score = sum(components[k] * self._weights.get(k, 0) / total_weight for k in components)
            score = round(min(100.0, max(0.0, score)), 2)
            if score >= 90:
                grade = "A"
            elif score >= 75:
                grade = "B"
            elif score >= 60:
                grade = "C"
            elif score >= 40:
                grade = "D"
            else:
                grade = "F"

            n = metrics.total_requests
            if n >= 200:
                confidence = "high"
            elif n >= 50:
                confidence = "medium"
            else:
                confidence = "low"

            return ARSResult(
                agent_id=agent_id,
                score=score,
                grade=grade,
                components={k: round(v, 2) for k, v in components.items()},
                sample_size=n,
                confidence=confidence,
                computed_at=time.time(),
            )

    def compute_all(self) -> list[ARSResult]:
        with self._lock:
            agent_ids = list(self._agents.keys())
        return [item for aid in agent_ids if (item := self.compute(aid)) is not None]

    def _score_task_completion(self, m: AgentMetrics) -> float:
        n = m.total_sessions
        if n == 0:
            return 50.0
        p = m.successful_sessions / n
        z = 1.96
        denominator = 1 + (z * z / n)
        center = p + (z * z / (2 * n))
        spread = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)
        lower = (center - spread) / denominator
        return round(min(100.0, max(0.0, lower * 100.0)), 2)

    def _score_loop_freedom(self, m: AgentMetrics) -> float:
        if m.total_requests == 0:
            return 50.0
        clean = m.total_requests - m.loop_flagged_requests
        rate = (clean + 1) / (m.total_requests + 2)
        return round(rate * 100.0, 2)

    def _score_cost_efficiency(self, m: AgentMetrics) -> float:
        if m.budget_ceiling_usd <= 0:
            return 50.0
        ratio = m.total_cost_usd / m.budget_ceiling_usd
        return round(max(0.0, 100.0 * (1.0 - min(1.0, ratio))), 2)

    def _score_latency_health(self, m: AgentMetrics) -> float:
        if len(m.latencies_ms) < 5:
            return 50.0
        sorted_lat = sorted(m.latencies_ms)
        idx = min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))
        p95 = sorted_lat[idx]
        if p95 <= 0:
            return 100.0
        return round(max(0.0, 100.0 * min(1.0, self._latency_baseline / p95)), 2)

    def _score_context_stability(self, m: AgentMetrics) -> float:
        if len(m.token_counts) < 3:
            return 50.0
        n = len(m.token_counts)
        mean = sum(m.token_counts) / n
        if mean <= 0:
            return 50.0
        variance = sum((x - mean) ** 2 for x in m.token_counts) / n
        cv = math.sqrt(variance) / mean
        score = 100.0 * max(0.0, 1.0 - cv)
        return round(max(0.0, min(100.0, score)), 2)

    def _score_termination_quality(self, m: AgentMetrics) -> float:
        total = m.clean_terminations + m.dirty_terminations
        if total == 0:
            return 50.0
        return round((m.clean_terminations / total) * 100.0, 2)

    def _score_security_compliance(self, m: AgentMetrics) -> float:
        if m.total_requests == 0:
            return 50.0
        clean = m.total_requests - m.requests_with_threats
        return round((clean / m.total_requests) * 100.0, 2)

    def get_agent_metrics(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            metrics = self._agents.get(agent_id)
            if metrics is None:
                return None
            return {
                "agent_id": metrics.agent_id,
                "total_requests": metrics.total_requests,
                "total_sessions": metrics.total_sessions,
                "successful_sessions": metrics.successful_sessions,
                "total_cost_usd": round(metrics.total_cost_usd, 4),
                "loop_flagged_requests": metrics.loop_flagged_requests,
                "requests_with_threats": metrics.requests_with_threats,
                "clean_terminations": metrics.clean_terminations,
                "dirty_terminations": metrics.dirty_terminations,
                "first_seen": metrics.first_seen,
                "last_seen": metrics.last_seen,
            }

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "enabled": self._enabled,
                "weights": dict(self._weights),
                "max_agents": self._max_agents,
                "active_agents": len(self._agents),
            }
