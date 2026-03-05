"""A/B Testing Framework and Task Completion Tracking for AI agent optimization."""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class ExperimentStatus(Enum):
    """Lifecycle of an experiment."""

    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TaskOutcome(Enum):
    """How a task/session ended."""

    SUCCESS = "success"
    FAILURE = "failure"
    ABANDONED = "abandoned"
    TIMEOUT = "timeout"
    LOOP = "loop"
    ESCALATED = "escalated"
    UNKNOWN = "unknown"


class SplitStrategy(Enum):
    """How to assign requests to variants."""

    RANDOM = "random"
    STICKY_SESSION = "sticky_session"
    STICKY_AGENT = "sticky_agent"
    ROUND_ROBIN = "round_robin"


@dataclass
class Variant:
    """One arm of an A/B experiment."""

    name: str
    weight: float = 0.5
    model_override: str = ""
    config_overrides: dict = field(default_factory=dict)
    requests: int = 0
    successes: int = 0
    failures: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    total_tokens: int = 0
    total_tool_calls: int = 0
    avg_turns: float = 0.0
    _turns_sum: int = 0
    _tasks_completed: int = 0


@dataclass
class VariantAssignment:
    """Result of assigning a request to an experiment variant."""

    experiment_id: str
    variant_name: str
    model_override: str
    config_overrides: dict


@dataclass
class VariantStats:
    """Computed stats for one variant."""

    name: str
    sample_size: int
    success_rate: float
    avg_cost_usd: float
    avg_latency_ms: float
    avg_tokens: int
    avg_tool_calls: float
    avg_turns: float
    p95_latency_ms: float
    error_rate: float
    cost_per_success: float


@dataclass
class ExperimentResult:
    """Statistical comparison of experiment variants."""

    experiment_id: str
    is_significant: bool
    winner: str
    confidence: float
    variants: dict[str, VariantStats]
    recommendation: str
    cost_comparison: str

    def to_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "is_significant": self.is_significant,
            "winner": self.winner,
            "confidence": self.confidence,
            "variants": {k: asdict(v) for k, v in self.variants.items()},
            "recommendation": self.recommendation,
            "cost_comparison": self.cost_comparison,
        }


@dataclass
class Experiment:
    """A/B experiment definition."""

    experiment_id: str
    name: str
    description: str = ""
    status: ExperimentStatus = ExperimentStatus.DRAFT
    variants: list[Variant] = field(default_factory=list)
    split_strategy: SplitStrategy = SplitStrategy.STICKY_SESSION
    target_models: list[str] = field(default_factory=list)
    target_agents: list[str] = field(default_factory=list)
    target_tools: list[str] = field(default_factory=list)
    max_requests: int = 0
    max_duration_seconds: float = 0.0
    min_sample_size: int = 30
    created_at: float = 0.0
    started_at: float = 0.0
    ended_at: float = 0.0
    _round_robin_counter: int = 0

    def to_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "variants": [
                {
                    "name": v.name,
                    "weight": v.weight,
                    "model_override": v.model_override,
                    "config_overrides": v.config_overrides,
                    "requests": v.requests,
                    "successes": v.successes,
                    "failures": v.failures,
                    "total_cost_usd": v.total_cost_usd,
                    "total_latency_ms": v.total_latency_ms,
                    "total_tokens": v.total_tokens,
                    "total_tool_calls": v.total_tool_calls,
                    "avg_turns": v.avg_turns,
                }
                for v in self.variants
            ],
            "split_strategy": self.split_strategy.value,
            "target_models": self.target_models,
            "target_agents": self.target_agents,
            "target_tools": self.target_tools,
            "max_requests": self.max_requests,
            "max_duration_seconds": self.max_duration_seconds,
            "min_sample_size": self.min_sample_size,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


@dataclass
class ExperimentConfig:
    """Configuration for experiments and task tracking."""

    max_experiments: int = 10
    default_min_sample_size: int = 30
    auto_stop_on_significance: bool = True
    significance_threshold: float = 0.95
    max_tracked_sessions: int = 5000
    idle_timeout_seconds: float = 300.0
    min_turns_for_success: int = 1
    consecutive_errors_threshold: int = 3


@dataclass
class TaskSession:
    """State of a tracked task/session."""

    session_id: str
    started_at: float
    last_activity: float
    turns: int = 0
    models_used: list[str] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_tool_calls: int = 0
    total_latency_ms: float = 0.0
    errors: int = 0
    consecutive_errors: int = 0
    loop_detected: bool = False
    was_escalated: bool = False
    stop_reasons: list[str] = field(default_factory=list)
    outcome: TaskOutcome = TaskOutcome.UNKNOWN
    experiment_id: str = ""
    variant_name: str = ""


class TaskCorrelations:
    """Accumulates correlation data between features and outcomes."""

    def __init__(self) -> None:
        self._by_model: dict[str, dict[str, Any]] = {}
        self._by_tool_count: dict[str, dict[str, Any]] = {}
        self._by_turn_count: dict[str, dict[str, Any]] = {}

    def _get_bucket(self, d: dict[str, dict], key: str) -> dict[str, Any]:
        if key not in d:
            d[key] = {"success": 0, "total": 0, "cost_sum": 0.0}
        return d[key]

    def record(self, session: TaskSession) -> None:
        success = session.outcome == TaskOutcome.SUCCESS
        model = session.models_used[-1] if session.models_used else "unknown"
        bucket_m = self._get_bucket(self._by_model, model)
        bucket_m["success"] += 1 if success else 0
        bucket_m["total"] += 1
        bucket_m["cost_sum"] += session.total_cost_usd

        tc = session.total_tool_calls
        tc_label = self._bucket_count(tc, [(2, "1-2"), (5, "3-5"), (999999, "5+")])
        bucket_tc = self._get_bucket(self._by_tool_count, tc_label)
        bucket_tc["success"] += 1 if success else 0
        bucket_tc["total"] += 1

        turns = session.turns
        turn_label = self._bucket_count(turns, [(3, "1-3"), (7, "4-7"), (999999, "8+")])
        bucket_t = self._get_bucket(self._by_turn_count, turn_label)
        bucket_t["success"] += 1 if success else 0
        bucket_t["total"] += 1

    @staticmethod
    def _bucket_count(n: int, thresholds: list[tuple[int, str]]) -> str:
        for thresh, label in thresholds:
            if n <= thresh:
                return label
        return thresholds[-1][1] if thresholds else "unknown"

    def compute(self) -> dict:
        by_model: dict[str, dict[str, Any]] = {}
        for model, data in self._by_model.items():
            total = data["total"]
            if total > 0:
                by_model[model] = {
                    "success_rate": data["success"] / total,
                    "avg_cost": data["cost_sum"] / total,
                    "sample": total,
                }

        by_tool_count: dict[str, dict[str, Any]] = {}
        for label, data in self._by_tool_count.items():
            total = data["total"]
            if total > 0:
                by_tool_count[label] = {"success_rate": data["success"] / total, "sample": total}

        by_turn_count: dict[str, dict[str, Any]] = {}
        for label, data in self._by_turn_count.items():
            total = data["total"]
            if total > 0:
                by_turn_count[label] = {"success_rate": data["success"] / total, "sample": total}

        insights: list[str] = []
        for label, data in by_tool_count.items():
            sr = data["success_rate"]
            sample = data["sample"]
            if sample >= 10:
                for other_label, other_data in by_tool_count.items():
                    if other_label != label and other_data["sample"] >= 10:
                        diff = abs(sr - other_data["success_rate"])
                        if diff >= 0.15:
                            insights.append(
                                f"Tasks with {label} tool calls have {sr:.0%} success rate vs "
                                f"{other_data['success_rate']:.0%} for {other_label}"
                            )
                        break
        for model, data in by_model.items():
            if data["sample"] >= 20:
                for other_model, other_data in by_model.items():
                    if other_model != model and other_data["sample"] >= 20:
                        diff = abs(data["success_rate"] - other_data["success_rate"])
                        if diff >= 0.1:
                            insights.append(
                                f"{model} success rate is {data['success_rate']:.0%} vs "
                                f"{other_data['success_rate']:.0%} for {other_model}"
                            )
                        break

        return {
            "by_model": by_model,
            "by_tool_count": by_tool_count,
            "by_turn_count": by_turn_count,
            "insights": insights[:10],
        }


class TaskTracker:
    """Proxy-level task completion tracking."""

    def __init__(self, config: Optional[ExperimentConfig] = None) -> None:
        self._config = config or ExperimentConfig()
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, TaskSession] = OrderedDict()
        self._outcome_stats: dict[str, int] = {}
        self._correlations = TaskCorrelations()
        self._max_sessions = self._config.max_tracked_sessions

    def record_turn(
        self,
        session_id: str,
        model: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
        latency_ms: float,
        tool_calls: int,
        stop_reason: str,
        is_error: bool,
        was_escalated: bool = False,
        was_loop_detected: bool = False,
        experiment_id: str = "",
        variant_name: str = "",
    ) -> None:
        now = time.time()
        with self._lock:
            if session_id not in self._sessions:
                if len(self._sessions) >= self._max_sessions:
                    self._sessions.popitem(last=False)
                self._sessions[session_id] = TaskSession(
                    session_id=session_id,
                    started_at=now,
                    last_activity=now,
                )
            s = self._sessions[session_id]
            s.last_activity = now
            s.turns += 1
            if model and model not in s.models_used:
                s.models_used.append(model)
            s.total_cost_usd += cost_usd
            s.total_tokens += tokens_in + tokens_out
            s.total_tool_calls += tool_calls
            s.total_latency_ms += latency_ms
            if stop_reason:
                s.stop_reasons.append(stop_reason)
            if is_error:
                s.errors += 1
                s.consecutive_errors += 1
            else:
                s.consecutive_errors = 0
            if was_loop_detected:
                s.loop_detected = True
            if was_escalated:
                s.was_escalated = True
            if experiment_id:
                s.experiment_id = experiment_id
            if variant_name:
                s.variant_name = variant_name

    def finalize_session(self, session_id: str) -> TaskOutcome:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return TaskOutcome.UNKNOWN
            if s.loop_detected:
                outcome = TaskOutcome.LOOP
            elif s.consecutive_errors >= self._config.consecutive_errors_threshold:
                outcome = TaskOutcome.FAILURE
            elif s.was_escalated:
                outcome = TaskOutcome.ESCALATED
            elif s.turns >= self._config.min_turns_for_success:
                last_stop = s.stop_reasons[-1] if s.stop_reasons else ""
                if last_stop == "end_turn" and s.total_tool_calls > 0:
                    outcome = TaskOutcome.SUCCESS
                else:
                    outcome = TaskOutcome.UNKNOWN
            elif s.turns < self._config.min_turns_for_success and not s.stop_reasons:
                outcome = TaskOutcome.ABANDONED
            else:
                outcome = TaskOutcome.UNKNOWN
            s.outcome = outcome
            self._outcome_stats[outcome.value] = self._outcome_stats.get(outcome.value, 0) + 1
            self._correlations.record(s)
            return outcome

    def get_session_state(self, session_id: str) -> Optional[TaskSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_outcome_distribution(self) -> dict[str, int]:
        with self._lock:
            return dict(self._outcome_stats)

    def get_correlations(self) -> dict:
        with self._lock:
            return self._correlations.compute()

    def get_stats(self) -> dict:
        with self._lock:
            total = sum(self._outcome_stats.values())
            successes = self._outcome_stats.get(TaskOutcome.SUCCESS.value, 0)
            return {
                "tracked_sessions": len(self._sessions),
                "outcomes": dict(self._outcome_stats),
                "overall_success_rate": successes / total if total > 0 else 0.0,
            }


class ExperimentManager:
    """Manages A/B experiments and task completion tracking."""

    def __init__(self, config: Optional[ExperimentConfig] = None) -> None:
        self._config = config or ExperimentConfig()
        self._lock = threading.Lock()
        self._experiments: dict[str, Experiment] = {}
        self._assignments: dict[str, str] = {}
        self._task_tracker = TaskTracker(config)
        self._rng = random.Random()

    def create_experiment(
        self,
        name: str,
        variants: list[dict],
        split_strategy: str = "sticky_session",
        **kwargs: Any,
    ) -> Experiment:
        with self._lock:
            if len(self._experiments) >= self._config.max_experiments:
                raise ValueError("max_experiments limit reached")
            exp_id = hashlib.sha256(f"{name}{time.time()}".encode()).hexdigest()[:16]
            parsed_variants: list[Variant] = []
            for v in variants:
                if isinstance(v, dict):
                    parsed_variants.append(
                        Variant(
                            name=str(v.get("name", "control")),
                            weight=float(v.get("weight", 0.5)),
                            model_override=str(v.get("model_override", "")),
                            config_overrides=dict(v.get("config_overrides", {})),
                        )
                    )
            total_weight = sum(v.weight for v in parsed_variants)
            if total_weight <= 0:
                total_weight = 1.0
            for v in parsed_variants:
                v.weight = v.weight / total_weight
            strategy = SplitStrategy.RANDOM
            for s in SplitStrategy:
                if s.value == split_strategy:
                    strategy = s
                    break
            exp = Experiment(
                experiment_id=exp_id,
                name=name,
                description=str(kwargs.get("description", "")),
                status=ExperimentStatus.DRAFT,
                variants=parsed_variants,
                split_strategy=strategy,
                target_models=list(kwargs.get("target_models", []) or []),
                target_agents=list(kwargs.get("target_agents", []) or []),
                target_tools=list(kwargs.get("target_tools", []) or []),
                max_requests=int(kwargs.get("max_requests", 0) or 0),
                max_duration_seconds=float(kwargs.get("max_duration_seconds", 0) or 0),
                min_sample_size=int(kwargs.get("min_sample_size", self._config.default_min_sample_size) or 30),
                created_at=time.time(),
            )
            self._experiments[exp_id] = exp
            return exp

    def start_experiment(self, experiment_id: str) -> bool:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                return False
            if exp.status == ExperimentStatus.RUNNING:
                return False
            if exp.status not in (ExperimentStatus.DRAFT, ExperimentStatus.PAUSED):
                return False
            exp.status = ExperimentStatus.RUNNING
            exp.started_at = time.time()
            return True

    def stop_experiment(self, experiment_id: str) -> ExperimentResult:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                raise ValueError("experiment not found")
            exp.status = ExperimentStatus.COMPLETED
            exp.ended_at = time.time()
        return self.get_results(experiment_id)

    def pause_experiment(self, experiment_id: str) -> bool:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None or exp.status != ExperimentStatus.RUNNING:
                return False
            exp.status = ExperimentStatus.PAUSED
            return True

    def resume_experiment(self, experiment_id: str) -> bool:
        return self.start_experiment(experiment_id)

    def delete_experiment(self, experiment_id: str) -> bool:
        with self._lock:
            if experiment_id in self._experiments:
                del self._experiments[experiment_id]
                keys_to_remove = [k for k, v in self._assignments.items() if v == experiment_id]
                for k in keys_to_remove:
                    del self._assignments[k]
                return True
            return False

    def list_experiments(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._experiments.values()]

    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        with self._lock:
            return self._experiments.get(experiment_id)

    def assign_variant(
        self,
        session_id: str,
        agent_id: str,
        model: str,
        tools: list[str],
    ) -> Optional[VariantAssignment]:
        with self._lock:
            active = [
                e
                for e in self._experiments.values()
                if e.status == ExperimentStatus.RUNNING
            ]
            if not active:
                return None
            exp = active[0]
            if exp.target_models and model not in exp.target_models:
                return None
            if exp.target_agents and agent_id not in exp.target_agents:
                return None
            if exp.target_tools:
                if not any(t in exp.target_tools for t in tools):
                    return None
            variant = self._weighted_choice(exp, session_id, agent_id)
            if variant is None:
                return None
            return VariantAssignment(
                experiment_id=exp.experiment_id,
                variant_name=variant.name,
                model_override=variant.model_override or "",
                config_overrides=variant.config_overrides or {},
            )

    def _weighted_choice(self, exp: Experiment, session_id: str, agent_id: str) -> Optional[Variant]:
        if not exp.variants:
            return None
        if exp.split_strategy == SplitStrategy.ROUND_ROBIN:
            exp._round_robin_counter += 1
            idx = (exp._round_robin_counter - 1) % len(exp.variants)
            return exp.variants[idx]
        seed = ""
        if exp.split_strategy == SplitStrategy.STICKY_SESSION:
            seed = session_id
        elif exp.split_strategy == SplitStrategy.STICKY_AGENT:
            seed = agent_id
        else:
            seed = hashlib.sha256(f"{time.time()}{session_id}{agent_id}".encode()).hexdigest()
        h = int(hashlib.sha256(seed.encode()).hexdigest(), 16) % 10000
        r = (h / 10000.0) if seed else self._rng.random()
        cumul = 0.0
        for v in exp.variants:
            cumul += v.weight
            if r < cumul:
                return v
        return exp.variants[-1]

    def record_request(
        self,
        experiment_id: str,
        variant_name: str,
        cost_usd: float,
        latency_ms: float,
        tokens: int,
        tool_calls: int,
        is_error: bool,
        success: bool | None = None,
        turns: int = 1,
    ) -> None:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                return
            for v in exp.variants:
                if v.name == variant_name:
                    v.requests += 1
                    v.total_cost_usd += cost_usd
                    v.total_latency_ms += latency_ms
                    v.total_tokens += tokens
                    v.total_tool_calls += tool_calls
                    if is_error:
                        v.failures += 1
                    elif success is True:
                        v.successes += 1
                    elif success is None and not is_error:
                        v.successes += 1
                    v._turns_sum += turns
                    v._tasks_completed += 1 if (success is True or (success is None and not is_error)) else 0
                    if v._tasks_completed > 0:
                        v.avg_turns = v._turns_sum / v._tasks_completed
                    if self._check_auto_stop(exp):
                        exp.status = ExperimentStatus.COMPLETED
                        exp.ended_at = time.time()
                    break

    def record_task_outcome(
        self,
        experiment_id: str,
        variant_name: str,
        outcome: TaskOutcome,
    ) -> None:
        """Update variant success/failure from task completion outcome."""
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                return
            for v in exp.variants:
                if v.name == variant_name:
                    if outcome == TaskOutcome.SUCCESS:
                        v.successes += 1
                    elif outcome in (
                        TaskOutcome.FAILURE,
                        TaskOutcome.LOOP,
                        TaskOutcome.TIMEOUT,
                        TaskOutcome.ABANDONED,
                    ):
                        v.failures += 1
                    break

    def _check_auto_stop(self, exp: Experiment) -> bool:
        if exp.max_requests > 0:
            total = sum(v.requests for v in exp.variants)
            if total >= exp.max_requests:
                return True
        if exp.max_duration_seconds > 0 and exp.started_at > 0:
            if time.time() - exp.started_at >= exp.max_duration_seconds:
                return True
        if self._config.auto_stop_on_significance and len(exp.variants) >= 2:
            r = self.get_results(exp.experiment_id)
            if r.is_significant:
                return True
        return False

    @staticmethod
    def _z_test_proportions(
        successes1: int,
        n1: int,
        successes2: int,
        n2: int,
    ) -> tuple[float, float]:
        if n1 <= 0 or n2 <= 0:
            return 0.0, 1.0
        p1 = successes1 / n1
        p2 = successes2 / n2
        p_pooled = (successes1 + successes2) / (n1 + n2)
        if p_pooled <= 0 or p_pooled >= 1:
            return 0.0, 1.0
        denom = math.sqrt(p_pooled * (1 - p_pooled) * (1 / n1 + 1 / n2))
        if denom <= 0:
            return 0.0, 1.0
        z = (p1 - p2) / denom
        p_value = 2 * (1 - _normal_cdf(abs(z)))
        return z, p_value

    def get_results(self, experiment_id: str) -> ExperimentResult:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                raise ValueError("experiment not found")
        variants_stats: dict[str, VariantStats] = {}
        latencies: dict[str, list[float]] = {}
        for v in exp.variants:
            n = v.requests
            if n == 0:
                variants_stats[v.name] = VariantStats(
                    name=v.name,
                    sample_size=0,
                    success_rate=0.0,
                    avg_cost_usd=0.0,
                    avg_latency_ms=0.0,
                    avg_tokens=0,
                    avg_tool_calls=0.0,
                    avg_turns=0.0,
                    p95_latency_ms=0.0,
                    error_rate=0.0,
                    cost_per_success=0.0,
                )
                continue
            sr = (v.successes / n) if n > 0 else 0.0
            err_rate = (v.failures / n) if n > 0 else 0.0
            avg_cost = (v.total_cost_usd / n) if n > 0 else 0.0
            avg_lat = (v.total_latency_ms / n) if n > 0 else 0.0
            avg_tok = int(v.total_tokens / n) if n > 0 else 0
            avg_tc = (v.total_tool_calls / n) if n > 0 else 0.0
            avg_t = v.avg_turns
            cps = (v.total_cost_usd / v.successes) if v.successes > 0 else 0.0
            variants_stats[v.name] = VariantStats(
                name=v.name,
                sample_size=n,
                success_rate=sr,
                avg_cost_usd=avg_cost,
                avg_latency_ms=avg_lat,
                avg_tokens=avg_tok,
                avg_tool_calls=avg_tc,
                avg_turns=avg_t,
                p95_latency_ms=avg_lat,
                error_rate=err_rate,
                cost_per_success=cps,
            )
            latencies[v.name] = []

        is_sig = False
        winner = ""
        confidence = 0.0
        if len(exp.variants) >= 2:
            v0, v1 = exp.variants[0], exp.variants[1]
            n0, n1 = v0.requests, v1.requests
            if n0 >= exp.min_sample_size and n1 >= exp.min_sample_size:
                z, p = self._z_test_proportions(v0.successes, n0, v1.successes, n1)
                confidence = 1.0 - p
                if p < (1 - self._config.significance_threshold):
                    is_sig = True
                    winner = v0.name if v0.successes / max(1, n0) > v1.successes / max(1, n1) else v1.name

        best = max(exp.variants, key=lambda v: (v.successes / max(1, v.requests), -v.total_cost_usd))
        if not winner:
            winner = best.name
        rec = f"Variant {winner} shows best performance."
        if is_sig:
            rec = f"Statistically significant: {winner} is recommended (confidence {confidence:.2%})."
        cost_comp = ""
        if len(exp.variants) >= 2:
            v0, v1 = exp.variants[0], exp.variants[1]
            diff = (v1.total_cost_usd - v0.total_cost_usd) / max(1, v0.requests + v1.requests) * 1000
            cost_comp = f"Variant {v1.name} costs ${abs(diff):.4f} {'more' if diff > 0 else 'less'} per 1000 requests vs {v0.name}"
        return ExperimentResult(
            experiment_id=experiment_id,
            is_significant=is_sig,
            winner=winner,
            confidence=confidence,
            variants=variants_stats,
            recommendation=rec,
            cost_comparison=cost_comp,
        )

    def get_live_stats(self, experiment_id: str) -> dict:
        with self._lock:
            exp = self._experiments.get(experiment_id)
            if exp is None:
                return {}
        result = self.get_results(experiment_id)
        return {
            "experiment_id": experiment_id,
            "status": exp.status.value,
            "variants": {
                k: asdict(v) for k, v in result.variants.items()
            },
            "is_significant": result.is_significant,
            "winner": result.winner,
        }


def _normal_cdf(z: float) -> float:
    """Standard normal CDF using math.erf."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))
