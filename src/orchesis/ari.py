"""Agent Readiness Index (ARI) - forward-looking production readiness."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

from orchesis.ars import ARSResult


@dataclass
class ReadinessDimension:
    name: str
    score: float
    weight: int
    status: str
    details: str
    blocking: bool


@dataclass
class ReadinessResult:
    agent_id: str
    index: float
    verdict: str
    dimensions: list[ReadinessDimension]
    blocking_failures: list[str]
    recommendations: list[str]
    computed_at: float
    ars_score: float | None
    confidence: str


class AgentReadinessIndex:
    """Compute production readiness from ARS and/or explicit metrics."""

    DEFAULT_WEIGHTS = {
        "security_posture": 25,
        "cost_predictability": 20,
        "task_reliability": 20,
        "loop_safety": 15,
        "latency_profile": 10,
        "observability": 10,
    }

    DEFAULT_THRESHOLDS = {
        "security_posture": {"pass": 80.0, "warn": 60.0},
        "cost_predictability": {"pass": 70.0, "warn": 50.0},
        "task_reliability": {"pass": 75.0, "warn": 55.0},
        "loop_safety": {"pass": 85.0, "warn": 70.0},
        "latency_profile": {"pass": 70.0, "warn": 50.0},
        "observability": {"pass": 60.0, "warn": 40.0},
    }

    _BLOCKING = {"security_posture", "cost_predictability", "task_reliability"}

    def __init__(
        self,
        weights: dict[str, int] | None = None,
        thresholds: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self._weights = dict(self.DEFAULT_WEIGHTS)
        if isinstance(weights, dict):
            for name, value in weights.items():
                if name in self._weights and isinstance(value, int | float):
                    self._weights[name] = int(value)

        self._thresholds = {
            name: {"pass": cfg["pass"], "warn": cfg["warn"]} for name, cfg in self.DEFAULT_THRESHOLDS.items()
        }
        if isinstance(thresholds, dict):
            for name, cfg in thresholds.items():
                if name not in self._thresholds or not isinstance(cfg, dict):
                    continue
                pass_value = cfg.get("pass", self._thresholds[name]["pass"])
                warn_value = cfg.get("warn", self._thresholds[name]["warn"])
                try:
                    self._thresholds[name]["pass"] = float(pass_value)
                    self._thresholds[name]["warn"] = float(warn_value)
                except (TypeError, ValueError):
                    continue

    def evaluate(
        self,
        agent_id: str,
        ars_result: ARSResult | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        metrics = metrics or {}
        components = ars_result.components if ars_result is not None else {}

        raw_scores = {
            "security_posture": self._coerce_score(
                components.get("security_compliance"), metrics.get("security_score", 50.0)
            ),
            "cost_predictability": self._coerce_score(components.get("cost_efficiency"), metrics.get("cost_score", 50.0)),
            "task_reliability": self._coerce_score(components.get("task_completion"), metrics.get("task_score", 50.0)),
            "loop_safety": self._coerce_score(components.get("loop_freedom"), metrics.get("loop_score", 50.0)),
            "latency_profile": self._coerce_score(components.get("latency_health"), metrics.get("latency_score", 50.0)),
            "observability": self._coerce_score(components.get("context_stability"), metrics.get("obs_score", 50.0)),
        }

        dimensions: list[ReadinessDimension] = []
        recommendations: list[str] = []
        blocking_failures: list[str] = []

        for name in self.DEFAULT_WEIGHTS:
            score = raw_scores[name]
            status = self._status_for(name, score)
            blocking = name in self._BLOCKING
            details = (
                f"score={score:.1f}, pass>={self._thresholds[name]['pass']:.0f}, "
                f"warn>={self._thresholds[name]['warn']:.0f}"
            )
            dimensions.append(
                ReadinessDimension(
                    name=name,
                    score=score,
                    weight=int(self._weights.get(name, 0)),
                    status=status,
                    details=details,
                    blocking=blocking,
                )
            )
            if blocking and status == "fail":
                blocking_failures.append(name)
            recommendations.extend(self._recommendations_for(name, status))

        total_weight = sum(max(0, int(dim.weight)) for dim in dimensions) or 1
        index = sum(dim.score * max(0, int(dim.weight)) / total_weight for dim in dimensions)
        index = round(index, 2)

        if blocking_failures:
            verdict = "NOT_READY"
        elif index >= 75:
            verdict = "READY"
        else:
            verdict = "CONDITIONAL"

        deduped_recommendations = list(dict.fromkeys(recommendations))

        confidence = "low"
        ars_score: float | None = None
        if ars_result is not None:
            confidence = ars_result.confidence if ars_result.confidence in {"high", "medium", "low"} else "low"
            ars_score = ars_result.score

        return ReadinessResult(
            agent_id=agent_id,
            index=index,
            verdict=verdict,
            dimensions=dimensions,
            blocking_failures=blocking_failures,
            recommendations=deduped_recommendations,
            computed_at=time.time(),
            ars_score=ars_score,
            confidence=confidence,
        )

    def batch_evaluate(self, agents: list[dict[str, Any]]) -> list[ReadinessResult]:
        results: list[ReadinessResult] = []
        for item in agents:
            agent_id = str(item.get("agent_id", "") or "")
            if not agent_id:
                continue
            results.append(
                self.evaluate(
                    agent_id=agent_id,
                    ars_result=item.get("ars_result"),
                    metrics=item.get("metrics"),
                )
            )
        return results

    def get_summary(self, results: list[ReadinessResult]) -> dict[str, Any]:
        total = len(results)
        ready = sum(1 for r in results if r.verdict == "READY")
        conditional = sum(1 for r in results if r.verdict == "CONDITIONAL")
        not_ready = sum(1 for r in results if r.verdict == "NOT_READY")
        avg_index = round(sum(r.index for r in results) / total, 2) if total else 0.0

        counter = Counter()
        for result in results:
            counter.update(result.blocking_failures)
        top_blocking_dimensions = [name for name, _count in counter.most_common()]

        return {
            "total": total,
            "ready": ready,
            "conditional": conditional,
            "not_ready": not_ready,
            "avg_index": avg_index,
            "top_blocking_dimensions": top_blocking_dimensions,
        }

    @staticmethod
    def _coerce_score(primary: Any, fallback: Any) -> float:
        value = fallback if primary is None else primary
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 50.0
        return max(0.0, min(100.0, numeric))

    def _status_for(self, dimension: str, score: float) -> str:
        pass_cutoff = self._thresholds[dimension]["pass"]
        warn_cutoff = self._thresholds[dimension]["warn"]
        if score >= pass_cutoff:
            return "pass"
        if score >= warn_cutoff:
            return "warn"
        return "fail"

    @staticmethod
    def _recommendations_for(dimension: str, status: str) -> list[str]:
        if status == "pass":
            return []
        if dimension == "security_posture" and status == "fail":
            return ["Reduce threat rate below 20%", "Review tool policies"]
        if dimension == "cost_predictability" and status == "fail":
            return ["Set budget ceiling", "Enable cost velocity alerts"]
        if dimension == "task_reliability" and status == "fail":
            return ["Improve session success rate above 75%"]
        if dimension == "loop_safety":
            return ["Enable loop detection", "Set max_iterations limit"]
        if dimension == "latency_profile":
            return ["Check upstream LLM latency", "Consider model routing"]
        if dimension == "observability":
            return ["Enable session recording", "Add Flow X-Ray tracing"]
        return []

