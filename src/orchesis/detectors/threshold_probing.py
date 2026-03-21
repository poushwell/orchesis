"""
Threshold Probing Detector - detects agents systematically
testing policy limits to discover enforcement boundaries.

Patterns detected:
1. Linear probing: values increase by constant delta
2. Binary search probing: values converge on threshold
3. Boundary testing: rapid oscillation near a limit

Usage:
    detector = ThresholdProbingDetector()
    detector.record_attempt(agent_id, metric="token_count", value=100)
    detector.record_attempt(agent_id, metric="token_count", value=200)
    detector.record_attempt(agent_id, metric="token_count", value=300)
    result = detector.check(agent_id)
    # result.probing_detected == True, pattern == "linear"
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class ProbingAttempt:
    agent_id: str
    metric: str
    value: float
    timestamp: float
    was_blocked: bool = False


@dataclass
class ProbingResult:
    probing_detected: bool = False
    pattern: str = ""
    confidence: float = 0.0
    metric: str = ""
    agent_id: str = ""
    attempt_count: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


class ThresholdProbingDetector:
    def __init__(self, window_seconds: float = 600, min_attempts: int = 3):
        self.window_seconds = float(window_seconds)
        self.min_attempts = int(min_attempts)
        self._attempts: dict[str, list[ProbingAttempt]] = {}

    def record_attempt(
        self,
        agent_id,
        metric,
        value,
        was_blocked: bool = False,
    ) -> None:
        """Record a policy-relevant attempt."""
        aid = str(agent_id or "unknown")
        metric_name = str(metric or "")
        attempt = ProbingAttempt(
            agent_id=aid,
            metric=metric_name,
            value=float(value),
            timestamp=time.time(),
            was_blocked=bool(was_blocked),
        )
        self._attempts.setdefault(aid, []).append(attempt)
        self._trim_window(aid)

    def check(self, agent_id) -> ProbingResult:
        """Check if agent is probing thresholds."""
        aid = str(agent_id or "unknown")
        self._trim_window(aid)
        rows = self._attempts.get(aid, [])
        if not rows:
            return ProbingResult(agent_id=aid)

        by_metric: dict[str, list[ProbingAttempt]] = {}
        for row in rows:
            by_metric.setdefault(row.metric, []).append(row)

        best = ProbingResult(agent_id=aid)
        for metric_name, attempts in by_metric.items():
            attempts.sort(key=lambda x: x.timestamp)
            if len(attempts) < self.min_attempts:
                continue

            values = [a.value for a in attempts]
            blocked = [a.was_blocked for a in attempts]
            local_best = self._best_pattern(values, blocked)
            if not local_best.probing_detected:
                continue
            local_best.metric = metric_name
            local_best.agent_id = aid
            local_best.attempt_count = len(attempts)
            if local_best.confidence > best.confidence:
                best = local_best

        if best.probing_detected:
            best.recommendation = (
                "Potential threshold probing detected. Increase randomization around limits, "
                "apply stricter per-agent rate limits, and review this agent's denied attempts."
            )
            logger.warning(
                "Threshold probing pattern detected",
                extra={
                    "component": "threshold_probing",
                    "agent_id": aid,
                    "metric": best.metric,
                    "pattern": best.pattern,
                    "confidence": best.confidence,
                    "attempt_count": best.attempt_count,
                },
            )
        return best

    def _best_pattern(self, values: list[float], blocked: list[bool]) -> ProbingResult:
        linear_detected, linear_conf = self._check_linear(values)
        binary_detected, binary_conf = self._check_binary_search(values)
        boundary_detected, boundary_conf = self._check_boundary_oscillation(values, blocked)

        candidates: list[tuple[str, float, dict[str, Any]]] = []
        if linear_detected:
            deltas = [values[i] - values[i - 1] for i in range(1, len(values))]
            candidates.append(
                (
                    "linear",
                    linear_conf,
                    {
                        "values": values,
                        "deltas": deltas,
                    },
                )
            )
        if binary_detected:
            abs_deltas = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
            ratios = []
            for i in range(1, len(abs_deltas)):
                if abs_deltas[i - 1] <= 0.0:
                    continue
                ratios.append(abs_deltas[i] / abs_deltas[i - 1])
            candidates.append(
                (
                    "binary_search",
                    binary_conf,
                    {
                        "values": values,
                        "abs_deltas": abs_deltas,
                        "ratios": ratios,
                    },
                )
            )
        if boundary_detected:
            candidates.append(
                (
                    "boundary_oscillation",
                    boundary_conf,
                    {
                        "values": values,
                        "blocked": blocked,
                        "spread": max(values) - min(values),
                    },
                )
            )

        if not candidates:
            return ProbingResult(probing_detected=False)

        pattern, confidence, evidence = max(candidates, key=lambda row: row[1])
        return ProbingResult(
            probing_detected=True,
            pattern=pattern,
            confidence=confidence,
            evidence=evidence,
        )

    def _check_linear(self, values: list[float]) -> tuple[bool, float]:
        """Check for linear probing pattern. Returns (detected, confidence)."""
        if len(values) < max(3, self.min_attempts):
            return (False, 0.0)
        deltas = [values[i] - values[i - 1] for i in range(1, len(values))]
        if not deltas:
            return (False, 0.0)

        signs = [1 if d > 0 else (-1 if d < 0 else 0) for d in deltas]
        non_zero = [s for s in signs if s != 0]
        if not non_zero:
            return (False, 0.0)
        dominant_sign_count = max(non_zero.count(1), non_zero.count(-1))
        sign_consistency = dominant_sign_count / float(len(non_zero))
        if sign_consistency < 0.8:
            return (False, 0.0)

        magnitudes = [abs(d) for d in deltas if abs(d) > 0]
        if not magnitudes:
            return (False, 0.0)
        mean_delta = sum(magnitudes) / len(magnitudes)
        if mean_delta <= 1e-12:
            return (False, 0.0)
        variance = sum((d - mean_delta) ** 2 for d in magnitudes) / len(magnitudes)
        std = math.sqrt(variance)
        cv = std / mean_delta
        if cv >= 0.3:
            return (False, 0.0)

        confidence = max(0.0, min(1.0, 1.0 - (cv / 0.3) * 0.5))
        confidence = min(1.0, confidence * (0.8 + 0.2 * sign_consistency))
        return (confidence >= 0.65, confidence)

    def _check_binary_search(self, values: list[float]) -> tuple[bool, float]:
        """Check for binary search pattern."""
        if len(values) < max(5, self.min_attempts):
            return (False, 0.0)

        abs_deltas = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
        if len(abs_deltas) < 3:
            return (False, 0.0)
        if any(delta <= 0.0 for delta in abs_deltas):
            return (False, 0.0)

        ratios: list[float] = []
        for idx in range(1, len(abs_deltas)):
            prev_delta = abs_deltas[idx - 1]
            if prev_delta <= 0.0:
                continue
            ratios.append(abs_deltas[idx] / prev_delta)
        if len(ratios) < 2:
            return (False, 0.0)

        mean_ratio = sum(ratios) / len(ratios)
        distance = abs(mean_ratio - 0.5)
        if distance > 0.2:
            return (False, 0.0)

        variance = sum((r - mean_ratio) ** 2 for r in ratios) / len(ratios)
        std = math.sqrt(variance)
        if std > 0.2:
            return (False, 0.0)

        confidence = max(0.0, min(1.0, 1.0 - (distance / 0.2) * 0.6 - std * 0.5))
        return (confidence >= 0.65, confidence)

    def _check_boundary_oscillation(
        self,
        values: list[float],
        blocked: list[bool],
    ) -> tuple[bool, float]:
        """Check for boundary oscillation pattern."""
        if len(values) < max(4, self.min_attempts):
            return (False, 0.0)
        if len(blocked) != len(values):
            return (False, 0.0)

        mean_value = sum(values) / len(values)
        if abs(mean_value) <= 1e-12:
            return (False, 0.0)
        spread = max(values) - min(values)
        spread_ratio = spread / abs(mean_value)
        if spread_ratio >= 0.1:
            return (False, 0.0)

        transitions = 0
        for idx in range(1, len(blocked)):
            if blocked[idx] != blocked[idx - 1]:
                transitions += 1
        max_transitions = len(blocked) - 1
        if max_transitions <= 0:
            return (False, 0.0)
        alternating_ratio = transitions / float(max_transitions)
        if alternating_ratio < 0.75:
            return (False, 0.0)

        confidence = max(
            0.0,
            min(
                1.0,
                0.65 + (0.1 - spread_ratio) * 2.0 + (alternating_ratio - 0.75) * 0.7,
            ),
        )
        return (confidence >= 0.7, confidence)

    def clear(self, agent_id=None) -> None:
        """Clear history for agent or all."""
        if agent_id is None:
            self._attempts.clear()
            return
        self._attempts.pop(str(agent_id), None)

    def get_attempts(self, agent_id) -> list[ProbingAttempt]:
        """Get recorded attempts for agent."""
        aid = str(agent_id or "unknown")
        self._trim_window(aid)
        return list(self._attempts.get(aid, []))

    def _trim_window(self, agent_id: str) -> None:
        now = time.time()
        cutoff = now - self.window_seconds
        rows = self._attempts.get(agent_id, [])
        if not rows:
            return
        self._attempts[agent_id] = [row for row in rows if row.timestamp >= cutoff]

