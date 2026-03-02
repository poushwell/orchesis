"""State drift detector for runtime anomaly checks."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.engine import evaluate
from orchesis.replay import ReplayEngine, read_events_from_jsonl
from orchesis.state import DEFAULT_SESSION_ID, RateLimitTracker
from orchesis.telemetry import DecisionEvent


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class DriftEvent:
    timestamp: str
    agent_id: str
    drift_type: str
    expected: str
    actual: str
    severity: str


class DriftDetector:
    """Detects state drift and runtime anomalies."""

    def __init__(self) -> None:
        self._events: list[DriftEvent] = []
        self._baseline_latency: float | None = None
        self._last_replay_sample_size: int = 0

    def _record(
        self,
        *,
        agent_id: str,
        drift_type: str,
        expected: str,
        actual: str,
        severity: str,
    ) -> DriftEvent:
        event = DriftEvent(
            timestamp=_now_iso(),
            agent_id=agent_id,
            drift_type=drift_type,
            expected=expected,
            actual=actual,
            severity=severity,
        )
        self._events.append(event)
        return event

    def check_counter_integrity(
        self,
        tracker: RateLimitTracker,
        agent_id: str,
        tool: str,
        expected_count: int,
    ) -> DriftEvent | None:
        """Verify rate limit counter matches expected value."""
        actual_count = tracker.get_count(
            tool_name=tool,
            window_seconds=86400,
            agent_id=agent_id,
            session_id=DEFAULT_SESSION_ID,
        )
        if actual_count == expected_count:
            return None
        delta = abs(actual_count - expected_count)
        severity = "medium" if delta <= 1 else "high"
        return self._record(
            agent_id=agent_id,
            drift_type="counter_mismatch",
            expected=str(expected_count),
            actual=str(actual_count),
            severity=severity,
        )

    def check_budget_integrity(
        self,
        tracker: RateLimitTracker,
        agent_id: str,
        expected_spent: float,
    ) -> DriftEvent | None:
        """Verify budget spent matches expected value."""
        actual_spent = tracker.get_agent_budget_spent(
            agent_id=agent_id,
            window_seconds=86400,
            session_id=DEFAULT_SESSION_ID,
        )
        if abs(actual_spent - expected_spent) < 1e-9:
            return None
        delta = abs(actual_spent - expected_spent)
        severity = "medium" if delta <= 0.01 else "high"
        return self._record(
            agent_id=agent_id,
            drift_type="budget_mismatch",
            expected=f"{expected_spent:.6f}",
            actual=f"{actual_spent:.6f}",
            severity=severity,
        )

    def check_replay_consistency(
        self,
        event: DecisionEvent,
        policy: dict[str, Any],
        registry=None,  # noqa: ANN001
    ) -> DriftEvent | None:
        """Replay one decision and check for divergence."""
        _ = registry  # Reserved for future identity-aware replay.
        result = ReplayEngine().replay_event(event, policy, strict=True)
        if result.match:
            return None
        drift_detail = (
            result.drift_reasons[0] if result.drift_reasons else f"original={event.decision}"
        )
        return self._record(
            agent_id=event.agent_id,
            drift_type="replay_divergence",
            expected=event.decision,
            actual=drift_detail,
            severity="critical",
        )

    def check_latency_anomaly(self, duration_us: int) -> DriftEvent | None:
        """Detect latency spikes (>10x baseline)."""
        if duration_us <= 0:
            return None
        if self._baseline_latency is None:
            self._baseline_latency = float(duration_us)
            return None
        baseline = max(self._baseline_latency, 1.0)
        if duration_us > baseline * 10.0:
            return self._record(
                agent_id="__runtime__",
                drift_type="latency_spike",
                expected=f"<= {baseline * 10.0:.0f}us",
                actual=f"{duration_us}us",
                severity="medium",
            )
        self._baseline_latency = (baseline * 0.95) + (float(duration_us) * 0.05)
        return None

    def check_decision_consistency(
        self,
        request: dict[str, Any],
        policy: dict[str, Any],
        expected_allowed: bool,
        registry=None,  # noqa: ANN001
    ) -> DriftEvent | None:
        """Verify a known request produces expected decision."""
        decision = evaluate(
            request,
            policy,
            state=RateLimitTracker(persist_path=None),
            registry=registry,
        )
        if decision.allowed == expected_allowed:
            return None
        drift_type = "unexpected_allow" if decision.allowed else "unexpected_deny"
        expected = "ALLOW" if expected_allowed else "DENY"
        actual = "ALLOW" if decision.allowed else "DENY"
        severity = "critical" if drift_type == "unexpected_allow" else "high"
        context = request.get("context")
        agent_id = (
            context.get("agent", "__global__") if isinstance(context, dict) else "__global__"
        )
        return self._record(
            agent_id=str(agent_id),
            drift_type=drift_type,
            expected=expected,
            actual=actual,
            severity=severity,
        )

    def run_all_checks(
        self,
        tracker: RateLimitTracker,
        policy: dict[str, Any],
        decisions_log: str | Path,
        registry=None,  # noqa: ANN001
    ) -> list[DriftEvent]:
        """Run all drift checks. Returns list of drift events."""
        _ = tracker
        path = Path(decisions_log)
        events = read_events_from_jsonl(path)
        if not events:
            self._last_replay_sample_size = 0
            return list(self._events)

        rng = random.Random(42)
        sample_size = min(100, len(events))
        self._last_replay_sample_size = sample_size
        sampled = [events[idx] for idx in rng.sample(range(len(events)), sample_size)]
        for item in sampled:
            self.check_latency_anomaly(item.evaluation_duration_us)
            self.check_replay_consistency(item, policy, registry=registry)
        return list(self._events)

    @property
    def baseline_latency_us(self) -> float | None:
        return self._baseline_latency

    @property
    def replay_sample_size(self) -> int:
        return self._last_replay_sample_size

    @property
    def events(self) -> list[DriftEvent]:
        return list(self._events)

    @property
    def has_critical_drift(self) -> bool:
        return any(event.severity == "critical" for event in self._events)
