"""Session-level risk accumulation with composite scoring and escalation."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import threading
import time
from typing import Any


@dataclass
class RiskSignal:
    """A single risk signal observed in a request."""

    category: str
    confidence: float
    severity: str
    source: str
    description: str
    timestamp: float = 0.0


@dataclass
class SessionRiskState:
    """Accumulated risk state for a single session."""

    session_id: str
    signals: list[RiskSignal] = field(default_factory=list)
    composite_score: float = 0.0
    unique_categories: set[str] = field(default_factory=set)
    escalation_level: str = "observe"
    last_updated: float = 0.0
    request_count: int = 0


@dataclass
class RiskAssessment:
    """Result of evaluating a request against session risk."""

    action: str
    composite_score: float
    escalation_level: str
    reason: str
    contributing_signals: list[dict[str, Any]] = field(default_factory=list)
    unique_categories: int = 0
    total_signals: int = 0


class SessionRiskAccumulator:
    """Per-session risk scoring with time decay and escalation."""

    def __init__(
        self,
        warn_threshold: float = 30.0,
        block_threshold: float = 60.0,
        decay_half_life_seconds: float = 300.0,
        max_signals_per_session: int = 100,
        session_ttl_seconds: float = 3600.0,
        category_diversity_bonus: float = 10.0,
        enabled: bool = True,
    ) -> None:
        self._warn_threshold = max(0.0, float(warn_threshold))
        self._block_threshold = max(self._warn_threshold, float(block_threshold))
        self._decay_half_life = max(1.0, float(decay_half_life_seconds))
        self._max_signals = max(10, int(max_signals_per_session))
        self._session_ttl = max(60.0, float(session_ttl_seconds))
        self._category_diversity_bonus = max(0.0, float(category_diversity_bonus))
        self._enabled = bool(enabled)

        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRiskState] = {}
        self._stats = {
            "total_evaluations": 0,
            "escalations_warn": 0,
            "escalations_block": 0,
            "sessions_tracked": 0,
            "signals_recorded": 0,
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    def record_signal(self, session_id: str, signal: RiskSignal) -> None:
        """Record a risk signal for a session."""
        if not self._enabled:
            return
        now = time.monotonic()
        signal.timestamp = signal.timestamp or now

        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                state = SessionRiskState(session_id=session_id)
                self._sessions[session_id] = state
                self._stats["sessions_tracked"] += 1

            state.signals.append(signal)
            if len(state.signals) > self._max_signals:
                state.signals = state.signals[-self._max_signals :]

            state.unique_categories.add(signal.category)
            state.last_updated = now
            state.request_count += 1
            self._stats["signals_recorded"] += 1
            state.composite_score = self._compute_score_locked(state, now)

            old_level = state.escalation_level
            if state.composite_score >= self._block_threshold:
                state.escalation_level = "block"
            elif state.composite_score >= self._warn_threshold:
                state.escalation_level = "warn"
            else:
                state.escalation_level = "observe"

            if old_level != state.escalation_level:
                if state.escalation_level == "warn":
                    self._stats["escalations_warn"] += 1
                elif state.escalation_level == "block":
                    self._stats["escalations_block"] += 1

    def evaluate(self, session_id: str) -> RiskAssessment:
        """Evaluate current risk level for a session."""
        if not self._enabled:
            return RiskAssessment(
                action="allow",
                composite_score=0.0,
                escalation_level="observe",
                reason="disabled",
            )

        now = time.monotonic()
        with self._lock:
            self._stats["total_evaluations"] += 1
            self._cleanup_expired_locked(now)

            state = self._sessions.get(session_id)
            if state is None:
                return RiskAssessment(
                    action="allow",
                    composite_score=0.0,
                    escalation_level="observe",
                    reason="no signals",
                )

            state.composite_score = self._compute_score_locked(state, now)

            action = "allow"
            reason = f"score {state.composite_score:.1f}"
            if state.composite_score >= self._block_threshold:
                action = "block"
                reason = (
                    f"session risk score {state.composite_score:.1f} >= "
                    f"{self._block_threshold} (block threshold)"
                )
            elif state.composite_score >= self._warn_threshold:
                action = "warn"
                reason = (
                    f"session risk score {state.composite_score:.1f} >= "
                    f"{self._warn_threshold} (warn threshold)"
                )

            if action == "block":
                state.escalation_level = "block"
            elif action == "warn" and state.escalation_level == "observe":
                state.escalation_level = "warn"

            contributing = []
            for sig in state.signals[-10:]:
                contributing.append(
                    {
                        "category": sig.category,
                        "confidence": round(sig.confidence, 2),
                        "severity": sig.severity,
                        "source": sig.source,
                        "description": sig.description,
                        "age_seconds": round(now - sig.timestamp, 1),
                    }
                )

            return RiskAssessment(
                action=action,
                composite_score=round(state.composite_score, 2),
                escalation_level=state.escalation_level,
                reason=reason,
                contributing_signals=contributing,
                unique_categories=len(state.unique_categories),
                total_signals=len(state.signals),
            )

    def _compute_score_locked(self, state: SessionRiskState, now: float) -> float:
        severity_weights = {
            "info": 2.0,
            "low": 5.0,
            "medium": 12.0,
            "high": 20.0,
            "critical": 35.0,
        }

        total = 0.0
        for signal in state.signals:
            age = max(0.0, now - signal.timestamp)
            decay = math.pow(2.0, -age / self._decay_half_life)
            weight = severity_weights.get(str(signal.severity).lower(), 5.0)
            confidence = max(0.0, min(1.0, float(signal.confidence)))
            total += weight * confidence * decay

        num_categories = len(state.unique_categories)
        if num_categories > 1:
            total += self._category_diversity_bonus * (num_categories - 1)

        return min(100.0, total)

    def _cleanup_expired_locked(self, now: float) -> None:
        expired = [
            sid
            for sid, state in self._sessions.items()
            if (now - state.last_updated) > self._session_ttl
        ]
        for sid in expired:
            del self._sessions[sid]

    def get_session_state(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None
            return {
                "session_id": state.session_id,
                "composite_score": round(state.composite_score, 2),
                "escalation_level": state.escalation_level,
                "unique_categories": sorted(state.unique_categories),
                "total_signals": len(state.signals),
                "request_count": state.request_count,
                "last_updated": state.last_updated,
            }

    def reset_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "active_sessions": len(self._sessions),
                "warn_threshold": self._warn_threshold,
                "block_threshold": self._block_threshold,
            }
