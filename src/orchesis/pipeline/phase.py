"""Phase base class and per-phase tracking wrapper.

A Phase declares its contract via ClassVars:
    name, version, core_compat
    after, before, parallel_group      — ordering
    reads, writes_processed, appends_tracking  — state contract
    PRODUCES_HAZARDS                   — hazard signal whitelist
    failure_mode, timeout_seconds, has_external_side_effects  — operational

The engine wraps `ctx.tracking` in a `ScopedTracking` before calling
`execute()`. ScopedTracking enforces that:
    - decisions are stamped with the phase name
    - tracking lists declared in `appends_tracking` can be appended to
    - hazard event types are in PRODUCES_HAZARDS
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, Mapping

from orchesis.pipeline.context import (
    Decision,
    DeviationEvent,
    PhaseTimings,
    RequestContext,
    Tracking,
)


PhaseStatus = Literal["pass", "modify", "block", "skip", "retry"]
FailureMode = Literal["fail_fast", "fail_soft", "fail_skip"]

# Tracking lists that can appear in `appends_tracking`.
_TRACKING_KINDS = frozenset({"decisions", "deviations", "timings", "metrics"})


class ContractViolation(Exception):
    """Raised when a phase violates its declared contract.

    Examples:
      - Phase emits a decision under another phase's name.
      - Phase appends to a tracking list not declared in `appends_tracking`.
      - Phase emits a hazard event_type not in PRODUCES_HAZARDS.
    """

    def __init__(self, phase_name: str, detail: str):
        super().__init__(f"phase {phase_name!r}: {detail}")
        self.phase_name = phase_name
        self.detail = detail


@dataclass(frozen=True, slots=True)
class PhaseResult:
    """Verdict returned by `Phase.execute()`."""
    status: PhaseStatus
    reason: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    # For status="retry"
    retry_after_phase: str | None = None
    retry_modifications: Mapping[str, Any] = field(default_factory=dict)


class Phase(ABC):
    """Base class for pipeline phases."""

    # Identity
    name: ClassVar[str] = ""
    version: ClassVar[str] = "0.1.0"
    core_compat: ClassVar[str] = ">=0.5,<1.0"

    # Ordering — declarative
    after: ClassVar[frozenset[str]] = frozenset()
    before: ClassVar[frozenset[str]] = frozenset()
    parallel_group: ClassVar[str | None] = None

    # State contract — dotted paths
    reads: ClassVar[frozenset[str]] = frozenset()
    writes_processed: ClassVar[frozenset[str]] = frozenset()
    appends_tracking: ClassVar[frozenset[str]] = frozenset()

    # Hazard signals — declared production list
    PRODUCES_HAZARDS: ClassVar[frozenset[str]] = frozenset()

    # Operational
    failure_mode: ClassVar[FailureMode] = "fail_skip"
    timeout_seconds: ClassVar[float] = 5.0
    has_external_side_effects: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Lightweight validation: name must be non-empty and lowercase identifier.
        if cls.name == "":
            # Allow abstract intermediate subclasses to skip this — they have no
            # name. Concrete subclasses must override.
            if not getattr(cls, "__abstractmethods__", None):
                raise TypeError(
                    f"Phase subclass {cls.__name__} must set ClassVar 'name'"
                )
            return
        if not cls.name.replace("_", "").isalnum() or not cls.name[0].isalpha():
            raise TypeError(
                f"Phase {cls.__name__}: name {cls.name!r} must be a snake_case identifier"
            )
        # appends_tracking values must be in known kinds.
        for kind in cls.appends_tracking:
            if kind not in _TRACKING_KINDS:
                raise TypeError(
                    f"Phase {cls.__name__}: appends_tracking entry "
                    f"{kind!r} not in {sorted(_TRACKING_KINDS)}"
                )

    @abstractmethod
    async def execute(self, ctx: RequestContext) -> PhaseResult:
        """Execute phase logic. Can mutate ctx.processed in declared
        writes_processed. Can call ctx.tracking.add_* in declared
        appends_tracking. Cannot mutate ctx.id or ctx.input — those are
        frozen dataclasses.
        """

    def can_skip(self, ctx: RequestContext) -> bool:
        """Optional: check if phase should skip on this request."""
        return False


class ScopedTracking:
    """Per-phase view on Tracking. Enforces contract.

    The engine constructs one of these per phase per request. Phases call
    its add_* methods rather than the raw Tracking.
    """

    __slots__ = ("_t", "_phase_name", "_allowed", "_allowed_hazards")

    def __init__(self, tracking: Tracking, phase: Phase):
        self._t = tracking
        self._phase_name = phase.name
        self._allowed = phase.appends_tracking
        self._allowed_hazards = phase.PRODUCES_HAZARDS

    def add_decision(
        self,
        verdict: PhaseStatus,
        reason: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if "decisions" not in self._allowed:
            raise ContractViolation(self._phase_name, "'decisions' not declared in appends_tracking")
        self._t.add_decision(Decision(
            phase_name=self._phase_name,
            verdict=verdict,
            reason=reason,
            details=details or {},
        ))

    def add_deviation(
        self,
        event_type: str,
        severity: float,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if "deviations" not in self._allowed:
            raise ContractViolation(self._phase_name, "'deviations' not declared in appends_tracking")
        if event_type not in self._allowed_hazards:
            raise ContractViolation(
                self._phase_name,
                f"hazard {event_type!r} not in PRODUCES_HAZARDS"
            )
        if not (0.0 <= severity <= 1.0):
            raise ContractViolation(
                self._phase_name,
                f"hazard severity {severity!r} out of [0, 1]"
            )
        self._t.add_deviation(DeviationEvent(
            phase_name=self._phase_name,
            event_type=event_type,
            severity=float(severity),
            details=details or {},
        ))

    def add_timing(self, started_at: float, finished_at: float) -> None:
        if "timings" not in self._allowed:
            raise ContractViolation(self._phase_name, "'timings' not declared in appends_tracking")
        self._t.add_timing(PhaseTimings(
            phase_name=self._phase_name,
            started_at=started_at,
            finished_at=finished_at,
        ))

    def set_metric(self, name: str, value: float) -> None:
        if "metrics" not in self._allowed:
            raise ContractViolation(self._phase_name, "'metrics' not declared in appends_tracking")
        self._t.set_metric(f"{self._phase_name}.{name}", value)
