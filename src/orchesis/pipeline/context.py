"""Request context for the pipeline plugin architecture.

Three zones with different mutation policies (per SPEC §1.2):

  Identity      — frozen, set at request entry.
  InputSnapshot — frozen, immutable record of original input.
  Processed     — mutable, phases modify in-place between commit points.
  Tracking      — append-only journals (decisions, deviations, timings,
                  metrics), with lengths() / truncate_to() for retry rollback.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Mapping


Tier = Literal["free", "lite", "pro", "deep_pro", "enterprise"]
TaskType = Literal["factual", "evaluative", "creative", "tool_use", "agent_step"]


@dataclass(frozen=True, slots=True)
class Identity:
    """Immutable identity. Set at request entry, never changes."""
    request_id: str
    session_id: str
    agent_id: str
    customer_id: str
    tier: Tier
    company_id: str | None = None
    received_at: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class InputSnapshot:
    """Immutable snapshot of original input. Reference for retry."""
    raw_body: bytes
    original_messages: tuple[Mapping[str, Any], ...]
    original_tools: tuple[Mapping[str, Any], ...]
    requested_model: str
    requested_params: Mapping[str, Any]
    provider_hint: str | None
    headers: Mapping[str, str]
    compression_format: str | None = None
    session_state: Literal["new", "continuation", "resumed_from_sleep"] | None = None


@dataclass(slots=True)
class Processed:
    """Mutable. Phases modify in-place between commit points."""
    messages: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    model: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    upstream: str = ""
    provider: str = ""
    task_type: TaskType | None = None
    chain_length: int = 0
    messages_decompressed: bool = False
    messages_canonicalized: bool = False


@dataclass(frozen=True, slots=True)
class Decision:
    """One verdict emitted by a phase."""
    phase_name: str
    verdict: str  # PhaseStatus value
    reason: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    at: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class DeviationEvent:
    """Hazard contribution with calibrated severity."""
    phase_name: str
    event_type: str
    severity: float  # [0, 1] calibrated probability-scale hazard
    at: float = field(default_factory=time.time)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PhaseTimings:
    phase_name: str
    started_at: float
    finished_at: float


class Tracking:
    """Append-only journals. Snapshot for retry via lengths()/truncate_to()."""

    __slots__ = ("_decisions", "_deviations", "_timings", "_metrics", "_lock")

    def __init__(self) -> None:
        self._decisions: list[Decision] = []
        self._deviations: list[DeviationEvent] = []
        self._timings: list[PhaseTimings] = []
        self._metrics: dict[str, float] = {}
        self._lock = threading.Lock()

    def add_decision(self, d: Decision) -> None:
        with self._lock:
            self._decisions.append(d)

    def add_deviation(self, e: DeviationEvent) -> None:
        with self._lock:
            self._deviations.append(e)

    def add_timing(self, t: PhaseTimings) -> None:
        with self._lock:
            self._timings.append(t)

    def set_metric(self, name: str, value: float) -> None:
        with self._lock:
            self._metrics[name] = float(value)

    @property
    def decisions(self) -> tuple[Decision, ...]:
        with self._lock:
            return tuple(self._decisions)

    @property
    def deviations(self) -> tuple[DeviationEvent, ...]:
        with self._lock:
            return tuple(self._deviations)

    @property
    def timings(self) -> tuple[PhaseTimings, ...]:
        with self._lock:
            return tuple(self._timings)

    @property
    def metrics(self) -> Mapping[str, float]:
        with self._lock:
            return MappingProxyType(dict(self._metrics))

    def lengths(self) -> tuple[int, int, int, frozenset[str]]:
        """Snapshot lengths for retry rollback."""
        with self._lock:
            return (
                len(self._decisions),
                len(self._deviations),
                len(self._timings),
                frozenset(self._metrics.keys()),
            )

    def truncate_to(self, lengths: tuple[int, int, int, frozenset[str]]) -> None:
        """Rollback to snapshot point."""
        d_len, dev_len, t_len, metric_keys = lengths
        with self._lock:
            del self._decisions[d_len:]
            del self._deviations[dev_len:]
            del self._timings[t_len:]
            for key in list(self._metrics.keys()):
                if key not in metric_keys:
                    del self._metrics[key]


class RecordingHandle:
    """Opaque handle for session recording. Engine owns lifecycle.

    The handle accepts events from phases (event_type, payload) and enqueues
    them on the underlying writer. Phases never know about the writer impl.
    """

    __slots__ = ("_writer",)

    def __init__(self, writer: Any | None = None):
        self._writer = writer

    def append(self, event_type: str, payload: Mapping[str, Any]) -> None:
        if self._writer is None:
            return
        if hasattr(self._writer, "enqueue"):
            self._writer.enqueue(event_type, payload)
        elif callable(self._writer):
            self._writer(event_type, payload)


@dataclass(slots=True)
class RequestContext:
    """Composite context. Engine creates on request entry, threads through phases."""
    id: Identity
    input: InputSnapshot
    processed: Processed
    tracking: Tracking
    recording: RecordingHandle


# Type alias for callers that want the historical "recent steps" deque.
RecentStepsDeque = deque
