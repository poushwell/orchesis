"""Pipeline plugin architecture.

The pipeline composes request processing as an ordered sequence of `Phase`
plugins. Phases declare their contract (reads/writes, ordering, hazard
signals) and are linearized via Kahn's topological sort at registry build.

Public surface:
    Phase, PhaseResult, FailureMode, PhaseStatus, ContractViolation
    RequestContext, Identity, InputSnapshot, Processed, Tracking
    Decision, DeviationEvent, PhaseTimings, RecordingHandle, ScopedTracking
    PhaseGraph, PhaseGraphError
    PhaseRegistry, PhaseRegistryError
    PipelineEngine
"""

from orchesis.pipeline.context import (
    Decision,
    DeviationEvent,
    Identity,
    InputSnapshot,
    PhaseTimings,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)
from orchesis.pipeline.phase import (
    ContractViolation,
    FailureMode,
    Phase,
    PhaseResult,
    PhaseStatus,
    ScopedTracking,
)
from orchesis.pipeline.graph import PhaseGraph, PhaseGraphError
from orchesis.pipeline.registry import PhaseRegistry, PhaseRegistryError
from orchesis.pipeline.engine import PipelineEngine
from orchesis.pipeline.budget_check import check_budget

__all__ = [
    "ContractViolation",
    "Decision",
    "DeviationEvent",
    "FailureMode",
    "Identity",
    "InputSnapshot",
    "Phase",
    "PhaseGraph",
    "PhaseGraphError",
    "PhaseRegistry",
    "PhaseRegistryError",
    "PhaseResult",
    "PhaseStatus",
    "PhaseTimings",
    "PipelineEngine",
    "Processed",
    "RecordingHandle",
    "RequestContext",
    "ScopedTracking",
    "Tracking",
    "check_budget",
]
