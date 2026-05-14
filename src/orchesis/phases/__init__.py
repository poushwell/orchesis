"""First-party Phase plugins for the pipeline architecture.

These modules host concrete `Phase` subclasses migrated out of the
monolithic proxy module. Each plugin is registered into the
`PhaseRegistry` either by entry-point discovery or by explicit
construction with injected dependencies (e.g., a shared FlowAnalyzer
instance).
"""

from orchesis.phases.flow_xray_record import FlowXrayRecordPhase
from orchesis.phases.legacy import make_legacy_phase
from orchesis.phases.canonicalize import CanonicalizePhase
from orchesis.phases.compression_decode import CompressionDecodePhase

__all__ = [
    "CanonicalizePhase",
    "CompressionDecodePhase",
    "FlowXrayRecordPhase",
    "make_legacy_phase",
]
