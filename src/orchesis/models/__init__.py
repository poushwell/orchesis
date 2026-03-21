"""Unified model exports for Orchesis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from orchesis.models.ecosystem import (
    Alert,
    BenchmarkEntry,
    Finding,
    IncidentRecord,
    ReliabilityReport,
    SLOTarget,
    Severity,
)


@dataclass
class Decision:
    """Decision returned by the verification engine."""

    allowed: bool = True
    reasons: list[str] = field(default_factory=list)
    rules_checked: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    debug_trace: dict[str, Any] | None = None

