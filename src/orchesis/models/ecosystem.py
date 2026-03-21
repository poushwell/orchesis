"""
Shared domain models for Orchesis ecosystem.

These canonical types are the single source of truth.
Module-specific types should inherit or alias these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Universal detection/scan finding."""

    finding_id: str = field(default_factory=lambda: f"f-{uuid.uuid4().hex[:8]}")
    title: str = ""
    severity: str = "MEDIUM"
    category: str = ""
    description: str = ""
    source_module: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentRecord:
    """
    Canonical incident record.

    CASURA, forensics, and related modules can use this directly or adapt to it.
    """

    incident_id: str = field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    title: str = ""
    severity: float = 0.0
    category: str = ""
    description: str = ""
    source: str = ""
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    status: str = "open"


@dataclass
class Alert:
    """Universal alert model."""

    alert_id: str = field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:8]}")
    severity: str = "MEDIUM"
    alert_type: str = ""
    source_module: str = ""
    title: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False


@dataclass
class SLOTarget:
    """Service Level Objective definition."""

    name: str = ""
    target: float = 0.99
    window_hours: int = 720
    metric: str = ""


@dataclass
class ReliabilityReport:
    """Reliability/SRE report output."""

    agent_id: str = ""
    slos: list[SLOTarget] = field(default_factory=list)
    current_values: dict[str, Any] = field(default_factory=dict)
    error_budget_remaining: float = 1.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class BenchmarkEntry:
    """AABB benchmark entry."""

    agent_id: str = ""
    agent_name: str = ""
    scores: dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

