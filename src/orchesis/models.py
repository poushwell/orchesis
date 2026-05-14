"""Data models for the Orchesis kernel."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Decision:
    """Result of evaluating a tool/request against policy (allow/deny and audit metadata)."""

    allowed: bool = True
    reasons: list[str] = field(default_factory=list)
    rules_checked: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    debug_trace: dict[str, Any] | None = None
