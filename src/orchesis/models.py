"""Data models for the Orchesis kernel."""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Decision:
    """Decision returned by the verification engine."""

    allowed: bool = True
    reasons: list[str] = field(default_factory=list)
    rules_checked: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
