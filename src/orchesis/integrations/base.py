"""Shared primitives for alert integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class AlertEvent:
    """Normalized alert event delivered to external integrations."""

    action: str
    severity: str
    agent_id: str
    rule_id: str
    pattern: str
    description: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseIntegration:
    """Base class for all alert integrations."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if isinstance(config, dict) else {}

    def should_alert(self, event: AlertEvent, config: dict[str, Any] | None = None) -> bool:
        """Check whether event passes integration filters."""
        cfg = config if isinstance(config, dict) else self.config
        if not bool(cfg.get("enabled", False)):
            return False
        on_events = cfg.get("on", [])
        if isinstance(on_events, list) and on_events:
            allowed = {str(item).strip().lower() for item in on_events if str(item).strip()}
            if str(event.action).strip().lower() not in allowed:
                return False
        min_severity = str(cfg.get("min_severity", "low")).strip().lower()
        event_rank = _SEVERITY_ORDER.get(str(event.severity).strip().lower(), 0)
        min_rank = _SEVERITY_ORDER.get(min_severity, 0)
        return event_rank >= min_rank

    def send(self, event: AlertEvent) -> Any:  # pragma: no cover - interface only
        raise NotImplementedError

