"""Crystal Alert v1.0 — alerts when agent context crystallizes.

Monitors agent state for quality state changes and
sends alerts via configurable channels (webhook, log, callback).

Usage:
    alert = QualityAlertMonitor(config)
    alert.check(agent_state)  # triggers alert if crystal + stale
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


class AlertChannel(str, Enum):
    LOG = "log"
    WEBHOOK = "webhook"
    CALLBACK = "callback"


@dataclass
class QualityAlertConfig:
    """Configuration for Crystal Alert monitoring."""

    enabled: bool = True
    psi_threshold: float = 0.85
    stale_required: bool = True
    slope_alert_required: bool = False
    cooldown_seconds: float = 300.0
    channels: list = field(default_factory=lambda: ["log"])
    webhook_url: str = ""
    callback: Optional[Callable] = None


@dataclass
class QualityAlertEvent:
    """A crystal alert event."""

    alert_id: str = ""
    agent_id: str = ""
    timestamp: float = 0.0
    psi: float = 0.0
    phase: str = ""
    stale_crystal: bool = False
    slope_alert: bool = False
    slope_quality: float = 0.0
    message: str = ""
    severity: str = "HIGH"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "psi": self.psi,
            "phase": self.phase,
            "stale_crystal": self.stale_crystal,
            "slope_alert": self.slope_alert,
            "slope_quality": self.slope_quality,
            "message": self.message,
            "severity": self.severity,
        }


class QualityAlertMonitor:
    """Monitor agent states for crystal phase transitions."""

    def __init__(self, config: QualityAlertConfig | None = None):
        self.config = config or QualityAlertConfig()
        self._last_alert_time: dict[str, float] = {}
        self._alert_history: list[QualityAlertEvent] = []
        self._alert_count = 0

    def _is_crystal(self, state) -> bool:
        """Check if agent state indicates crystallization."""
        psi = getattr(state, "psi", None) or (state.get("psi") if isinstance(state, dict) else 0.0)
        stale = getattr(state, "stale_crystal", None)
        if stale is None and isinstance(state, dict):
            stale = state.get("stale_crystal", False)

        psi = float(psi or 0.0)
        if psi < self.config.psi_threshold:
            return False

        if self.config.stale_required and not stale:
            return False

        if self.config.slope_alert_required:
            slope_alert = getattr(state, "slope_alert", None)
            if slope_alert is None and isinstance(state, dict):
                slope_alert = state.get("slope_alert", False)
            if not slope_alert:
                return False

        return True

    def _in_cooldown(self, agent_id: str) -> bool:
        """Check if agent is in cooldown period."""
        last = self._last_alert_time.get(agent_id, 0.0)
        return (time.time() - last) < self.config.cooldown_seconds

    def _build_event(self, state, agent_id: str) -> QualityAlertEvent:
        """Build alert event from state."""
        import uuid

        psi = float(
            getattr(state, "psi", 0.0) if not isinstance(state, dict) else state.get("psi", 0.0)
        )
        phase = (
            getattr(state, "phase", "") if not isinstance(state, dict) else state.get("phase", "")
        )
        stale = bool(
            getattr(state, "stale_crystal", False)
            if not isinstance(state, dict)
            else state.get("stale_crystal", False)
        )
        slope_alert = bool(
            getattr(state, "slope_alert", False)
            if not isinstance(state, dict)
            else state.get("slope_alert", False)
        )
        slope_quality = float(
            getattr(state, "slope_quality", 0.0)
            if not isinstance(state, dict)
            else state.get("slope_quality", 0.0)
        )

        return QualityAlertEvent(
            alert_id=f"crystal-{uuid.uuid4().hex[:8]}",
            agent_id=agent_id,
            timestamp=time.time(),
            psi=psi,
            phase=phase,
            stale_crystal=stale,
            slope_alert=slope_alert,
            slope_quality=slope_quality,
            message=f"Agent {agent_id} context crystallized: Ψ={psi:.3f}, phase={phase}, stale={stale}",
            severity="HIGH" if stale else "MEDIUM",
        )

    def _dispatch(self, event: QualityAlertEvent) -> None:
        """Send alert through configured channels."""
        for channel in self.config.channels:
            try:
                if channel == AlertChannel.LOG.value:
                    logger.warning(
                        event.message,
                        extra={
                            "component": "quality_alert",
                            "agent_id": event.agent_id,
                            "psi": event.psi,
                        },
                    )
                elif channel == AlertChannel.WEBHOOK.value and self.config.webhook_url:
                    import urllib.request

                    req = urllib.request.Request(
                        self.config.webhook_url,
                        data=json.dumps(event.to_dict()).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(req, timeout=5)
                    except Exception as exc:
                        logger.debug(
                            "Webhook delivery failed: %s", exc, extra={"component": "quality_alert"}
                        )
                elif channel == AlertChannel.CALLBACK.value and self.config.callback:
                    self.config.callback(event)
            except Exception as exc:
                logger.warning(
                    "Alert dispatch failed on %s: %s",
                    channel,
                    exc,
                    exc_info=True,
                    extra={"component": "quality_alert"},
                )

    def check(self, state, agent_id: str = "") -> Optional[QualityAlertEvent]:
        """Check agent state and fire alert if crystallized."""
        if not self.config.enabled:
            return None

        if not agent_id:
            agent_id = (
                getattr(state, "agent_id", "")
                if not isinstance(state, dict)
                else state.get("agent_id", "unknown")
            )
            if not agent_id:
                agent_id = "unknown"

        if not self._is_crystal(state):
            return None

        if self._in_cooldown(agent_id):
            logger.debug(
                "Agent %s in cooldown, skipping alert",
                agent_id,
                extra={"component": "quality_alert"},
            )
            return None

        event = self._build_event(state, agent_id)
        self._dispatch(event)

        self._last_alert_time[agent_id] = time.time()
        self._alert_history.append(event)
        self._alert_count += 1
        return event

    def get_history(self) -> list[QualityAlertEvent]:
        return list(self._alert_history)

    @property
    def alert_count(self) -> int:
        return self._alert_count
