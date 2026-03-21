"""Channel Health Monitor — detects silent drops and channel anomalies.

Monitors Telegram, WhatsApp, WebChat via LLM traffic signals.
Part of Overwatch tab.
"""
from __future__ import annotations

import time
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class ChannelAlert:
    severity: str
    channel_type: str
    alert_type: str
    drop_ratio: float
    evidence: dict[str, Any]
    recommendation: str


@dataclass
class ChannelState:
    channel_type: str
    outbound_count: int
    inbound_count: int
    last_inbound_ts: float
    window_start_ts: float
    avg_response_time_s: float
    metadata: dict[str, Any]


class ChannelHealthMonitor:
    CHANNELS = ["telegram", "whatsapp", "webchat"]

    ALERTS = {
        "silent_drop_HIGH": "Outbound tool_calls > 0, inbound = 0 for 2h",
        "silent_drop_MEDIUM": "No session keys 1.5h during business hours",
        "expiry_warning": "WhatsApp session age >= 12 days",
        "expiry_critical": "WhatsApp session age >= 13.5 days",
        "concurrent_session": "Two WS clients with same token — possible hijack",
        "vpn_hint": "No Telegram + OpenClaw 2026.3.x + Russia region",
    }

    def __init__(self, config: dict | None = None):
        _ = config
        now = time.time()
        self._channel_state: dict[str, dict[str, Any]] = {
            ch: {
                "last_inbound": None,
                "last_outbound": None,
                "last_outbound_ts": 0.0,
                "outbound_count": 0,
                "inbound_count": 0,
                "last_inbound_ts": 0.0,
                "window_start_ts": now,
                "avg_response_time_s": 5.0,
                "session_age_days": 0.0,
                "active_clients": 0,
                "session_keys_count": 0,
                "metadata": {},
                "status": "unknown",
            }
            for ch in self.CHANNELS
        }
        self._alerts: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _parse_iso(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def record_event(self, channel: str, event_type: str, metadata: dict) -> None:
        """Record channel traffic event."""
        with self._lock:
            if channel not in self._channel_state:
                return
            now_ts = time.time()
            now_iso = datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat()
            state = self._channel_state[channel]
            if not isinstance(state.get("metadata"), dict):
                state["metadata"] = {}
            meta = metadata if isinstance(metadata, dict) else {}
            if event_type == "inbound":
                state["last_inbound"] = now_iso
                state["last_inbound_ts"] = now_ts
                state["inbound_count"] = int(state.get("inbound_count", 0) or 0) + 1
                last_outbound_ts = float(state.get("last_outbound_ts", 0.0) or 0.0)
                if last_outbound_ts > 0:
                    response_time = max(0.0, now_ts - last_outbound_ts)
                    current_avg = float(state.get("avg_response_time_s", 5.0) or 5.0)
                    state["avg_response_time_s"] = round((current_avg + response_time) / 2.0, 3)
            elif event_type == "outbound":
                state["last_outbound"] = now_iso
                state["last_outbound_ts"] = now_ts
                state["outbound_count"] = int(state.get("outbound_count", 0) or 0) + 1
                if int(state.get("outbound_count", 0) or 0) == 1 and int(state.get("inbound_count", 0) or 0) == 0:
                    state["window_start_ts"] = now_ts
            if "session_age_days" in metadata:
                try:
                    state["session_age_days"] = float(metadata["session_age_days"])
                except (TypeError, ValueError):
                    pass
            if "active_clients" in metadata:
                try:
                    state["active_clients"] = max(0, int(metadata["active_clients"]))
                except (TypeError, ValueError):
                    pass
            if "session_keys_count" in metadata:
                try:
                    state["session_keys_count"] = max(0, int(metadata["session_keys_count"]))
                except (TypeError, ValueError):
                    pass
            if "avg_response_time_s" in meta:
                try:
                    state["avg_response_time_s"] = max(0.0, float(meta["avg_response_time_s"]))
                except (TypeError, ValueError):
                    pass
            if "window_start_ts" in meta:
                try:
                    state["window_start_ts"] = float(meta["window_start_ts"])
                except (TypeError, ValueError):
                    pass
            state["metadata"].update(meta)

    def check_health(self) -> dict[str, Any]:
        """Run all channel health checks."""
        alerts: list[dict[str, Any]] = []
        statuses: dict[str, str] = {}
        now = datetime.now(timezone.utc)
        with self._lock:
            state = {k: dict(v) for k, v in self._channel_state.items()}

        for channel, info in state.items():
            channel_state = ChannelState(
                channel_type=channel,
                outbound_count=int(info.get("outbound_count", 0) or 0),
                inbound_count=int(info.get("inbound_count", 0) or 0),
                last_inbound_ts=float(info.get("last_inbound_ts", 0.0) or 0.0),
                window_start_ts=float(info.get("window_start_ts", time.time()) or time.time()),
                avg_response_time_s=float(info.get("avg_response_time_s", 5.0) or 5.0),
                metadata=dict(info.get("metadata", {})) if isinstance(info.get("metadata"), dict) else {},
            )
            channel_alerts = self._check_channel(channel_state)
            alerts.extend(self._serialize_alert(alert) for alert in channel_alerts)
            statuses[channel] = "healthy" if not channel_alerts else "degraded"

        wa = state.get("whatsapp", {})
        age = float(wa.get("session_age_days", 0.0) or 0.0)
        if age >= 13.5:
            alerts.append(
                self._serialize_alert(
                    ChannelAlert(
                        severity="CRITICAL",
                        channel_type="whatsapp",
                        alert_type="expiry_critical",
                        drop_ratio=0.0,
                        evidence={"session_age_days": age},
                        recommendation=f"Session expires in {max(0.0, 14.0 - age):.1f} days - CRITICAL",
                    )
                )
            )
            statuses["whatsapp"] = "degraded"
        elif age >= 12:
            alerts.append(
                self._serialize_alert(
                    ChannelAlert(
                        severity="HIGH",
                        channel_type="whatsapp",
                        alert_type="expiry_warning",
                        drop_ratio=0.0,
                        evidence={"session_age_days": age},
                        recommendation=f"Session expires in {max(0.0, 14.0 - age):.1f} days",
                    )
                )
            )
            statuses["whatsapp"] = "degraded"

        wc = state.get("webchat", {})
        if int(wc.get("active_clients", 0) or 0) >= 2:
            alerts.append(
                self._serialize_alert(
                    ChannelAlert(
                        severity="HIGH",
                        channel_type="webchat",
                        alert_type="concurrent_session",
                        drop_ratio=0.0,
                        evidence={"active_clients": int(wc.get("active_clients", 0) or 0)},
                        recommendation="Multiple clients with same token - possible hijack",
                    )
                )
            )
            statuses["webchat"] = "degraded"

        with self._lock:
            for channel, status in statuses.items():
                if channel in self._channel_state:
                    self._channel_state[channel]["status"] = status
            self._alerts.extend(alerts)
            if len(self._alerts) > 10000:
                self._alerts = self._alerts[-10000:]

        return {
            "statuses": statuses,
            "alerts": alerts,
            "overall": "healthy" if not alerts else "degraded",
            "checked_at": now.isoformat(),
        }

    def _check_channel(self, channel: ChannelState) -> list[ChannelAlert]:
        """
        Detect silent drops via outbound/inbound message contrast.
        """
        if channel.outbound_count == 0:
            return []

        now = time.time()
        drop_ratio = 1.0 - (channel.inbound_count / max(channel.outbound_count, 1))
        window_minutes = max(0.0, (now - channel.window_start_ts) / 60.0)

        severity = ""
        if drop_ratio >= 0.8 and window_minutes >= 30:
            severity = "HIGH"
        elif drop_ratio >= 0.5 and window_minutes >= 15:
            severity = "MEDIUM"
        elif drop_ratio >= 0.8:
            severity = "MEDIUM"
        elif drop_ratio >= 0.3:
            severity = "LOW"
        else:
            return []

        evidence: dict[str, Any] = {
            "outbound_count": channel.outbound_count,
            "inbound_count": channel.inbound_count,
            "drop_ratio": round(drop_ratio, 4),
            "window_minutes": round(window_minutes, 2),
            "last_inbound_ts": channel.last_inbound_ts,
            "avg_response_time_s": channel.avg_response_time_s,
            "metadata": dict(channel.metadata),
        }

        if severity == "HIGH":
            stale_confirmed = bool(
                channel.last_inbound_ts > 0
                and now - channel.last_inbound_ts > (2.0 * max(channel.avg_response_time_s, 0.1))
            )
            evidence["stale_confirmed"] = stale_confirmed

        metadata = channel.metadata if isinstance(channel.metadata, dict) else {}
        if severity == "MEDIUM":
            webhook_last_error = metadata.get("webhook_last_error_date")
            if isinstance(webhook_last_error, int | float) and now - float(webhook_last_error) <= 3600:
                severity = "HIGH"
                evidence["webhook_last_error_date"] = float(webhook_last_error)
                evidence["amplified_by"] = "telegram_webhook_error"

            session_expiry_ts = metadata.get("session_expiry_ts")
            if channel.channel_type == "whatsapp" and isinstance(session_expiry_ts, int | float):
                hours_left = (float(session_expiry_ts) - now) / 3600.0
                if float(session_expiry_ts) - now < 48 * 3600:
                    severity = "HIGH"
                    evidence["session_expiry_ts"] = float(session_expiry_ts)
                    evidence["expiry_hours_remaining"] = round(hours_left, 2)
                    evidence["amplified_by"] = "whatsapp_session_expiry"

            last_pong_ts = metadata.get("last_pong_ts")
            if channel.channel_type == "webchat" and isinstance(last_pong_ts, int | float):
                if now - float(last_pong_ts) > 60:
                    severity = "HIGH"
                    evidence["last_pong_ts"] = float(last_pong_ts)
                    evidence["seconds_since_last_pong"] = round(now - float(last_pong_ts), 2)
                    evidence["amplified_by"] = "webchat_stale_pong"

        recommendation = self._recommendation_for(
            channel_type=channel.channel_type,
            severity=severity,
            drop_ratio=drop_ratio,
            evidence=evidence,
            now_ts=now,
        )
        return [
            ChannelAlert(
                severity=severity,
                channel_type=channel.channel_type,
                alert_type="silent_drop",
                drop_ratio=drop_ratio,
                evidence=evidence,
                recommendation=recommendation,
            )
        ]

    def _recommendation_for(
        self,
        channel_type: str,
        severity: str,
        drop_ratio: float,
        evidence: dict[str, Any],
        now_ts: float,
    ) -> str:
        if severity == "HIGH" and channel_type == "telegram":
            last_error = evidence.get("webhook_last_error_date")
            if isinstance(last_error, int | float):
                detail = datetime.fromtimestamp(float(last_error), tz=timezone.utc).isoformat()
            else:
                detail = "unknown"
            return (
                "Telegram bot webhook may be failing. Check bot token and webhook URL. "
                f"Last error: {detail}"
            )
        if severity == "HIGH" and channel_type == "whatsapp":
            session_expiry_ts = evidence.get("session_expiry_ts")
            hours = (float(session_expiry_ts) - now_ts) / 3600.0 if isinstance(session_expiry_ts, int | float) else 48.0
            return (
                "WhatsApp session may be expiring. "
                f"Renew session within {max(0.0, hours):.1f}h to prevent message loss."
            )
        if severity == "HIGH" and channel_type == "webchat":
            return "WebChat connection appears stale. Check WebSocket server health."
        if severity == "MEDIUM":
            return f"Message delivery degraded on {channel_type}. Monitor closely. Drop ratio: {drop_ratio:.0%}"
        return f"Minor delivery gap detected on {channel_type}. Drop ratio: {drop_ratio:.0%}"

    def _serialize_alert(self, alert: ChannelAlert) -> dict[str, Any]:
        payload = asdict(alert)
        payload["channel"] = alert.channel_type
        payload["type"] = alert.alert_type
        payload["message"] = alert.recommendation
        return payload

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "channels": len(self._channel_state),
                "total_alerts": len(self._alerts),
                "channel_statuses": {
                    ch: info["status"]
                    for ch, info in self._channel_state.items()
                },
            }

    def get_channel_status(self, channel: str) -> dict[str, Any]:
        with self._lock:
            info = self._channel_state.get(channel)
            if info is None:
                return {}
            return {"channel": channel, **dict(info)}
