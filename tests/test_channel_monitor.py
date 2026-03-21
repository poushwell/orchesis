from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.channel_monitor import ChannelAlert, ChannelHealthMonitor, ChannelState
from orchesis.dashboard import get_dashboard_html


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    return create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )


def make_channel(
    channel_type: str = "telegram",
    outbound: int = 100,
    inbound: int = 50,
    window_minutes: float = 60,
    avg_response_s: float = 5.0,
    metadata: dict | None = None,
    last_inbound_offset_s: float = 10,
) -> ChannelState:
    now = time.time()
    return ChannelState(
        channel_type=channel_type,
        outbound_count=outbound,
        inbound_count=inbound,
        last_inbound_ts=now - last_inbound_offset_s,
        window_start_ts=now - (window_minutes * 60),
        avg_response_time_s=avg_response_s,
        metadata=metadata or {},
    )


def test_event_recorded() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("telegram", "outbound", {"session_age_days": 1})
    status = monitor.get_channel_status("telegram")
    assert status["channel"] == "telegram"
    assert status["last_outbound"] is not None
    assert float(status["session_age_days"]) == 1.0


def test_whatsapp_expiry_warning_at_12_days() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("whatsapp", "outbound", {"session_age_days": 12.0})
    result = monitor.check_health()
    assert any(item.get("type") == "expiry_warning" for item in result["alerts"])


def test_whatsapp_expiry_critical_at_13_5_days() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("whatsapp", "outbound", {"session_age_days": 13.5})
    result = monitor.check_health()
    assert any(item.get("type") == "expiry_critical" for item in result["alerts"])


def test_webchat_concurrent_session_alert() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("webchat", "inbound", {"active_clients": 2})
    result = monitor.check_health()
    assert any(item.get("type") == "concurrent_session" for item in result["alerts"])


def test_healthy_channels_no_alerts() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("telegram", "inbound", {"session_keys_count": 1})
    monitor.record_event("whatsapp", "inbound", {"session_age_days": 1})
    monitor.record_event("webchat", "inbound", {"active_clients": 1})
    result = monitor.check_health()
    assert result["overall"] == "healthy"
    assert result["alerts"] == []


def test_stats_returned() -> None:
    monitor = ChannelHealthMonitor()
    monitor.record_event("telegram", "outbound", {})
    monitor.check_health()
    stats = monitor.get_stats()
    assert stats["channels"] == 3
    assert "total_alerts" in stats
    assert "channel_statuses" in stats


@pytest.mark.asyncio
async def test_api_health_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/channels/health", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "statuses" in payload
    assert "alerts" in payload


@pytest.mark.asyncio
async def test_api_record_event_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/channels/telegram/event",
            headers=_auth(),
            json={"event_type": "outbound", "metadata": {"session_keys_count": 1}},
        )
        assert res.status_code == 200
        status_res = await client.get("/api/v1/channels/telegram/status", headers=_auth())
    assert status_res.status_code == 200
    status_payload = status_res.json()
    assert status_payload["channel"] == "telegram"
    assert status_payload["last_outbound"] is not None


def test_dashboard_channels_tab() -> None:
    html = get_dashboard_html()
    assert 'id="tab-channels"' in html
    assert 'id="channels"' in html
    assert "async function pollChannels()" in html
    assert "fetch('/api/v1/channels/health')" in html


def test_silent_drop_high_telegram() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(make_channel(channel_type="telegram", outbound=100, inbound=10, window_minutes=45))  # noqa: SLF001
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].channel_type == "telegram"


def test_silent_drop_high_stale_confirmed() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(outbound=100, inbound=10, window_minutes=45, avg_response_s=5.0, last_inbound_offset_s=20)
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["stale_confirmed"] is True


def test_silent_drop_medium_whatsapp() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(channel_type="whatsapp", outbound=100, inbound=40, window_minutes=20)
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].channel_type == "whatsapp"


def test_window_too_short_for_high() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(outbound=100, inbound=10, window_minutes=10)
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"


def test_silent_drop_low_webchat() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(channel_type="webchat", outbound=100, inbound=65, window_minutes=60)
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"


def test_window_too_short_for_medium() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(outbound=100, inbound=40, window_minutes=5)
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"


def test_no_drop() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(make_channel(outbound=100, inbound=90, window_minutes=60))  # noqa: SLF001
    assert alerts == []


def test_zero_outbound() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(make_channel(outbound=0, inbound=0, window_minutes=60))  # noqa: SLF001
    assert alerts == []


def test_whatsapp_expiry_amplification() -> None:
    monitor = ChannelHealthMonitor()
    expiry_ts = time.time() + 24 * 3600
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(
            channel_type="whatsapp",
            outbound=100,
            inbound=40,
            window_minutes=20,
            metadata={"session_expiry_ts": expiry_ts},
        )
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["amplified_by"] == "whatsapp_session_expiry"


def test_webchat_stale_pong_amplification() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(
            channel_type="webchat",
            outbound=100,
            inbound=40,
            window_minutes=20,
            metadata={"last_pong_ts": time.time() - 120},
        )
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["amplified_by"] == "webchat_stale_pong"


def test_telegram_webhook_error_in_evidence() -> None:
    monitor = ChannelHealthMonitor()
    webhook_error_ts = time.time() - 300
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(
            channel_type="telegram",
            outbound=100,
            inbound=40,
            window_minutes=20,
            metadata={"webhook_last_error_date": webhook_error_ts},
        )
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["webhook_last_error_date"] == webhook_error_ts


def test_edge_exact_thresholds() -> None:
    monitor = ChannelHealthMonitor()
    alerts = monitor._check_channel(  # noqa: SLF001
        make_channel(outbound=100, inbound=50, window_minutes=15)
    )
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"


def test_recommendation_text_not_empty() -> None:
    monitor = ChannelHealthMonitor()
    samples = [
        make_channel(channel_type="telegram", outbound=100, inbound=10, window_minutes=45),
        make_channel(channel_type="whatsapp", outbound=100, inbound=40, window_minutes=20),
        make_channel(channel_type="webchat", outbound=100, inbound=65, window_minutes=60),
    ]
    alerts = [monitor._check_channel(sample)[0] for sample in samples]  # noqa: SLF001
    assert all(len(alert.recommendation) > 10 for alert in alerts)


def test_channel_alert_dataclass_fields() -> None:
    alert = ChannelAlert(
        severity="HIGH",
        channel_type="telegram",
        alert_type="silent_drop",
        drop_ratio=0.9,
        evidence={"detail": "x"},
        recommendation="Check webhook",
    )
    assert isinstance(alert.severity, str)
    assert isinstance(alert.channel_type, str)
    assert isinstance(alert.alert_type, str)
    assert isinstance(alert.drop_ratio, float)
    assert isinstance(alert.evidence, dict)
    assert isinstance(alert.recommendation, str)


def test_multiple_channels() -> None:
    monitor = ChannelHealthMonitor()
    telegram = monitor._check_channel(make_channel(channel_type="telegram", outbound=100, inbound=10, window_minutes=45))[0]  # noqa: SLF001
    whatsapp = monitor._check_channel(make_channel(channel_type="whatsapp", outbound=100, inbound=40, window_minutes=20))[0]  # noqa: SLF001
    webchat = monitor._check_channel(make_channel(channel_type="webchat", outbound=100, inbound=65, window_minutes=60))[0]  # noqa: SLF001
    assert telegram.channel_type == "telegram"
    assert whatsapp.channel_type == "whatsapp"
    assert webchat.channel_type == "webchat"
