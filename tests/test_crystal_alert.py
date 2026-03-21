from __future__ import annotations

import time
from dataclasses import dataclass

from orchesis.alerts.crystal_alert import CrystalAlertConfig, CrystalAlertEvent, CrystalAlertMonitor


@dataclass
class _AgentState:
    agent_id: str = "agent-1"
    psi: float = 0.9
    phase: str = "crystal"
    stale_crystal: bool = True
    slope_alert: bool = True
    slope_cqs: float = -0.12


def test_crystal_detected() -> None:
    monitor = CrystalAlertMonitor()
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True})
    assert event is not None


def test_no_crystal_low_psi() -> None:
    monitor = CrystalAlertMonitor()
    event = monitor.check({"agent_id": "a1", "psi": 0.5, "phase": "liquid", "stale_crystal": True})
    assert event is None


def test_no_crystal_not_stale() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(stale_required=True))
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": False})
    assert event is None


def test_crystal_stale_not_required() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(stale_required=False))
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": False})
    assert event is not None


def test_crystal_with_slope_required() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(slope_alert_required=True))
    event = monitor.check(
        {"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True, "slope_alert": False}
    )
    assert event is None


def test_cooldown_blocks_repeat() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(cooldown_seconds=300))
    state = {"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True}
    first = monitor.check(state)
    second = monitor.check(state)
    assert first is not None
    assert second is None
    assert monitor.alert_count == 1


def test_cooldown_expired() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(cooldown_seconds=0.1))
    state = {"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True}
    first = monitor.check(state)
    time.sleep(0.2)
    second = monitor.check(state)
    assert first is not None
    assert second is not None
    assert monitor.alert_count == 2


def test_dispatch_log() -> None:
    monitor = CrystalAlertMonitor(CrystalAlertConfig(channels=["log"]))
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True})
    assert event is not None


def test_dispatch_callback() -> None:
    captured: list[CrystalAlertEvent] = []

    def _callback(evt: CrystalAlertEvent) -> None:
        captured.append(evt)

    monitor = CrystalAlertMonitor(CrystalAlertConfig(channels=["callback"], callback=_callback))
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True})
    assert event is not None
    assert len(captured) == 1
    assert captured[0].agent_id == "a1"


def test_dispatch_webhook_failure() -> None:
    monitor = CrystalAlertMonitor(
        CrystalAlertConfig(channels=["webhook"], webhook_url="http://127.0.0.1:1/does-not-exist")
    )
    event = monitor.check({"agent_id": "a1", "psi": 0.9, "phase": "crystal", "stale_crystal": True})
    assert event is not None


def test_event_has_fields() -> None:
    monitor = CrystalAlertMonitor()
    event = monitor.check(
        {
            "agent_id": "a1",
            "psi": 0.92,
            "phase": "crystal",
            "stale_crystal": True,
            "slope_alert": True,
            "slope_cqs": -0.3,
        }
    )
    assert event is not None
    assert event.alert_id
    assert event.agent_id == "a1"
    assert event.psi > 0
    assert event.message


def test_event_to_dict() -> None:
    event = CrystalAlertEvent(alert_id="x", agent_id="a", psi=0.9, message="m")
    payload = event.to_dict()
    for key in (
        "alert_id",
        "agent_id",
        "timestamp",
        "psi",
        "phase",
        "stale_crystal",
        "slope_alert",
        "slope_cqs",
        "message",
        "severity",
    ):
        assert key in payload


def test_check_with_dict() -> None:
    monitor = CrystalAlertMonitor()
    event = monitor.check({"agent_id": "dict-agent", "psi": 0.9, "phase": "crystal", "stale_crystal": True})
    assert event is not None
    assert event.agent_id == "dict-agent"


def test_check_with_agent_state() -> None:
    monitor = CrystalAlertMonitor()
    state = _AgentState()
    event = monitor.check(state)
    assert event is not None
    assert event.agent_id == "agent-1"

