from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.byzantine_detector import ByzantineDetector


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
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app


def _healthy() -> dict:
    return {
        "behavior_drift": 0.05,
        "response_inconsistency": 0.05,
        "cost_anomaly": 0.1,
        "timing_anomaly": 0.05,
        "tool_abuse": 0.1,
    }


def _risky() -> dict:
    return {
        "behavior_drift": 0.95,
        "response_inconsistency": 0.9,
        "cost_anomaly": 0.85,
        "timing_anomaly": 0.8,
        "tool_abuse": 0.9,
    }


def test_min_fleet_size_required() -> None:
    detector = ByzantineDetector({})
    for idx in range(4):
        detector.observe(f"agent-{idx}", _healthy())
    assert detector.detect() == []
    health = detector.get_fleet_health()
    assert health["detection_ready"] is False
    assert health["fleet_size"] == 4


def test_observation_recorded() -> None:
    detector = ByzantineDetector({})
    detector.observe("agent-a", {"behavior_drift": 0.2})
    assert "agent-a" in detector._observations
    assert len(detector._observations["agent-a"]) == 1


def test_byzantine_agent_detected() -> None:
    detector = ByzantineDetector({})
    for idx in range(4):
        detector.observe(f"agent-{idx}", _healthy())
    detector.observe("agent-bad", _risky())
    rows = detector.detect()
    assert any(item["agent_id"] == "agent-bad" for item in rows)


def test_healthy_agent_not_flagged() -> None:
    detector = ByzantineDetector({})
    for idx in range(5):
        detector.observe(f"agent-{idx}", _healthy())
    rows = detector.detect()
    assert rows == []


def test_cross_validation_inconsistency() -> None:
    detector = ByzantineDetector({})
    detector.observe("agent-a", {"query": "what is policy", "response": "allow request now"})
    detector.observe("agent-b", {"query": "what is policy", "response": "deny request immediately"})
    out = detector.cross_validate("agent-a", "agent-b", "what is policy")
    assert out["inconsistent"] is True
    assert "response_inconsistency" in out["signals"]


def test_fleet_health_returned() -> None:
    detector = ByzantineDetector({})
    for idx in range(4):
        detector.observe(f"agent-{idx}", _healthy())
    detector.observe("agent-bad", _risky())
    health = detector.get_fleet_health()
    assert health["fleet_size"] == 5
    assert health["detection_ready"] is True
    assert health["quarantined"] >= 1 or health["suspicious"] >= 1


@pytest.mark.asyncio
async def test_api_detect_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        for idx in range(4):
            await client.post(
                "/api/v1/byzantine/observe",
                json={"agent_id": f"agent-{idx}", "metrics": _healthy()},
                headers=_auth(),
            )
        await client.post(
            "/api/v1/byzantine/observe",
            json={"agent_id": "agent-bad", "metrics": _risky()},
            headers=_auth(),
        )
        res = await client.get("/api/v1/byzantine/detect", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "results" in payload
    assert any(item["agent_id"] == "agent-bad" for item in payload["results"])


@pytest.mark.asyncio
async def test_api_fleet_health_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/byzantine/observe",
            json={"agent_id": "agent-a", "metrics": _healthy()},
            headers=_auth(),
        )
        res = await client.get("/api/v1/byzantine/fleet-health", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["fleet_size"] == 1
    assert "detection_ready" in payload
