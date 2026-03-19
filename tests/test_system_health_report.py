from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.system_health_report import SystemHealthReport


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


class _StateStub:
    red_queen = object()
    immune_memory = object()
    token_yield = object()
    quorum_sensor = object()
    byzantine_detector = object()
    raft_context = object()
    casura_db = object()
    aabb_benchmark = object()
    are = object()


def test_report_generated() -> None:
    report = SystemHealthReport().generate(_StateStub())
    assert report["report_id"].startswith("health-")
    assert report["generated_at"]


def test_all_subsystems_present() -> None:
    report = SystemHealthReport().generate(_StateStub())
    subsystems = report["subsystems"]
    for key in ("proxy", "api", "security", "cost", "fleet", "research", "ecosystem"):
        assert key in subsystems


def test_overall_status_healthy() -> None:
    report = SystemHealthReport().generate(_StateStub())
    assert report["overall_status"] == "healthy"


def test_security_subsystem_checked() -> None:
    security = SystemHealthReport().generate(_StateStub())["subsystems"]["security"]
    assert security["status"] == "active"
    assert "red_queen" in security
    assert "immune_memory" in security


def test_fleet_subsystem_checked() -> None:
    fleet = SystemHealthReport().generate(_StateStub())["subsystems"]["fleet"]
    assert fleet["status"] == "ready"
    assert "quorum_sensing" in fleet
    assert "byzantine_detector" in fleet
    assert "raft_context" in fleet


def test_ecosystem_subsystem_checked() -> None:
    eco = SystemHealthReport().generate(_StateStub())["subsystems"]["ecosystem"]
    assert "casura" in eco and "aabb" in eco and "are" in eco


@pytest.mark.asyncio
async def test_api_health_report_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/system/health-report", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["overall_status"] == "healthy"
    assert "subsystems" in payload


def test_metrics_summary_included() -> None:
    metrics = SystemHealthReport().generate(_StateStub())["metrics_summary"]
    assert "total_modules" in metrics
    assert "active_endpoints" in metrics
    assert "tests_passing" in metrics
