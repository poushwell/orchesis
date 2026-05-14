from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.dashboard import get_dashboard_html


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules:
  - name: rate_default
    max_requests_per_minute: 10
agents:
  - id: agent_ok
    rate_limit_per_minute: 10
  - id: agent_warning
    rate_limit_per_minute: 10
  - id: agent_throttled
    rate_limit_per_minute: 10
  - id: agent_percent
    rate_limit_per_minute: 10
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app


def _record_requests(app, agent_id: str, count: int, *, seconds_ago: int = 0) -> None:
    tracker = app.state.tracker
    stamp = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    for _ in range(count):
        tracker.record(
            "chat",
            timestamp=stamp,
            agent_id=agent_id,
            session_id="sess-1",
        )


@pytest.mark.asyncio
async def test_rate_limit_status_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    _record_requests(app, "agent_ok", 2)
    async with await _client(app) as client:
        res = await client.get("/api/v1/rate-limits/status", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "agents" in payload
    assert "global" in payload
    assert "agent_ok" in payload["agents"]


@pytest.mark.asyncio
async def test_percent_used_calculated(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    _record_requests(app, "agent_percent", 5)
    async with await _client(app) as client:
        res = await client.get("/api/v1/rate-limits/status", headers=_auth())
    agent = res.json()["agents"]["agent_percent"]
    assert agent["limit_per_minute"] == 10
    assert 49.0 <= float(agent["percent_used"]) <= 51.0


@pytest.mark.asyncio
async def test_status_ok_warning_throttled(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    _record_requests(app, "agent_ok", 3)
    _record_requests(app, "agent_warning", 8)
    _record_requests(app, "agent_throttled", 12)
    async with await _client(app) as client:
        res = await client.get("/api/v1/rate-limits/status", headers=_auth())
    agents = res.json()["agents"]
    assert agents["agent_ok"]["status"] == "ok"
    assert agents["agent_warning"]["status"] == "warning"
    assert agents["agent_throttled"]["status"] == "throttled"


@pytest.mark.asyncio
async def test_global_stats_included(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    _record_requests(app, "agent_ok", 4)
    _record_requests(app, "agent_ok", 6, seconds_ago=90)
    _record_requests(app, "agent_warning", 9, seconds_ago=1200)
    async with await _client(app) as client:
        res = await client.get("/api/v1/rate-limits/status", headers=_auth())
    global_stats = res.json()["global"]
    assert global_stats["requests_this_minute"] >= 4
    assert global_stats["peak_this_hour"] >= global_stats["requests_this_minute"]


def test_dashboard_widget_markup() -> None:
    html = get_dashboard_html(demo_mode=False)
    assert "Rate Limits" in html
    assert "rl-global-rpm" in html
    assert "rl-throttled" in html
    assert "rl-agent-rows" in html
    assert "RATE_LIMIT_REFRESH_MS = 10000" in html
