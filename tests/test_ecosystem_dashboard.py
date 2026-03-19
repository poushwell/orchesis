from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
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
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app


def test_ecosystem_tab_present() -> None:
    html = get_dashboard_html()
    assert 'id="tab-ecosystem"' in html
    assert 'id="ecosystem"' in html
    assert "Ecosystem" in html


def test_ecosystem_poll_function() -> None:
    html = get_dashboard_html()
    assert "async function pollEcosystem()" in html
    assert "Promise.allSettled" in html
    assert "fetch('/api/v1/casura/incidents/stats')" in html
    assert "fetch('/api/v1/aabb/leaderboard')" in html
    assert "fetch('/api/v1/are/report')" in html
    assert "fetch('/api/v1/competitive/latest')" in html


@pytest.mark.asyncio
async def test_competitive_latest_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/competitive/latest", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "alerts" in payload
    assert "count" in payload


@pytest.mark.asyncio
async def test_ecosystem_summary_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/ecosystem/summary", headers=_auth())
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_all_subsystems_in_summary(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/ecosystem/summary", headers=_auth())
    payload = res.json()
    assert "casura" in payload
    assert "aabb" in payload
    assert "are" in payload
    assert "competitive" in payload
