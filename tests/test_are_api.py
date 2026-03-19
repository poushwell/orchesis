from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app


def _policy_yaml(with_are: bool = False) -> str:
    base = """
api:
  token: "orch_sk_test"
rules: []
"""
    if not with_are:
        return base
    return (
        base
        + """
are:
  slos:
    - name: availability
      sli: availability
      target: 0.999
      window_days: 30
    - name: security_rate
      sli: security_rate
      target: 0.95
      window_days: 7
"""
    )


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_app(tmp_path: Path, *, with_are: bool = False):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(with_are=with_are), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app


@pytest.mark.asyncio
async def test_define_slo_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/are/slo",
            headers=_auth(),
            json={"name": "latency_guard", "sli": "latency_p99", "target": 0.25, "window_days": 14},
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["slo"]["name"] == "latency_guard"
    assert payload["slo"]["sli"] == "latency_p99"


@pytest.mark.asyncio
async def test_record_sli_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/are/slo",
            headers=_auth(),
            json={"name": "availability_custom", "sli": "availability", "target": 0.99, "window_days": 30},
        )
        res = await client.post(
            "/api/v1/are/sli/availability_custom",
            headers=_auth(),
            json={"value": 0.995},
        )
    assert res.status_code == 200
    assert res.json()["ok"] is True


@pytest.mark.asyncio
async def test_get_error_budget_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/are/sli/availability",
            headers=_auth(),
            json={"value": 0.997},
        )
        res = await client.get("/api/v1/are/budget/availability", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["slo_name"] == "availability"
    assert "burn_rate" in payload


@pytest.mark.asyncio
async def test_reliability_report_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path, with_are=True)
    async with await _client(app) as client:
        res = await client.get("/api/v1/are/report", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "slos" in payload
    assert payload["total_slos"] >= 2


@pytest.mark.asyncio
async def test_burn_rate_alert_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/are/sli/security_rate",
            headers=_auth(),
            json={"value": 0.1},
        )
        res = await client.get("/api/v1/are/alerts", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "alerts" in payload
    assert isinstance(payload["alerts"], list)


@pytest.mark.asyncio
async def test_default_slos_loaded(tmp_path: Path) -> None:
    app = _make_app(tmp_path, with_are=False)
    async with await _client(app) as client:
        report = await client.get("/api/v1/are/report", headers=_auth())
    assert report.status_code == 200
    names = {row.get("slo_name") for row in report.json().get("slos", []) if isinstance(row, dict)}
    assert "availability" in names
    assert "security_rate" in names
