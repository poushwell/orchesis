from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.api_rate_limiter import ApiRateLimiter


def _policy_yaml(requests_per_minute: int = 60, burst: int = 10) -> str:
    return f"""
api:
  token: "orch_sk_test"
  rate_limit:
    requests_per_minute: {requests_per_minute}
    burst: {burst}
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_within_limit_allowed() -> None:
    limiter = ApiRateLimiter({"requests_per_minute": 2, "burst": 0})
    first = limiter.check("c1")
    assert first["allowed"] is True
    limiter.record("c1")
    second = limiter.check("c1")
    assert second["allowed"] is True
    assert int(second["remaining"]) == 1


def test_exceeds_limit_blocked() -> None:
    limiter = ApiRateLimiter({"requests_per_minute": 1, "burst": 0})
    limiter.record("c1")
    blocked = limiter.check("c1")
    assert blocked["allowed"] is False
    assert int(blocked["remaining"]) == 0
    assert blocked["retry_after"] is not None


def test_burst_allowed() -> None:
    limiter = ApiRateLimiter({"requests_per_minute": 1, "burst": 2})
    assert limiter.check("c1")["allowed"] is True
    limiter.record("c1")
    assert limiter.check("c1")["allowed"] is True
    limiter.record("c1")
    assert limiter.check("c1")["allowed"] is True
    limiter.record("c1")
    assert limiter.check("c1")["allowed"] is False


def test_reset_clears_count() -> None:
    limiter = ApiRateLimiter({"requests_per_minute": 1, "burst": 0})
    limiter.record("c1")
    assert limiter.check("c1")["allowed"] is False
    limiter.reset("c1")
    assert limiter.check("c1")["allowed"] is True


@pytest.mark.asyncio
async def test_retry_after_header(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(requests_per_minute=1, burst=0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        first = await client.get("/api/v1/policy", headers=_auth())
        second = await client.get("/api/v1/policy", headers=_auth())
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json().get("error") == "rate_limit_exceeded"
    assert "Retry-After" in second.headers
    assert int(second.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_api_status_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(requests_per_minute=10, burst=0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        response = await client.get("/api/v1/rate-limit/status", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is True
    assert "client_id" in payload
    assert "remaining" in payload
    assert "reset_at" in payload
    assert "retry_after" in payload
