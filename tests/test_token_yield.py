from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.token_yield import TokenYieldTracker


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_token_yield_computed_correctly() -> None:
    tracker = TokenYieldTracker()
    tracker.record("s1", prompt_tokens=100, completion_tokens=100, cache_hit=False, unique_content_ratio=0.5)
    payload = tracker.get_yield("s1")
    assert payload["total_tokens"] == 200
    assert payload["semantic_tokens"] == 100
    assert payload["token_yield"] == 0.5


def test_waste_percent_inverse_of_yield() -> None:
    tracker = TokenYieldTracker()
    tracker.record("s1", prompt_tokens=80, completion_tokens=20, cache_hit=False, unique_content_ratio=0.7)
    payload = tracker.get_yield("s1")
    assert payload["waste_percent"] == pytest.approx(1.0 - payload["token_yield"], rel=1e-6)


def test_context_collapse_detected_at_3x() -> None:
    tracker = TokenYieldTracker()
    tracker.record("s1", prompt_tokens=10, completion_tokens=0, cache_hit=False, unique_content_ratio=1.0)
    tracker.record("s1", prompt_tokens=31, completion_tokens=0, cache_hit=False, unique_content_ratio=1.0)
    assert tracker.context_collapse_detected("s1") is True


def test_cache_savings_counted() -> None:
    tracker = TokenYieldTracker()
    tracker.record("s1", prompt_tokens=60, completion_tokens=40, cache_hit=True, unique_content_ratio=0.6)
    payload = tracker.get_yield("s1")
    assert payload["cache_savings"] == 100


def test_global_stats_aggregated() -> None:
    tracker = TokenYieldTracker()
    tracker.record("a", prompt_tokens=50, completion_tokens=50, cache_hit=False, unique_content_ratio=0.5)
    tracker.record("b", prompt_tokens=100, completion_tokens=0, cache_hit=True, unique_content_ratio=0.8)
    stats = tracker.get_global_stats()
    assert stats["sessions"] == 2
    assert stats["total_tokens"] == 200
    assert stats["semantic_tokens"] == 130
    assert stats["cache_savings"] == 100


@pytest.mark.asyncio
async def test_api_endpoint_returns_yield(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    app.state.token_yield.record(
        "session-1",
        prompt_tokens=120,
        completion_tokens=80,
        cache_hit=True,
        unique_content_ratio=0.75,
    )
    async with await _client(app) as client:
        res = await client.get("/api/v1/token-yield/session-1", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["session_id"] == "session-1"
    assert payload["total_tokens"] == 200
    assert payload["cache_savings"] == 200


@pytest.mark.asyncio
async def test_api_endpoint_global_is_not_shadowed_by_session_route(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    app.state.token_yield.record(
        "session-a",
        prompt_tokens=20,
        completion_tokens=10,
        cache_hit=False,
        unique_content_ratio=0.5,
    )
    async with await _client(app) as client:
        res = await client.get("/api/v1/token-yield/global", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["sessions"] >= 1
