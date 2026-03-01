from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
default_trust_tier: intern
token_limits:
  max_tokens_per_call: 1000
  max_tokens_per_session: 5000
  max_tokens_per_day: 20000
rules:
  - name: file_access
    denied_paths: ["/etc", "/root"]
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_evaluate_with_session_type(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={
                "tool_name": "read_file",
                "params": {"path": "/tmp/a"},
                "agent_id": "my-agent",
                "session_type": "dm",
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is True
    assert payload["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_evaluate_with_token_context(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={
                "tool_name": "read_file",
                "params": {"path": "/tmp/a"},
                "agent_id": "my-agent",
                "context": {"estimated_tokens": 1500, "session_tokens_used": 1200},
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is False
    assert "token_budget" in payload["rule"]


@pytest.mark.asyncio
async def test_evaluate_batch(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/evaluate/batch",
            headers=_auth(),
            json={
                "evaluations": [
                    {"tool_name": "read_file", "params": {"path": "/tmp/a"}, "agent_id": "a"},
                    {"tool_name": "read_file", "params": {"path": "/etc/passwd"}, "agent_id": "a"},
                    {"tool_name": "read_file", "params": {"path": "/tmp/b"}, "agent_id": "b"},
                ]
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["results"]) == 3


@pytest.mark.asyncio
async def test_evaluate_batch_summary(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/evaluate/batch",
            headers=_auth(),
            json={
                "evaluations": [
                    {"tool_name": "read_file", "params": {"path": "/tmp/a"}, "agent_id": "a"},
                    {"tool_name": "read_file", "params": {"path": "/etc/passwd"}, "agent_id": "a"},
                ]
            },
        )
    summary = response.json()["summary"]
    assert summary["total"] == 2
    assert summary["denied"] >= 1


@pytest.mark.asyncio
async def test_proxy_stats_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    app.state.proxy_stats = {"requests_total": 1234, "requests_allowed": 1100, "requests_denied": 134, "avg_latency_ms": 0.8}
    async with await _client(app) as client:
        response = await client.get("/api/v1/proxy/stats")
    assert response.status_code == 200
    assert response.json()["requests_total"] == 1234
