from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app


def _policy_yaml(max_cost: float = 1.0) -> str:
    return f"""
api:
  token: "orch_sk_test"
agents:
  - id: "cursor"
    name: "Cursor IDE Agent"
    trust_tier: operator
default_trust_tier: intern
rules:
  - name: budget_limit
    max_cost_per_call: {max_cost}
    daily_budget: 10.0
  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE"]
  - name: rate_limit
    max_requests_per_minute: 100
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_get_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.get("/api/v1/policy", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "version_id" in payload
    assert "yaml_content" in payload
    assert payload["agents_count"] == 1


@pytest.mark.asyncio
async def test_post_new_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(max_cost=1.0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        before = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        posted = await client.post(
            "/api/v1/policy",
            headers=_auth(),
            json={"yaml_content": _policy_yaml(max_cost=2.0)},
        )
        assert posted.status_code == 200
        after = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
    assert before != after


@pytest.mark.asyncio
async def test_post_invalid_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/policy",
            headers=_auth(),
            json={"yaml_content": "rules:\n  - name: budget_limit\n"},
        )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_policy_history(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(max_cost=1.0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        await client.post("/api/v1/policy", headers=_auth(), json={"yaml_content": _policy_yaml(max_cost=2.0)})
        await client.post("/api/v1/policy", headers=_auth(), json={"yaml_content": _policy_yaml(max_cost=3.0)})
        history = await client.get("/api/v1/policy/history", headers=_auth())
    assert history.status_code == 200
    assert len(history.json()["versions"]) >= 3


@pytest.mark.asyncio
async def test_rollback(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(max_cost=1.0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        first = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        await client.post("/api/v1/policy", headers=_auth(), json={"yaml_content": _policy_yaml(max_cost=4.0)})
        second = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        rolled = await client.post("/api/v1/policy/rollback", headers=_auth())
        current = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
    assert second != first
    assert rolled.status_code == 200
    assert current == first


@pytest.mark.asyncio
async def test_validate_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        valid = await client.post(
            "/api/v1/policy/validate",
            headers=_auth(),
            json={"yaml_content": _policy_yaml()},
        )
        invalid = await client.post(
            "/api/v1/policy/validate",
            headers=_auth(),
            json={"yaml_content": "rules:\n  - name: budget_limit\n"},
        )
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    assert invalid.json()["errors"]


@pytest.mark.asyncio
async def test_get_agents(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.get("/api/v1/agents", headers=_auth())
    assert res.status_code == 200
    assert len(res.json()["agents"]) == 1


@pytest.mark.asyncio
async def test_update_agent_tier(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        updated = await client.put(
            "/api/v1/agents/cursor/tier",
            headers=_auth(),
            json={"trust_tier": "blocked"},
        )
        agent = await client.get("/api/v1/agents/cursor", headers=_auth())
    assert updated.status_code == 200
    assert updated.json()["new_tier"] == "blocked"
    assert agent.json()["trust_tier"] == "blocked"


@pytest.mark.asyncio
async def test_status_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        status = await client.get("/api/v1/status")
    assert status.status_code == 200
    payload = status.json()
    for field in (
        "version",
        "uptime_seconds",
        "policy_version",
        "total_decisions",
        "decisions_per_minute",
        "active_agents",
        "deny_rate_1h",
        "anomaly_count_1h",
        "subscriber_count",
        "corpus_size",
    ):
        assert field in payload


@pytest.mark.asyncio
async def test_evaluate_via_api(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(max_cost=1.0), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        allow = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1},
        )
        deny = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1},
        )
    assert allow.status_code == 200 and allow.json()["allowed"] is True
    assert deny.status_code == 200 and deny.json()["allowed"] is False
    assert allow.headers.get("X-Orchesis-Decision") == "ALLOW"
    assert deny.headers.get("X-Orchesis-Decision") == "DENY"
    assert allow.headers.get("X-Orchesis-Trace-Id")


@pytest.mark.asyncio
async def test_audit_stats_api(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1, "context": {"agent": "cursor"}},
        )
        await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1, "context": {"agent": "cursor"}},
        )
        stats = await client.get("/api/v1/audit/stats?agent_id=cursor&since_hours=24", headers=_auth())
    assert stats.status_code == 200
    payload = stats.json()
    assert payload["total_events"] >= 2
    assert payload["deny_count"] >= 1


@pytest.mark.asyncio
async def test_audit_anomalies_api(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        for _ in range(10):
            await client.post(
                "/api/v1/evaluate",
                headers=_auth(),
                json={
                    "tool": "read_file",
                    "params": {"path": "/etc/passwd"},
                    "cost": 0.1,
                    "context": {"agent": "probe_bot"},
                },
            )
        anomalies = await client.get("/api/v1/audit/anomalies", headers=_auth())
    assert anomalies.status_code == 200
    items = anomalies.json()["anomalies"]
    assert any(item["rule"] == "high_deny_rate" for item in items)


@pytest.mark.asyncio
async def test_auth_required(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        no_auth = await client.get("/api/v1/policy")
        wrong_auth = await client.get(
            "/api/v1/policy",
            headers={"Authorization": "Bearer wrong"},
        )
        ok_auth = await client.get("/api/v1/policy", headers=_auth())
    assert no_auth.status_code == 401
    assert no_auth.json()["error"] == "unauthorized"
    assert wrong_auth.status_code == 401
    assert wrong_auth.json()["error"] == "unauthorized"
    assert ok_auth.status_code == 200


@pytest.mark.asyncio
async def test_timeline_api(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        for _ in range(3):
            await client.post(
                "/api/v1/evaluate",
                headers=_auth(),
                json={
                    "tool": "read_file",
                    "params": {"path": "/data/safe.txt"},
                    "cost": 0.1,
                    "context": {"agent": "timeline_bot"},
                },
            )
        timeline = await client.get("/api/v1/audit/timeline/timeline_bot?hours=24", headers=_auth())
    assert timeline.status_code == 200
    payload = timeline.json()
    assert payload["agent_id"] == "timeline_bot"
    assert len(payload["events"]) >= 3
