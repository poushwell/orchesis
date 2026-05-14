from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.agent_lifecycle import AgentLifecycleManager
from orchesis.api import create_api_app


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


def test_register_agent() -> None:
    mgr = AgentLifecycleManager()
    row = mgr.register("agent-a", {"team": "core"})
    assert row["agent_id"] == "agent-a"
    assert row["state"] == "initializing"
    assert row["metadata"]["team"] == "core"


def test_valid_transition() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("agent-a")
    assert mgr.transition("agent-a", "active", "boot complete") is True
    assert mgr.get_state("agent-a")["state"] == "active"


def test_invalid_transition_rejected() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("agent-a")
    assert mgr.transition("agent-a", "retired", "too early") is False
    assert mgr.get_state("agent-a")["state"] == "initializing"


def test_auto_transition_on_high_error_rate() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("agent-a")
    assert mgr.transition("agent-a", "active")
    new_state = mgr.auto_transition("agent-a", {"error_rate": 0.5})
    assert new_state == "degraded"
    assert mgr.get_state("agent-a")["state"] == "degraded"


def test_retire_agent() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("agent-a")
    mgr.transition("agent-a", "active")
    assert mgr.retire("agent-a", "no longer needed") is True
    assert mgr.get_state("agent-a")["state"] == "retired"


def test_ban_agent() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("agent-a")
    mgr.transition("agent-a", "active")
    mgr.transition("agent-a", "degraded")
    assert mgr.ban("agent-a", "policy breach") is True
    assert mgr.get_state("agent-a")["state"] == "banned"


def test_list_by_state() -> None:
    mgr = AgentLifecycleManager()
    mgr.register("a1")
    mgr.register("a2")
    mgr.transition("a1", "active")
    active = mgr.list_by_state("active")
    ids = {row["agent_id"] for row in active}
    assert ids == {"a1"}


@pytest.mark.asyncio
async def test_api_lifecycle_endpoints(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        reg = await client.post(
            "/api/v1/lifecycle/register",
            headers=_auth(),
            json={"agent_id": "agent-x", "metadata": {"owner": "qa"}},
        )
        assert reg.status_code == 200
        assert reg.json()["state"] == "initializing"

        tr = await client.post(
            "/api/v1/lifecycle/agent-x/transition",
            headers=_auth(),
            json={"new_state": "active", "reason": "ready"},
        )
        assert tr.status_code == 200
        assert tr.json()["state"] == "active"

        get_one = await client.get("/api/v1/lifecycle/agent-x", headers=_auth())
        assert get_one.status_code == 200
        assert get_one.json()["agent_id"] == "agent-x"

        by_state = await client.get("/api/v1/lifecycle/state/active", headers=_auth())
        assert by_state.status_code == 200
        assert by_state.json()["count"] >= 1

        retire = await client.post(
            "/api/v1/lifecycle/agent-x/retire",
            headers=_auth(),
            json={"reason": "sunset"},
        )
        assert retire.status_code == 200
        assert retire.json()["state"] == "retired"
