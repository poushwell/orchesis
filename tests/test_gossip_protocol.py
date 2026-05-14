from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.gossip_protocol import GossipProtocol


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


def test_broadcast_creates_message() -> None:
    gp = GossipProtocol({})
    msg_id = gp.broadcast("policy", "strict", "agent-a")
    assert msg_id.startswith("gossip-")
    status = gp.get_convergence_status()
    assert status["total_messages"] == 1


def test_agent_receives_messages() -> None:
    gp = GossipProtocol({})
    gp.broadcast("policy", "strict", "agent-a")
    rows = gp.receive("agent-b")
    assert len(rows) == 1
    assert rows[0]["key"] == "policy"


def test_propagation_reduces_pending() -> None:
    gp = GossipProtocol({"fanout": 1, "ttl_rounds": 5})
    gp.broadcast("policy", "strict", "agent-a")
    gp.receive("agent-b")
    gp.receive("agent-c")
    before = gp.get_convergence_status()["pending"]
    _ = gp.propagate()
    after = gp.get_convergence_status()["pending"]
    assert after <= before


def test_convergence_tracked() -> None:
    gp = GossipProtocol({"fanout": 3, "ttl_rounds": 5})
    gp.broadcast("cache", "enabled", "agent-a")
    gp.receive("agent-b")
    gp.receive("agent-c")
    gp.propagate()
    status = gp.get_convergence_status()
    assert "convergence_rate" in status
    assert 0.0 <= float(status["convergence_rate"]) <= 1.0


def test_ttl_expires_old_messages() -> None:
    gp = GossipProtocol({"fanout": 1, "ttl_rounds": 1})
    gp.broadcast("x", "1", "agent-a")
    gp.receive("agent-b")
    gp.propagate()
    status = gp.get_convergence_status()
    assert status["pending"] == 0


def test_fanout_respected() -> None:
    gp = GossipProtocol({"fanout": 2, "ttl_rounds": 5})
    gp.broadcast("r", "1", "agent-a")
    for aid in ("agent-b", "agent-c", "agent-d", "agent-e"):
        gp.receive(aid)
    propagated = gp.propagate()
    assert propagated <= 2


@pytest.mark.asyncio
async def test_api_broadcast_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/gossip/broadcast",
            json={"key": "policy", "value": "strict", "source_agent": "agent-a"},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["message_id"].startswith("gossip-")


@pytest.mark.asyncio
async def test_api_convergence_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/gossip/broadcast",
            json={"key": "policy", "value": "strict", "source_agent": "agent-a"},
            headers=_auth(),
        )
        await client.get("/api/v1/gossip/agent-b/messages", headers=_auth())
        res = await client.get("/api/v1/gossip/convergence", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "total_messages" in payload
    assert "convergence_rate" in payload
