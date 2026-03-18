from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.raft_context import RaftContextProtocol


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


def test_entry_appended() -> None:
    raft = RaftContextProtocol({})
    out = raft.append_entry("task", "v1", "agent-a")
    assert out["index"] == 1
    assert out["key"] == "task"


def test_acknowledgement_tracked() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("task", "v1", "agent-a")
    ok = raft.acknowledge("agent-a", 1)
    assert ok is True


def test_consistent_context_returned() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("task", "v1", "agent-a")
    raft.acknowledge("agent-a", 1)
    ctx = raft.get_consistent_context("agent-a")
    assert ctx["committed_index"] >= 1
    assert len(ctx["entries"]) >= 1


def test_divergent_agents_identified() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("k1", "v1", "agent-a")
    raft.append_entry("k2", "v2", "agent-b")
    raft.acknowledge("agent-a", 2)
    divergent = raft.get_divergent_agents()
    assert "agent-b" in divergent


def test_sync_sends_missing_entries() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("k1", "v1", "agent-a")
    raft.append_entry("k2", "v2", "agent-b")
    raft.acknowledge("agent-a", 2)
    synced = raft.sync_agent("agent-b")
    assert synced["sent"] >= 1
    assert isinstance(synced["entries"], list)


def test_committed_index_advances() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("k1", "v1", "agent-a")
    raft.append_entry("k2", "v2", "agent-b")
    raft.acknowledge("agent-a", 2)
    stats = raft.get_raft_stats()
    assert stats["committed"] >= 1


def test_raft_stats_returned() -> None:
    raft = RaftContextProtocol({})
    raft.append_entry("k1", "v1", "agent-a")
    stats = raft.get_raft_stats()
    assert "term" in stats
    assert "consistency_rate" in stats


@pytest.mark.asyncio
async def test_api_append_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/raft/append",
            json={"key": "policy", "value": "strict", "agent_id": "agent-a"},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["index"] == 1
    assert payload["key"] == "policy"


@pytest.mark.asyncio
async def test_api_sync_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/raft/append",
            json={"key": "policy", "value": "strict", "agent_id": "agent-a"},
            headers=_auth(),
        )
        await client.post(
            "/api/v1/raft/append",
            json={"key": "cache", "value": "on", "agent_id": "agent-b"},
            headers=_auth(),
        )
        await client.post(
            "/api/v1/raft/acknowledge",
            json={"agent_id": "agent-a", "index": 2},
            headers=_auth(),
        )
        res = await client.post("/api/v1/raft/agent-b/sync", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-b"
    assert payload["sent"] >= 1
