from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.agent_graph import AgentCollaborationGraph
from orchesis.api import create_api_app


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
agents:
  - id: agent_a
  - id: agent_b
  - id: agent_c
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _write_event(
    decisions_log: Path,
    *,
    agent_id: str,
    to_agent: str | None = None,
    interaction_type: str = "context_share",
) -> None:
    row = {
        "event_id": f"evt-{agent_id}-{to_agent or 'none'}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc123",
        "cost": 0.2,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 2000,
        "policy_version": "v1",
        "state_snapshot": {
            "to_agent": to_agent,
            "interaction_type": interaction_type,
        },
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
    }
    decisions_log.parent.mkdir(parents=True, exist_ok=True)
    with decisions_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


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
    return app, decisions_log


def test_record_interaction() -> None:
    graph = AgentCollaborationGraph()
    graph.record_interaction("agent_a", "agent_b", "context_share")
    model = graph.get_graph()
    assert len(model["edges"]) == 1
    assert model["edges"][0]["weight"] == 1


def test_graph_structure_valid() -> None:
    graph = AgentCollaborationGraph()
    graph.record_interaction("agent_a", "agent_b")
    model = graph.get_graph()
    assert "nodes" in model
    assert "edges" in model
    assert "central_agent" in model
    assert "isolated_agents" in model


def test_central_agent_identified() -> None:
    graph = AgentCollaborationGraph()
    graph.record_interaction("agent_a", "agent_b")
    graph.record_interaction("agent_a", "agent_c")
    model = graph.get_graph()
    assert model["central_agent"] == "agent_a"


def test_isolated_agents_found() -> None:
    graph = AgentCollaborationGraph()
    graph.record_agent("agent_alone")
    graph.record_interaction("agent_a", "agent_b")
    model = graph.get_graph()
    assert "agent_alone" in model["isolated_agents"]


def test_clusters_computed() -> None:
    graph = AgentCollaborationGraph()
    graph.record_interaction("agent_a", "agent_b")
    graph.record_interaction("agent_x", "agent_y")
    clusters = graph.get_clusters()
    assert len(clusters) >= 2


@pytest.mark.asyncio
async def test_api_graph_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="agent_a", to_agent="agent_b", interaction_type="context_share")
    _write_event(decisions_log, agent_id="agent_a", to_agent="agent_b", interaction_type="tool_call")
    async with await _client(app) as client:
        res = await client.get("/api/v1/agents/graph", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert isinstance(payload["nodes"], list)
    assert isinstance(payload["edges"], list)
    assert "central_agent" in payload


@pytest.mark.asyncio
async def test_api_clusters_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="agent_a", to_agent="agent_b")
    async with await _client(app) as client:
        res = await client.get("/api/v1/agents/clusters", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "clusters" in payload
    assert isinstance(payload["clusters"], list)
