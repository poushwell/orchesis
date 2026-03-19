from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.group_selection import GroupSelectionModel


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
    return create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )


def test_agent_registered() -> None:
    model = GroupSelectionModel({})
    model.register_agent("agent-a", "g1")
    stats = model.get_stats()
    assert stats["agents"] == 1
    assert stats["groups"] == 1


def test_cooperative_gets_bonus() -> None:
    model = GroupSelectionModel({"cooperation_bonus": 0.2})
    model.register_agent("agent-a", "g1")
    row = model.record_interaction("agent-a", cooperative=True, outcome=0.5)
    assert float(row["group_effect"]) > 0.0
    assert float(row["total_fitness"]) > float(row["individual_fitness"])


def test_defector_gets_penalty() -> None:
    model = GroupSelectionModel({"defection_penalty": 0.1})
    model.register_agent("agent-a", "g1")
    row = model.record_interaction("agent-a", cooperative=False, outcome=0.5)
    assert float(row["group_effect"]) < 0.0
    assert float(row["total_fitness"]) < float(row["individual_fitness"])


def test_group_fitness_aggregated() -> None:
    model = GroupSelectionModel({})
    model.register_agent("agent-a", "g1")
    model.register_agent("agent-b", "g1")
    model.record_interaction("agent-a", cooperative=True, outcome=0.8)
    model.record_interaction("agent-b", cooperative=True, outcome=0.6)
    row = model.get_group_fitness("g1")
    assert row["group_id"] == "g1"
    assert row["size"] == 2
    assert 0.0 <= float(row["fitness"]) <= 1.0


def test_fittest_group_identified() -> None:
    model = GroupSelectionModel({})
    model.register_agent("agent-a", "g1")
    model.register_agent("agent-b", "g2")
    model.record_interaction("agent-a", cooperative=True, outcome=0.9)
    model.record_interaction("agent-b", cooperative=False, outcome=0.2)
    row = model.get_fittest_group()
    assert row is not None
    assert row["group_id"] == "g1"


def test_cooperation_rate_computed() -> None:
    model = GroupSelectionModel({})
    model.register_agent("agent-a", "g1")
    model.register_agent("agent-b", "g1")
    model.record_interaction("agent-b", cooperative=False, outcome=0.4)
    row = model.record_interaction("agent-a", cooperative=True, outcome=0.7)
    assert 0.0 <= float(row["cooperation_rate"]) <= 1.0
    assert float(row["cooperation_rate"]) == 0.5


@pytest.mark.asyncio
async def test_api_register_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/group-selection/register",
            headers=_auth(),
            json={"agent_id": "agent-a", "group_id": "g1"},
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["ok"] is True
    assert payload["group_id"] == "g1"


@pytest.mark.asyncio
async def test_api_fittest_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/group-selection/register",
            headers=_auth(),
            json={"agent_id": "agent-a", "group_id": "g1"},
        )
        await client.post(
            "/api/v1/group-selection/register",
            headers=_auth(),
            json={"agent_id": "agent-b", "group_id": "g2"},
        )
        await client.post(
            "/api/v1/group-selection/interaction",
            headers=_auth(),
            json={"agent_id": "agent-a", "cooperative": True, "outcome": 0.9},
        )
        await client.post(
            "/api/v1/group-selection/interaction",
            headers=_auth(),
            json={"agent_id": "agent-b", "cooperative": False, "outcome": 0.2},
        )
        res = await client.get("/api/v1/group-selection/fittest", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "group" in payload
    assert payload["group"]["group_id"] == "g1"
