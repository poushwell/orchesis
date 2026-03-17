from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app


def _policy_yaml(extra: str = "") -> str:
    return f"""
api:
  token: "orch_sk_test"
rules: []
{extra}
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
    seconds_ago: float,
    decision: str = "ALLOW",
    cost: float = 0.0,
    reason: str = "",
    model: str = "gpt-4o",
) -> None:
    ts = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    row = {
        "event_id": f"evt-{agent_id}-{int(seconds_ago)}-{decision.lower()}",
        "timestamp": ts.isoformat(),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc123",
        "cost": float(cost),
        "decision": decision,
        "reasons": [reason] if reason else ([] if decision == "ALLOW" else ["policy:blocked"]),
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 120,
        "policy_version": "v1",
        "state_snapshot": {"model": model},
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
    }
    decisions_log.parent.mkdir(parents=True, exist_ok=True)
    with decisions_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def _make_app(tmp_path: Path, policy_yaml: str | None = None):
    policy_path = tmp_path / "policy.yaml"
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(policy_yaml if isinstance(policy_yaml, str) else _policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app, decisions_log


@pytest.mark.asyncio
async def test_overwatch_returns_agents(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="openclaw_01", seconds_ago=5, cost=0.12)

    async with await _client(app) as client:
        res = await client.get("/api/v1/overwatch", headers=_auth())

    assert res.status_code == 200
    agents = res.json()["agents"]
    assert len(agents) == 1
    assert agents[0]["id"] == "openclaw_01"


@pytest.mark.asyncio
async def test_overwatch_agent_status_inferred_from_traffic(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="a_working", seconds_ago=10)
    _write_event(decisions_log, agent_id="b_idle", seconds_ago=120)
    _write_event(decisions_log, agent_id="c_offline", seconds_ago=600)

    async with await _client(app) as client:
        res = await client.get("/api/v1/overwatch", headers=_auth())

    assert res.status_code == 200
    by_id = {row["id"]: row for row in res.json()["agents"]}
    assert by_id["a_working"]["status"] == "working"
    assert by_id["b_idle"]["status"] == "idle"
    assert by_id["c_offline"]["status"] == "offline"


@pytest.mark.asyncio
async def test_overwatch_empty_returns_empty_list(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        res = await client.get("/api/v1/overwatch", headers=_auth())

    assert res.status_code == 200
    payload = res.json()
    assert payload["agents"] == []
    assert payload["overwatch_summary"]["total_cost_today"] == 0.0


@pytest.mark.asyncio
async def test_overwatch_threats_per_agent(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(
        decisions_log,
        agent_id="agent_x",
        seconds_ago=30,
        decision="DENY",
        reason="sql_restriction: denied operation",
    )
    _write_event(decisions_log, agent_id="agent_x", seconds_ago=20, decision="ALLOW")
    _write_event(
        decisions_log,
        agent_id="agent_x",
        seconds_ago=10,
        decision="DENY",
        reason="file_access: denied path",
    )

    async with await _client(app) as client:
        res = await client.get("/api/v1/overwatch/agent_x/threats", headers=_auth())

    assert res.status_code == 200
    threats = res.json()["threats"]
    assert len(threats) == 2
    assert threats[0]["blocked"] is True


@pytest.mark.asyncio
async def test_overwatch_budget_set(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/overwatch/agent_budget/budget",
            headers=_auth(),
            json={"daily_limit": 5.0},
        )

    assert res.status_code == 200
    assert res.json()["policy"]["budget_daily"] == 5.0


@pytest.mark.asyncio
async def test_overwatch_budget_enforced_prequest(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="agent_budget", seconds_ago=15, cost=1.25)

    async with await _client(app) as client:
        set_budget = await client.post(
            "/api/v1/overwatch/agent_budget/budget",
            headers=_auth(),
            json={"daily_limit": 1.0},
        )
        assert set_budget.status_code == 200
        blocked = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={"tool_name": "shell.exec", "params": {}, "agent_id": "agent_budget"},
        )

    assert blocked.status_code == 429
    assert blocked.json()["detail"]["reason"] == "budget_exceeded"


@pytest.mark.asyncio
async def test_overwatch_policy_get(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        await client.post(
            "/api/v1/overwatch/agent_policy/budget",
            headers=_auth(),
            json={"daily_limit": 3.5},
        )
        res = await client.get("/api/v1/overwatch/agent_policy/policy", headers=_auth())

    assert res.status_code == 200
    assert res.json()["policy"]["budget_daily"] == 3.5


@pytest.mark.asyncio
async def test_overwatch_policy_update(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/overwatch/agent_patch/policy",
            headers=_auth(),
            json={
                "budget_daily": 2.0,
                "block_patterns": ["rm -rf", "curl .*metadata"],
                "require_approval": True,
                "mode": "strict",
            },
        )

    assert res.status_code == 200
    policy = res.json()["policy"]
    assert policy["budget_daily"] == 2.0
    assert policy["require_approval"] is True
    assert policy["mode"] == "strict"


@pytest.mark.asyncio
async def test_team_assignment(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        set_team = await client.post(
            "/api/v1/overwatch/agent_team/team",
            headers=_auth(),
            json={"team_id": "research"},
        )
        get_policy = await client.get("/api/v1/overwatch/agent_team/policy", headers=_auth())

    assert set_team.status_code == 200
    assert set_team.json()["team_id"] == "research"
    assert get_policy.status_code == 200
    assert get_policy.json()["policy"]["team_id"] == "research"


@pytest.mark.asyncio
async def test_team_summary_aggregates_correctly(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="a1", seconds_ago=15, cost=1.2)
    _write_event(decisions_log, agent_id="a1", seconds_ago=10, decision="DENY", cost=0.3, reason="policy:blocked")
    _write_event(decisions_log, agent_id="a2", seconds_ago=20, cost=2.0)
    _write_event(decisions_log, agent_id="other", seconds_ago=12, cost=5.0)

    async with await _client(app) as client:
        await client.post("/api/v1/overwatch/a1/team", headers=_auth(), json={"team_id": "eng"})
        await client.post("/api/v1/overwatch/a2/team", headers=_auth(), json={"team_id": "eng"})
        res = await client.get("/api/v1/overwatch/teams/eng", headers=_auth())

    assert res.status_code == 200
    payload = res.json()
    assert payload["team_id"] == "eng"
    assert payload["requests_today"] == 3
    assert payload["threats_today"] == 1
    assert payload["cost_today"] == pytest.approx(3.5)


@pytest.mark.asyncio
async def test_team_budget_rollup(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="a1", seconds_ago=20, cost=1.0)
    _write_event(decisions_log, agent_id="a2", seconds_ago=18, cost=0.5)

    async with await _client(app) as client:
        await client.post("/api/v1/overwatch/a1/team", headers=_auth(), json={"team_id": "platform"})
        await client.post("/api/v1/overwatch/a2/team", headers=_auth(), json={"team_id": "platform"})
        await client.post("/api/v1/overwatch/a1/budget", headers=_auth(), json={"daily_limit": 3.0})
        await client.post("/api/v1/overwatch/a2/budget", headers=_auth(), json={"daily_limit": 2.0})
        res = await client.get("/api/v1/overwatch/teams/platform", headers=_auth())

    assert res.status_code == 200
    payload = res.json()
    assert payload["budget_limit"] == pytest.approx(5.0)
    assert payload["budget_remaining"] == pytest.approx(3.5)


@pytest.mark.asyncio
async def test_teams_list_endpoint(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(tmp_path)

    async with await _client(app) as client:
        await client.post("/api/v1/overwatch/a1/team", headers=_auth(), json={"team_id": "research"})
        await client.post("/api/v1/overwatch/a2/team", headers=_auth(), json={"team_id": "engineering"})
        res = await client.get("/api/v1/overwatch/teams", headers=_auth())

    assert res.status_code == 200
    teams = res.json()["teams"]
    team_ids = sorted(item["team_id"] for item in teams)
    assert team_ids == ["engineering", "research"]


@pytest.mark.asyncio
async def test_agent_team_from_yaml(tmp_path: Path) -> None:
    app, _decisions_log = _make_app(
        tmp_path,
        policy_yaml=_policy_yaml(
            extra="""
agents:
  - id: "research_01"
    team: "research"
  - id: "coding_02"
    team: "engineering"
"""
        ),
    )

    async with await _client(app) as client:
        teams_res = await client.get("/api/v1/overwatch/teams", headers=_auth())
        research_res = await client.get("/api/v1/overwatch/teams/research", headers=_auth())

    assert teams_res.status_code == 200
    ids = sorted(item["team_id"] for item in teams_res.json()["teams"])
    assert ids == ["engineering", "research"]
    assert research_res.status_code == 200
    assert [agent["id"] for agent in research_res.json()["agents"]] == ["research_01"]
