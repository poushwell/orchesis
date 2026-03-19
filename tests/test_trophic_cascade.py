from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.keystone_agent import KeystoneDetector


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


def test_uci_recorded() -> None:
    det = KeystoneDetector({})
    det.record_uci("agent-a", 0.7)
    assert det.get_stats()["agents_tracked"] == 1


def test_keystone_score_computed() -> None:
    det = KeystoneDetector({})
    det.record_uci("agent-a", 0.9)
    det.record_uci("agent-b", 0.4)
    out = det.compute_keystone_score("agent-a")
    assert "score" in out
    assert 0.0 <= float(out["score"]) <= 1.0


def test_keystone_flagged_above_threshold() -> None:
    det = KeystoneDetector({"threshold": 0.2})
    det.record_uci("agent-a", 0.95)
    det.record_uci("agent-b", 0.2)
    out = det.compute_keystone_score("agent-a")
    assert out["keystone"] is True


def test_not_keystone_below_threshold() -> None:
    det = KeystoneDetector({"threshold": 0.8})
    det.record_uci("agent-a", 0.55)
    det.record_uci("agent-b", 0.5)
    out = det.compute_keystone_score("agent-a")
    assert out["keystone"] is False


def test_all_keystones_ranked() -> None:
    det = KeystoneDetector({})
    det.record_uci("agent-a", 0.9)
    det.record_uci("agent-b", 0.3)
    det.record_uci("agent-c", 0.4)
    rows = det.get_all_keystones()
    assert len(rows) == 3
    assert float(rows[0]["score"]) >= float(rows[-1]["score"])


def test_trophic_cascade_risk() -> None:
    det = KeystoneDetector({})
    det.record_uci("agent-a", 0.95)
    det.record_uci("agent-b", 0.2)
    row = det.get_trophic_cascade("agent-a")
    assert row["cascade_risk"] in {"low", "medium", "high"}
    assert "agent-b" in row["affected_agents"]


@pytest.mark.asyncio
async def test_api_score_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/keystone/record-uci",
            headers=_auth(),
            json={"agent_id": "agent-a", "uci_score": 0.9},
        )
        await client.post(
            "/api/v1/keystone/record-uci",
            headers=_auth(),
            json={"agent_id": "agent-b", "uci_score": 0.4},
        )
        res = await client.get("/api/v1/keystone/agent-a/score", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-a"
    assert "score" in payload


@pytest.mark.asyncio
async def test_api_cascade_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/keystone/record-uci",
            headers=_auth(),
            json={"agent_id": "agent-a", "uci_score": 0.9},
        )
        await client.post(
            "/api/v1/keystone/record-uci",
            headers=_auth(),
            json={"agent_id": "agent-b", "uci_score": 0.5},
        )
        res = await client.get("/api/v1/keystone/agent-a/cascade", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-a"
    assert "cascade_risk" in payload
