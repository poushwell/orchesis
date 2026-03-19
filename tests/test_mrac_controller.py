from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.mrac_controller import MRACController


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
    ctl = MRACController({})
    row = ctl.register_agent("agent-a")
    assert row["gain_compression"] == 1.0
    assert row["gain_injection"] == 1.0


def test_gain_adapts_on_error() -> None:
    ctl = MRACController({"gamma": 0.2})
    ctl.register_agent("agent-a")
    out = ctl.update("agent-a", actual_cqs=0.4)
    assert float(out["gain_compression"]) < 1.0
    assert float(out["gain_injection"]) > 1.0


def test_gain_clamped_within_bounds() -> None:
    ctl = MRACController({"gamma": 10.0})
    ctl.register_agent("agent-a")
    for _ in range(20):
        ctl.update("agent-a", actual_cqs=-10.0)
    gains = ctl.get_gains("agent-a")
    assert 0.1 <= float(gains["gain_compression"]) <= 3.0
    assert 0.1 <= float(gains["gain_injection"]) <= 3.0


def test_reference_model_decays() -> None:
    ctl = MRACController({"ref_decay": 0.9})
    ctl.register_agent("agent-a")
    out1 = ctl.update("agent-a", actual_cqs=1.0)
    out2 = ctl.update("agent-a", actual_cqs=1.0)
    assert float(out2["ref_state"]) <= float(out1["ref_state"])


def test_tracking_error_computed() -> None:
    ctl = MRACController({})
    ctl.register_agent("agent-a")
    out = ctl.update("agent-a", actual_cqs=0.5)
    assert "tracking_error" in out
    assert isinstance(out["tracking_error"], float)


def test_all_agents_returned() -> None:
    ctl = MRACController({})
    ctl.register_agent("agent-a")
    ctl.register_agent("agent-b")
    rows = ctl.get_all_agents()
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_api_update_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/mrac/update",
            headers=_auth(),
            json={"agent_id": "agent-a", "actual_cqs": 0.61},
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-a"
    assert "gain_compression" in payload


@pytest.mark.asyncio
async def test_api_gains_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/mrac/update",
            headers=_auth(),
            json={"agent_id": "agent-z", "actual_cqs": 0.8},
        )
        res = await client.get("/api/v1/mrac/agent-z/gains", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-z"
    assert "gain_compression" in payload and "gain_injection" in payload
