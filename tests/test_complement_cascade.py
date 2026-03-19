from __future__ import annotations

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.complement_cascade import ComplementCascade


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


def test_c1_activated_above_threshold() -> None:
    cascade = ComplementCascade()
    result = cascade.activate(0.35, "prompt_injection")
    assert "C1" in result["stages_activated"]


def test_cascade_amplifies_signal() -> None:
    cascade = ComplementCascade({"amplification": 1.5})
    result = cascade.activate(0.5, "credential")
    assert result["amplified_signal"] >= 0.5


def test_mac_terminal_attack() -> None:
    cascade = ComplementCascade()
    result = cascade.activate(0.95, "critical")
    assert result["terminal_attack"] is True
    assert "MAC" in result["stages_activated"]


def test_action_circuit_break_at_mac() -> None:
    cascade = ComplementCascade()
    result = cascade.activate(0.95, "critical")
    assert result["action"] == "circuit_break"


def test_action_block_at_c5() -> None:
    cascade = ComplementCascade({"amplification": 1.1})
    result = cascade.activate(0.71, "ssrf")
    assert result["action"] in {"block", "circuit_break"}


def test_action_monitor_at_c1() -> None:
    cascade = ComplementCascade({"amplification": 1.0})
    result = cascade.activate(0.31, "low")
    assert result["action"] == "monitor"


def test_cascade_stats_tracked() -> None:
    cascade = ComplementCascade()
    cascade.activate(0.95, "critical")
    cascade.activate(0.35, "low")
    stats = cascade.get_cascade_stats()
    assert stats["total_activations"] == 2
    assert "terminal_rate" in stats


@pytest.mark.asyncio
async def test_api_activate_endpoint(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/complement/activate",
            headers=_auth(),
            json={"threat_signal": 0.95, "threat_type": "prompt_injection"},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["terminal_attack"] is True
    assert payload["action"] == "circuit_break"
