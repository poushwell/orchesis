from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.config import load_agent_registry
from orchesis.engine import evaluate
from orchesis.state import RateLimitTracker


def _policy() -> dict:
    return {
        "rules": [],
        "agents": [{"id": "bot", "name": "Bot", "trust_tier": "operator"}],
        "tool_access": {
            "mode": "tiered",
            "tiers": {
                "intern": {"allowed": ["read_file", "send_message"]},
                "assistant": {"allowed": ["read_file", "send_message", "web_search"]},
                "operator": {"allowed": ["*"], "denied": []},
            },
        },
        "channel_policies": {
            "whatsapp": {
                "risk_level": "high",
                "trust_tier": "intern",
                "max_requests_per_minute": 2,
                "denied_tools": ["shell", "write_file", "delete_file", "browser"],
                "require_approval_for": ["send_email"],
            },
            "telegram": {
                "risk_level": "medium",
                "trust_tier": "assistant",
                "max_requests_per_minute": 20,
                "denied_tools": ["shell", "delete_file"],
            },
            "cli": {"risk_level": "low", "trust_tier": "operator", "max_requests_per_minute": 60},
        },
    }


def test_whatsapp_denies_shell() -> None:
    decision = evaluate({"tool": "shell", "params": {}}, _policy(), channel="whatsapp")
    assert decision.allowed is False


def test_whatsapp_rate_limit() -> None:
    state = RateLimitTracker(persist_path=None)
    policy = _policy()
    assert evaluate({"tool": "read_file", "params": {}}, policy, state=state, channel="whatsapp").allowed is True
    assert evaluate({"tool": "read_file", "params": {}}, policy, state=state, channel="whatsapp").allowed is True
    third = evaluate({"tool": "read_file", "params": {}}, policy, state=state, channel="whatsapp")
    assert third.allowed is False
    assert any("exceeded max_requests_per_minute" in item for item in third.reasons)


def test_telegram_allows_more_tools() -> None:
    policy = _policy()
    decision = evaluate(
        {"tool": "web_search", "params": {}, "context": {"agent": "bot"}},
        policy,
        channel="telegram",
        registry=load_agent_registry(policy),
    )
    assert decision.allowed is True


def test_cli_highest_trust() -> None:
    policy = _policy()
    decision = evaluate(
        {"tool": "shell", "params": {}, "context": {"agent": "bot"}},
        policy,
        channel="cli",
        registry=load_agent_registry(policy),
    )
    assert decision.allowed is True


def test_channel_requires_approval() -> None:
    decision = evaluate({"tool": "send_email", "params": {}}, _policy(), channel="whatsapp")
    assert decision.allowed is False
    assert any("requires_human_approval" in item for item in decision.reasons)


def test_channel_trust_tier_min_with_agent() -> None:
    policy = _policy()
    decision = evaluate({"tool": "web_search", "params": {}}, policy, channel="whatsapp")
    assert decision.allowed is False
    assert any("effective tier 'intern'" in item for item in decision.reasons)


def test_no_channel_policy_allows_all() -> None:
    decision = evaluate({"tool": "web_search", "params": {}}, {"rules": []}, channel="telegram")
    assert decision.allowed is True


def test_channel_from_context() -> None:
    decision = evaluate({"tool": "shell", "params": {}, "context": {"channel": "whatsapp"}}, _policy())
    assert decision.allowed is False


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
channel_policies:
  whatsapp:
    denied_tools: ["shell"]
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_api_evaluate_with_channel(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/evaluate",
            headers=_auth(),
            json={
                "tool_name": "shell",
                "params": {"command": "ls"},
                "agent_id": "my-agent",
                "session_type": "group",
                "channel": "whatsapp",
            },
        )
    assert response.status_code == 200
    assert response.json()["allowed"] is False
