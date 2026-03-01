from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier


def _session_policy() -> dict:
    return {
        "tool_access": {"mode": "denylist", "denied": ["format_disk"]},
        "session_policies": {
            "group": {
                "trust_tier": "intern",
                "tool_access": {"mode": "allowlist", "allowed": ["web_search", "read_file", "send_message"]},
                "max_tokens_per_call": 2000,
                "denied_paths": ["~/.ssh", "~/.aws", "~/.config", ".env"],
            },
            "dm": {
                "trust_tier": "assistant",
                "tool_access": {"mode": "denylist", "denied": ["shell_execute", "format_disk"]},
            },
            "background": {
                "trust_tier": "intern",
                "tool_access": {"mode": "allowlist", "allowed": ["web_search", "send_message"]},
                "max_tokens_per_call": 1000,
                "budget_per_session": 0.50,
            },
            "cli": {
                "trust_tier": "operator",
                "tool_access": {"mode": "denylist", "denied": ["format_disk"]},
            },
        },
        "rules": [],
    }


def test_group_session_restricted() -> None:
    decision = evaluate({"tool": "write_file", "params": {}, "cost": 0.0}, _session_policy(), session_type="group")
    assert decision.allowed is False


def test_dm_session_normal() -> None:
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, _session_policy(), session_type="dm")
    assert decision.allowed is True


def test_background_session_minimal() -> None:
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, _session_policy(), session_type="background")
    assert decision.allowed is False


def test_cli_session_high_trust() -> None:
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, _session_policy(), session_type="cli")
    assert decision.allowed is True


def test_session_tier_override_lower() -> None:
    registry = AgentRegistry(
        agents={"op": AgentIdentity(agent_id="op", name="op", trust_tier=TrustTier.OPERATOR)}
    )
    policy = {
        "tool_access": {"mode": "tiered", "tiers": {"intern": ["read_file"], "operator": {"allowed": ["*"]}}},
        "session_policies": {"group": {"trust_tier": "intern"}},
        "rules": [],
    }
    request = {"tool": "write_file", "params": {}, "cost": 0.0, "context": {"agent": "op"}}
    decision = evaluate(request, policy, registry=registry, session_type="group")
    assert decision.allowed is False


def test_session_denied_paths() -> None:
    request = {"tool": "read_file", "params": {"path": "~/.ssh/id_rsa"}, "cost": 0.0}
    decision = evaluate(request, _session_policy(), session_type="group")
    assert decision.allowed is False
    assert any("denied for session 'group'" in reason for reason in decision.reasons)


def test_session_token_limit() -> None:
    request = {
        "tool": "read_file",
        "params": {},
        "cost": 0.0,
        "context": {"estimated_tokens": 3000},
    }
    decision = evaluate(request, _session_policy(), session_type="group")
    assert decision.allowed is False
    assert any("token limit exceeded" in reason for reason in decision.reasons)


def test_no_session_policy_defaults() -> None:
    policy = {"tool_access": {"mode": "denylist", "denied": ["shell_execute"]}, "rules": []}
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy, session_type="unknown")
    assert decision.allowed is True
