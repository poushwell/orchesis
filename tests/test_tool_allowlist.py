from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier


def test_allowlist_permits_allowed_tool() -> None:
    policy = {"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []}
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy)
    assert decision.allowed is True


def test_allowlist_denies_unlisted_tool() -> None:
    policy = {"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []}
    decision = evaluate({"tool": "write_file", "params": {}, "cost": 0.0}, policy)
    assert decision.allowed is False
    assert any("tool_access_control" in reason for reason in decision.reasons)


def test_allowlist_agent_override() -> None:
    policy = {
        "tool_access": {
            "mode": "allowlist",
            "allowed": ["read_file"],
            "overrides": {"agent_admin": {"additional_allowed": ["write_file"]}},
        },
        "rules": [],
    }
    request = {"tool": "write_file", "params": {}, "cost": 0.0, "context": {"agent": "agent_admin"}}
    decision = evaluate(request, policy)
    assert decision.allowed is True


def test_denylist_permits_unlisted_tool() -> None:
    policy = {"tool_access": {"mode": "denylist", "denied": ["shell_execute"]}, "rules": []}
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, policy)
    assert decision.allowed is True


def test_denylist_denies_listed_tool() -> None:
    policy = {"tool_access": {"mode": "denylist", "denied": ["shell_execute"]}, "rules": []}
    decision = evaluate({"tool": "shell_execute", "params": {}, "cost": 0.0}, policy)
    assert decision.allowed is False


def test_tiered_intern_restricted() -> None:
    policy = {
        "tool_access": {"mode": "tiered", "tiers": {"intern": ["read_file"], "operator": ["*"]}},
        "rules": [],
    }
    decision = evaluate({"tool": "write_file", "params": {}, "cost": 0.0}, policy)
    assert decision.allowed is False


def test_tiered_operator_wildcard() -> None:
    registry = AgentRegistry(
        agents={"op": AgentIdentity(agent_id="op", name="op", trust_tier=TrustTier.OPERATOR)}
    )
    policy = {"tool_access": {"mode": "tiered", "tiers": {"operator": {"allowed": ["*"]}}}, "rules": []}
    request = {"tool": "write_file", "params": {}, "cost": 0.0, "context": {"agent": "op"}}
    decision = evaluate(request, policy, registry=registry)
    assert decision.allowed is True


def test_tiered_operator_denied_override() -> None:
    registry = AgentRegistry(
        agents={"op": AgentIdentity(agent_id="op", name="op", trust_tier=TrustTier.OPERATOR)}
    )
    policy = {
        "tool_access": {
            "mode": "tiered",
            "tiers": {"operator": {"allowed": ["*"], "denied": ["shell_execute"]}},
        },
        "rules": [],
    }
    request = {"tool": "shell_execute", "params": {}, "cost": 0.0, "context": {"agent": "op"}}
    decision = evaluate(request, policy, registry=registry)
    assert decision.allowed is False


def test_no_tool_access_config_allows_all() -> None:
    decision = evaluate({"tool": "any_tool", "params": {}, "cost": 0.0}, {"rules": []})
    assert decision.allowed is True
