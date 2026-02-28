from __future__ import annotations

from orchesis.config import load_agent_registry
from orchesis.engine import evaluate
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier, check_capability
from orchesis.state import RateLimitTracker


def test_trust_tier_ordering() -> None:
    assert TrustTier.BLOCKED < TrustTier.INTERN < TrustTier.ASSISTANT < TrustTier.OPERATOR
    assert TrustTier.OPERATOR < TrustTier.PRINCIPAL


def test_agent_registry_lookup() -> None:
    registry = AgentRegistry(
        agents={
            "cursor": AgentIdentity(
                agent_id="cursor",
                name="Cursor",
                trust_tier=TrustTier.OPERATOR,
            )
        },
        default_tier=TrustTier.INTERN,
    )
    assert registry.get("cursor").trust_tier == TrustTier.OPERATOR
    unknown = registry.get("unknown")
    assert unknown.agent_id == "unknown"
    assert unknown.trust_tier == TrustTier.INTERN


def test_blocked_agent_always_denied() -> None:
    registry = AgentRegistry(
        agents={
            "blocked": AgentIdentity(
                agent_id="blocked",
                name="Blocked",
                trust_tier=TrustTier.BLOCKED,
            )
        }
    )
    request = {"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "blocked"}}
    decision = evaluate(request, {"rules": [{"name": "budget_limit", "max_cost_per_call": 5.0}]}, registry=registry)
    assert decision.allowed is False
    assert "identity: agent 'blocked' is blocked" in decision.reasons


def test_intern_read_only() -> None:
    registry = AgentRegistry(
        agents={
            "intern": AgentIdentity(
                agent_id="intern",
                name="Intern",
                trust_tier=TrustTier.INTERN,
            )
        }
    )
    read = evaluate(
        {"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "intern"}},
        {"rules": []},
        registry=registry,
    )
    write = evaluate(
        {"tool": "write_file", "params": {"path": "/tmp/a"}, "context": {"agent": "intern"}},
        {"rules": []},
        registry=registry,
    )
    delete = evaluate(
        {"tool": "delete_file", "params": {"path": "/tmp/a"}, "context": {"agent": "intern"}},
        {"rules": []},
        registry=registry,
    )
    assert read.allowed is True
    assert write.allowed is False
    assert delete.allowed is False


def test_operator_full_access_within_tools() -> None:
    registry = AgentRegistry(
        agents={
            "op": AgentIdentity(
                agent_id="op",
                name="Operator",
                trust_tier=TrustTier.OPERATOR,
                allowed_tools=["read_file", "write_file"],
            )
        }
    )
    allowed = evaluate(
        {"tool": "write_file", "params": {"path": "/tmp/a"}, "context": {"agent": "op"}},
        {"rules": []},
        registry=registry,
    )
    denied = evaluate(
        {"tool": "run_sql", "params": {"query": "SELECT 1"}, "context": {"agent": "op"}},
        {"rules": []},
        registry=registry,
    )
    assert allowed.allowed is True
    assert denied.allowed is False
    assert any("allowed_tools" in reason for reason in denied.reasons)


def test_principal_bypasses_identity_checks() -> None:
    registry = AgentRegistry(
        agents={
            "admin": AgentIdentity(
                agent_id="admin",
                name="Admin",
                trust_tier=TrustTier.PRINCIPAL,
                allowed_tools=["read_file"],
                denied_tools=["delete_file"],
            )
        }
    )
    allowed = evaluate(
        {"tool": "delete_file", "params": {"path": "/tmp/a"}, "context": {"agent": "admin"}},
        {"rules": []},
        registry=registry,
    )
    denied_by_policy = evaluate(
        {"tool": "api_call", "cost": 2.0, "context": {"agent": "admin"}},
        {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        registry=registry,
    )
    assert allowed.allowed is True
    assert denied_by_policy.allowed is False
    assert any("budget_limit" in reason for reason in denied_by_policy.reasons)


def test_agent_cost_override() -> None:
    registry = AgentRegistry(
        agents={
            "cursor": AgentIdentity(
                agent_id="cursor",
                name="Cursor",
                trust_tier=TrustTier.OPERATOR,
                max_cost_per_call=1.0,
            )
        }
    )
    decision = evaluate(
        {"tool": "api_call", "cost": 2.0, "context": {"agent": "cursor"}},
        {"rules": [{"name": "budget_limit", "max_cost_per_call": 5.0}]},
        registry=registry,
    )
    assert decision.allowed is False
    assert any("max_cost_per_call 1.0" in reason for reason in decision.reasons)


def test_agent_rate_limit_override() -> None:
    registry = AgentRegistry(
        agents={
            "cursor": AgentIdentity(
                agent_id="cursor",
                name="Cursor",
                trust_tier=TrustTier.OPERATOR,
                rate_limit_per_minute=5,
            )
        }
    )
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100}]}
    request = {"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "cursor"}}
    for _ in range(5):
        assert evaluate(request, policy, state=tracker, registry=registry).allowed is True
    sixth = evaluate(request, policy, state=tracker, registry=registry)
    assert sixth.allowed is False
    assert any("max_requests_per_minute 5" in reason for reason in sixth.reasons)


def test_load_registry_from_yaml() -> None:
    policy = {
        "agents": [
            {
                "id": "cursor",
                "name": "Cursor IDE Agent",
                "trust_tier": "operator",
                "allowed_tools": ["read_file", "write_file", "run_sql"],
                "max_cost_per_call": 2.0,
                "daily_budget": 50.0,
            },
            {
                "id": "untrusted_bot",
                "name": "External Bot",
                "trust_tier": "intern",
                "allowed_tools": ["read_file"],
                "rate_limit_per_minute": 10,
            },
            {"id": "admin_agent", "name": "System Admin", "trust_tier": "principal"},
        ],
        "default_trust_tier": "intern",
        "rules": [],
    }
    registry = load_agent_registry(policy)
    assert registry.default_tier == TrustTier.INTERN
    assert registry.get("cursor").trust_tier == TrustTier.OPERATOR
    assert registry.get("cursor").allowed_tools == ["read_file", "write_file", "run_sql"]
    assert registry.get("untrusted_bot").rate_limit_per_minute == 10
    assert registry.get("admin_agent").trust_tier == TrustTier.PRINCIPAL


def test_capability_check() -> None:
    intern = AgentIdentity(agent_id="i", name="Intern", trust_tier=TrustTier.INTERN)
    operator = AgentIdentity(agent_id="o", name="Operator", trust_tier=TrustTier.OPERATOR)
    assert check_capability(intern, "read_file") is True
    assert check_capability(intern, "delete_file") is False
    assert check_capability(operator, "delete_file") is True


def test_backward_compatible_no_registry() -> None:
    request = {"tool": "write_file", "params": {"path": "/tmp/out.txt"}, "cost": 0.0}
    policy = {"rules": []}
    decision = evaluate(request, policy)
    assert decision.allowed is True
