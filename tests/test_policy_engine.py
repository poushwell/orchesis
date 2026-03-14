from __future__ import annotations

from pathlib import Path

from orchesis.policy_engine import PolicyEngine
from orchesis.tool_policy import ToolPolicyEngine


def _base_policy() -> dict:
    return {
        "version": "1.0",
        "name": "production-policy",
        "default_action": "deny",
        "variables": {
            "trusted_agents": ["openclaw", "cursor"],
            "sensitive_tools": ["bash", "exec", "eval"],
        },
        "rules": [
            {
                "id": "block-sensitive-tools",
                "description": "Block dangerous shell tools",
                "when": {"tool": {"in": "$sensitive_tools"}},
                "action": "block",
                "priority": 100,
            },
            {
                "id": "allow-trusted-agents",
                "description": "Trusted agents get broader access",
                "when": {
                    "agent_id": {"in": "$trusted_agents"},
                    "tool": {"not_in": "$sensitive_tools"},
                },
                "action": "allow",
                "priority": 90,
            },
            {
                "id": "rate-limit-search",
                "description": "Limit search calls per session",
                "when": {"tool": {"eq": "web_search"}, "session_calls": {"gt": 10}},
                "action": "block",
                "priority": 80,
            },
            {
                "id": "warn-on-file-write",
                "description": "Warn when writing files",
                "when": {"tool": {"matches": "write_*"}},
                "action": "warn",
                "priority": 70,
            },
        ],
    }


def test_from_dict_basic() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    assert len(engine.get_rules()) == 4


def test_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: "1.0"
name: "production-policy"
default_action: deny
rules:
  - id: "r1"
    description: "desc"
    when:
      tool: {eq: "bash"}
    action: block
    priority: 10
""".strip()
        + "\n",
        encoding="utf-8",
    )
    engine = PolicyEngine.from_yaml(str(path))
    assert len(engine.get_rules()) == 1


def test_evaluate_eq() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="web_search", session_calls=11)
    assert result.action == "block"


def test_evaluate_in_list() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="bash")
    assert result.action == "block"


def test_evaluate_in_variable() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="eval")
    assert result.action == "block"


def test_evaluate_not_in() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="read_file", agent_id="openclaw")
    assert result.action == "allow"


def test_evaluate_matches_glob() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="write_file")
    assert result.action == "warn"


def test_evaluate_startswith() -> None:
    policy = {
        "default_action": "deny",
        "rules": [
            {"id": "r", "description": "d", "when": {"tool": {"startswith": "file"}}, "action": "allow", "priority": 1}
        ],
    }
    engine = PolicyEngine.from_dict(policy)
    result = engine.evaluate(tool_name="file_read")
    assert result.action == "allow"


def test_evaluate_gt_session_calls() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="web_search", session_calls=12)
    assert result.action == "block"


def test_evaluate_lte() -> None:
    policy = {
        "default_action": "deny",
        "rules": [
            {"id": "r", "description": "d", "when": {"token_count": {"lte": 1000}}, "action": "allow", "priority": 1}
        ],
    }
    engine = PolicyEngine.from_dict(policy)
    result = engine.evaluate(tool_name="read_file", token_count=500)
    assert result.action == "allow"


def test_evaluate_multi_condition_and() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    ok = engine.evaluate(tool_name="read_file", agent_id="openclaw")
    no = engine.evaluate(tool_name="bash", agent_id="openclaw")
    assert ok.action == "allow"
    assert no.action == "block"


def test_evaluate_priority_order() -> None:
    policy = {
        "default_action": "deny",
        "rules": [
            {"id": "low", "description": "d", "when": {"tool": {"contains": "write"}}, "action": "warn", "priority": 1},
            {"id": "high", "description": "d", "when": {"tool": {"contains": "write"}}, "action": "block", "priority": 10},
        ],
    }
    engine = PolicyEngine.from_dict(policy)
    result = engine.evaluate(tool_name="write_file")
    assert result.action == "block"
    assert result.rule_id == "high"


def test_evaluate_default_action() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="unknown")
    assert result.action == "block"
    assert result.matched is False


def test_evaluate_no_match_allow_default() -> None:
    policy = {"default_action": "allow", "rules": []}
    engine = PolicyEngine.from_dict(policy)
    result = engine.evaluate(tool_name="anything")
    assert result.action == "allow"
    assert result.matched is False


def test_variables_resolved() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    vars_map = engine.get_variables()
    assert "sensitive_tools" in vars_map
    assert "bash" in vars_map["sensitive_tools"]


def test_variables_not_found() -> None:
    policy = {
        "default_action": "deny",
        "rules": [
            {"id": "x", "description": "x", "when": {"tool": {"in": "$missing_var"}}, "action": "allow", "priority": 1}
        ],
    }
    engine = PolicyEngine.from_dict(policy)
    result = engine.evaluate(tool_name="bash")
    assert result.matched is False
    assert result.action == "block"


def test_integration_with_tool_policy_engine() -> None:
    pe = PolicyEngine.from_dict(_base_policy())
    tpe = ToolPolicyEngine({"default_action": "allow", "rules": {}}, policy_engine=pe)
    decision = tpe.evaluate(tool_name="bash", agent_id="x", session_id="s1")
    assert decision.action == "block"
    assert decision.rule_source == "policy_engine"


def test_tool_policy_fallthrough() -> None:
    pe = PolicyEngine.from_dict({"default_action": "deny", "rules": []})
    tpe = ToolPolicyEngine({"default_action": "allow", "rules": {"read_file": "allow"}}, policy_engine=pe)
    decision = tpe.evaluate(tool_name="read_file", agent_id="x", session_id="s1")
    assert decision.action == "allow"
    assert decision.rule_source == "explicit_rule"


def test_policy_rule_description_in_result() -> None:
    engine = PolicyEngine.from_dict(_base_policy())
    result = engine.evaluate(tool_name="bash")
    assert result.rule_description == "Block dangerous shell tools"


def test_empty_policy() -> None:
    engine = PolicyEngine.from_dict({})
    result = engine.evaluate(tool_name="read")
    assert result.action == "block"
    assert result.matched is False

