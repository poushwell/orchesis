from __future__ import annotations

import json
from pathlib import Path

from orchesis.config import load_policy, validate_policy
from orchesis.engine import evaluate


def test_production_policy_loads_and_validates() -> None:
    policy_path = Path("examples/production_policy.yaml")
    policy = load_policy(policy_path)

    assert isinstance(policy, dict)
    assert validate_policy(policy) == []


def test_production_policy_blocks_dangerous_operations() -> None:
    policy = load_policy(Path("examples/production_policy.yaml"))
    request = {
        "tool": "run_sql",
        "params": {"query": "DROP TABLE users"},
        "cost": 0.10,
        "context": {"agent": "cursor"},
    }

    decision = evaluate(request, policy)

    assert decision.allowed is False
    assert any(
        marker in reason
        for marker in ("sql_restriction", "regex_match")
        for reason in decision.reasons
    )


def test_production_policy_allows_safe_operations() -> None:
    policy = load_policy(Path("examples/production_policy.yaml"))
    request = {
        "tool": "read_file",
        "params": {"path": "/data/report.csv"},
        "cost": 0.10,
        "context": {"agent": "cursor"},
    }

    decision = evaluate(request, policy)

    assert decision.allowed is True


def test_cursor_config_is_valid_json() -> None:
    config_path = Path("examples/cursor_mcp_config.json")
    loaded = json.loads(config_path.read_text(encoding="utf-8"))

    assert isinstance(loaded, dict)
    assert "mcpServers" in loaded
    assert "orchesis-filesystem" in loaded["mcpServers"]


def test_claude_code_config_is_valid_json() -> None:
    config_path = Path("examples/claude_code_mcp_config.json")
    loaded = json.loads(config_path.read_text(encoding="utf-8"))

    assert isinstance(loaded, dict)
    assert "mcpServers" in loaded
    assert "orchesis-filesystem" in loaded["mcpServers"]
