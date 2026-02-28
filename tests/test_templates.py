from __future__ import annotations

from pathlib import Path

from orchesis.config import load_policy
from orchesis.templates import TEMPLATE_NAMES, load_template_text, template_path


def test_template_files_exist() -> None:
    for name in TEMPLATE_NAMES:
        assert template_path(name).exists(), f"Missing template: {name}"


def test_all_templates_load_as_valid_yaml(tmp_path: Path) -> None:
    for name in TEMPLATE_NAMES:
        target = tmp_path / f"{name}.yaml"
        target.write_text(load_template_text(name), encoding="utf-8")
        policy = load_policy(target)
        assert isinstance(policy, dict)
        assert "rules" in policy


def test_minimal_template_has_required_rules() -> None:
    text = load_template_text("minimal")
    assert "file_access" in text
    assert "budget_limit" in text
    assert "rate_limit" in text


def test_strict_template_has_identity_and_regex() -> None:
    text = load_template_text("strict")
    assert "default_trust_tier" in text
    assert "agents:" in text
    assert "regex_match" in text


def test_mcp_and_multi_agent_templates_have_agents() -> None:
    mcp_text = load_template_text("mcp_development")
    multi_text = load_template_text("multi_agent")
    assert "cursor" in mcp_text
    assert "claude_code" in mcp_text
    assert "orchestrator" in multi_text
