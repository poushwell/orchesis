from __future__ import annotations

from pathlib import Path

from orchesis.config import load_policy


def test_skill_md_exists() -> None:
    assert Path("integrations/openclaw/SKILL.md").exists()


def test_example_policy_valid() -> None:
    policy = load_policy("integrations/openclaw/example_policy.yaml")
    assert isinstance(policy, dict)
    assert isinstance(policy.get("rules"), list)


def test_readme_exists() -> None:
    assert Path("integrations/openclaw/README.md").exists()
