from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = REPO_ROOT / "integrations"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _exists(rel_path: str) -> bool:
    return (INTEGRATIONS / rel_path).exists()


def test_npm_package_json_exists() -> None:
    assert _exists("npm-cli/package.json")


def test_npm_package_name() -> None:
    package = json.loads(_read(INTEGRATIONS / "npm-cli" / "package.json"))
    assert package["name"] == "orchesis-scan"


def test_npm_bin_script_exists() -> None:
    assert _exists("npm-cli/bin/orchesis-scan.js")


def test_npm_readme_exists() -> None:
    assert _exists("npm-cli/README.md")


def test_github_action_yml_exists() -> None:
    assert _exists("github-action/action.yml")


def test_github_action_inputs() -> None:
    action_text = _read(INTEGRATIONS / "github-action" / "action.yml")
    assert "inputs:" in action_text
    assert "config-path:" in action_text
    assert "fail-on:" in action_text
    assert "min-severity:" in action_text


def test_github_action_outputs() -> None:
    action_text = _read(INTEGRATIONS / "github-action" / "action.yml")
    assert "outputs:" in action_text
    assert "risk-score:" in action_text
    assert "findings-count:" in action_text


def test_github_action_readme_exists() -> None:
    assert _exists("github-action/README.md")


def test_precommit_hooks_yaml_exists() -> None:
    assert _exists("pre-commit/.pre-commit-hooks.yaml")


def test_precommit_hook_id() -> None:
    hooks_text = _read(INTEGRATIONS / "pre-commit" / ".pre-commit-hooks.yaml")
    assert "id: orchesis-mcp-scan" in hooks_text


def test_precommit_files_pattern() -> None:
    hooks_text = _read(INTEGRATIONS / "pre-commit" / ".pre-commit-hooks.yaml")
    assert "mcp\\.json" in hooks_text


def test_precommit_script_exists() -> None:
    assert _exists("pre-commit/orchesis_pre_commit.py")


def test_precommit_readme_exists() -> None:
    assert _exists("pre-commit/README.md")


def test_npm_cli_has_auto_discover() -> None:
    cli_script = _read(INTEGRATIONS / "npm-cli" / "bin" / "orchesis-scan.js")
    assert ".config/claude/claude_desktop_config.json" in cli_script
    assert ".cursor/mcp.json" in cli_script
    assert ".vscode/mcp.json" in cli_script
    assert ".claude/mcp.json" in cli_script


def test_github_action_uses_composite() -> None:
    action_text = _read(INTEGRATIONS / "github-action" / "action.yml")
    assert "runs:" in action_text
    assert "using: 'composite'" in action_text
