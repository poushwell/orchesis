from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main


def test_new_creates_project_files() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["new", "demo"])
        assert result.exit_code == 0
        assert Path("demo/policy.yaml").exists()
        assert Path("demo/request.json").exists()
        assert Path("demo/README.md").exists()


def test_new_uses_selected_template() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["new", "demo", "--template", "strict"])
        assert result.exit_code == 0
        text = Path("demo/policy.yaml").read_text(encoding="utf-8")
        assert "default_trust_tier" in text
        assert "regex_match" in text


def test_new_refuses_overwrite_without_force() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("demo").mkdir(parents=True, exist_ok=True)
        Path("demo/policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["new", "demo"])
        assert result.exit_code != 0
        assert "Refusing to overwrite" in result.output


def test_new_force_overwrites_existing_files() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("demo").mkdir(parents=True, exist_ok=True)
        Path("demo/policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["new", "demo", "--template", "multi_agent", "--force"])
        assert result.exit_code == 0
        text = Path("demo/policy.yaml").read_text(encoding="utf-8")
        assert "orchestrator" in text


def test_doctor_passes_for_valid_project() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _ = runner.invoke(main, ["new", ".", "--force"])
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert result.exit_code == 0
        assert "Doctor checks:" in result.output
        assert "python_version" in result.output


def test_doctor_fails_for_invalid_policy() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: [{}]\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert result.exit_code == 1
        assert "policy_validate" in result.output
