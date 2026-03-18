from __future__ import annotations

from pathlib import Path

import yaml
from tests.cli_test_utils import CliRunner

from orchesis.cli import main


def test_init_non_interactive_creates_config() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--preset", "openclaw", "--non-interactive"])
        assert result.exit_code == 0
        assert Path("orchesis.yaml").exists()


def test_init_creates_orchesis_dir() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--preset", "claude", "--non-interactive"])
        assert result.exit_code == 0
        assert Path(".orchesis").exists()
        assert Path(".orchesis").is_dir()


def test_init_prints_next_steps() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--preset", "codex", "--non-interactive"])
        assert result.exit_code == 0
        assert "Next steps:" in result.output
        assert "orchesis proxy --config orchesis.yaml" in result.output
        assert "http://localhost:8080/dashboard" in result.output


def test_init_with_budget_option() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["init", "--preset", "openclaw", "--non-interactive", "--budget", "42.5"],
        )
        assert result.exit_code == 0
        data = yaml.safe_load(Path("orchesis.yaml").read_text(encoding="utf-8"))
        assert float(data["budgets"]["daily"]) == 42.5


def test_init_preset_openclaw() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--preset", "openclaw", "--non-interactive"])
        assert result.exit_code == 0
        data = yaml.safe_load(Path("orchesis.yaml").read_text(encoding="utf-8"))
        assert data["agent"]["type"] == "openclaw"
