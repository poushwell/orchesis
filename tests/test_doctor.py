from __future__ import annotations

from pathlib import Path

import yaml
from tests.cli_test_utils import CliRunner

from orchesis.cli import main


ROOT = Path(__file__).resolve().parents[1]


def test_doctor_python_version() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert "python_version" in result.output


def test_doctor_package_installed() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert "package_installed" in result.output


def test_doctor_no_config() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["doctor", "--policy", "missing.yaml"])
        assert result.exit_code == 1
        assert "config_found" in result.output


def test_doctor_port_check() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert "dashboard_port_8080" in result.output


def test_doctor_output_format() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml"])
        assert "Orchesis Doctor v" in result.output
        assert "Doctor checks:" in result.output


def test_doctor_config_alias_works() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("orchesis.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--config", "orchesis.yaml"])
        assert "config_found" in result.output


def test_github_actions_test_yml_exists() -> None:
    assert (ROOT / ".github" / "workflows" / "test.yml").exists()


def test_github_actions_lint_yml_exists() -> None:
    assert (ROOT / ".github" / "workflows" / "lint.yml").exists()


def test_github_actions_valid_yaml() -> None:
    test_data = yaml.safe_load((ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8"))
    lint_data = yaml.safe_load((ROOT / ".github" / "workflows" / "lint.yml").read_text(encoding="utf-8"))
    assert isinstance(test_data, dict)
    assert isinstance(lint_data, dict)


def test_test_workflow_runs_quickstart() -> None:
    content = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    assert "orchesis quickstart --preset minimal --non-interactive" in content

