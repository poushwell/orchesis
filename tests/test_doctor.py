from __future__ import annotations

import json
from pathlib import Path

import yaml
from tests.cli_test_utils import CliRunner

from orchesis.cli import main


ROOT = Path(__file__).resolve().parents[1]


def _run_doctor(args: list[str]) -> tuple[int, str]:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml", *args])
        return result.exit_code, result.output


def test_all_checks_run() -> None:
    _, output = _run_doctor([])
    required = [
        "python_version",
        "pyyaml_installed",
        "config_exists",
        "config_valid",
        "proxy_running",
        "api_running",
        "disk_space",
        "log_rotation",
        "api_key_configured",
        "semantic_cache_enabled",
        "loop_detection_enabled",
        "recording_enabled",
    ]
    for check_name in required:
        assert check_name in output


def test_fix_flag_attempts_repairs() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        big_log = Path("decisions.jsonl")
        big_log.write_bytes(b"x" * (100 * 1024 * 1024 + 128))
        result = runner.invoke(main, ["doctor", "--config", "missing.yaml", "--fix"])
        assert result.exit_code == 0
        assert Path("missing.yaml").exists()
        assert Path(".orchesis").exists()
        assert big_log.stat().st_size == 0
        assert Path("decisions.jsonl.1").exists()


def test_json_output_valid() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["doctor", "--policy", "policy.yaml", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert "checks" in payload
        assert "summary" in payload
        assert isinstance(payload["checks"], list)


def test_severity_levels_assigned() -> None:
    _, output = _run_doctor([])
    assert "[ERROR]" in output
    assert "[WARNING]" in output
    assert "[INFO]" in output


def test_api_key_check() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(
            main,
            ["doctor", "--policy", "policy.yaml"],
            env={"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""},
        )
        assert "api_key_configured" in result.output
        assert "not set" in result.output


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

