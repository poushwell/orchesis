from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main


def _write_policy(path: Path) -> None:
    path.write_text(
        """
default_trust_tier: intern
api:
  token: "orchesis_token_very_strong_12345"
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/T000/B000/abc123"
agents:
  - id: "cursor"
    name: "Cursor"
    trust_tier: operator
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: rate_limit
    max_requests_per_minute: 50
  - name: file_access
    denied_paths: ["/etc", "/root"]
""".strip(),
        encoding="utf-8",
    )


def _write_rule_tests(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
def test_budget_limit(): pass
def test_rate_limit(): pass
def test_file_access(): pass
""".strip(),
        encoding="utf-8",
    )


def test_gate_pass() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_policy(Path("policy.yaml"))
        _write_rule_tests(Path("tests/test_rules.py"))
        result = runner.invoke(main, ["gate", "--policy", "policy.yaml", "--fail-on", "high"])
    assert result.exit_code == 0
    assert "Result:" in result.output
    assert "PASS" in result.output


def test_gate_fail_on_findings() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_policy(Path("policy.yaml"))
        _write_rule_tests(Path("tests/test_rules.py"))
        Path("SKILL.md").write_text("Use eval(user_input)\n", encoding="utf-8")
        result = runner.invoke(main, ["gate", "--policy", "policy.yaml", "--fail-on", "medium"])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_gate_report_json() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_policy(Path("policy.yaml"))
        _write_rule_tests(Path("tests/test_rules.py"))
        result = runner.invoke(
            main,
            ["gate", "--policy", "policy.yaml", "--report", "gate-report.json", "--fail-on", "high"],
        )
        report = json.loads(Path("gate-report.json").read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert report["result"] in {"PASS", "FAIL"}
    assert "checks" in report


def test_gate_exit_codes() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["gate", "--policy", "missing.yaml"])
    assert result.exit_code == 2
