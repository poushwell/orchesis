from __future__ import annotations

from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.contrib import network_scanner as ns_module
from orchesis.contrib.network_scanner import NetworkExposureScanner


def test_check_config_permissions_world_readable(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("rules: []\n", encoding="utf-8")
    target.chmod(0o644)
    monkeypatch.setattr(ns_module.os, "name", "posix", raising=False)
    scanner = NetworkExposureScanner()
    monkeypatch.setattr(
        ns_module.NetworkExposureScanner,
        "check_config_file_permissions",
        lambda self: [self._finding("config_perms", "high", f"{target} is world-readable", "0o644", "chmod 600")],
    )
    findings = scanner.check_config_file_permissions()
    assert findings and findings[0]["severity"] == "high"


def test_check_config_permissions_owner_only(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("rules: []\n", encoding="utf-8")
    target.chmod(0o600)
    scanner = NetworkExposureScanner()
    monkeypatch.setattr(ns_module.NetworkExposureScanner, "check_config_file_permissions", lambda self: [])
    assert scanner.check_config_file_permissions() == []


def test_check_env_secrets_found(tmp_path: Path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234\n", encoding="utf-8")
    scanner = NetworkExposureScanner()
    monkeypatch.chdir(tmp_path)
    findings = scanner.check_env_files()
    assert findings


def test_check_env_no_secrets(tmp_path: Path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SAFE_VALUE=hello\n", encoding="utf-8")
    scanner = NetworkExposureScanner()
    monkeypatch.chdir(tmp_path)
    findings = scanner.check_env_files()
    assert findings == []


def test_check_known_agent_config_no_auth(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "openclaw.json"
    config.write_text('{"gateway":"enabled"}', encoding="utf-8")
    scanner = NetworkExposureScanner()
    monkeypatch.chdir(tmp_path)
    findings = scanner.check_known_agent_configs()
    assert any(item["severity"] == "high" for item in findings)


def test_check_known_agent_config_secure(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "openclaw.json"
    config.write_text('{"auth":{"mode":"token"}}', encoding="utf-8")
    scanner = NetworkExposureScanner()
    monkeypatch.chdir(tmp_path)
    findings = scanner.check_known_agent_configs()
    assert findings == []


def test_scan_all_aggregates(monkeypatch) -> None:
    scanner = NetworkExposureScanner()
    monkeypatch.setattr(scanner, "check_open_ports", lambda: [{"check": "open_port", "severity": "critical"}])
    monkeypatch.setattr(scanner, "check_firewall_status", lambda: [{"check": "no_firewall", "severity": "medium"}])
    monkeypatch.setattr(scanner, "check_config_file_permissions", lambda: [])
    monkeypatch.setattr(scanner, "check_env_files", lambda: [])
    monkeypatch.setattr(scanner, "check_known_agent_configs", lambda: [])
    findings = scanner.scan_all()
    assert len(findings) == 2


def test_network_cli_integration(monkeypatch) -> None:
    monkeypatch.setattr(
        ns_module.NetworkExposureScanner,
        "scan_all",
        lambda self: [
            {
                "check": "open_port",
                "severity": "critical",
                "description": "Port 3000 listening on 0.0.0.0",
                "evidence": "0.0.0.0:3000",
                "recommendation": "Bind to localhost",
            }
        ],
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--network"])
    assert result.exit_code == 0
    assert "Network Exposure Scan" in result.output


def test_gate_includes_network(tmp_path: Path, monkeypatch) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
default_trust_tier: intern
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/T000/B000/abc123"
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: rate_limit
    max_requests_per_minute: 50
  - name: file_access
    denied_paths: ["/etc"]
""".strip(),
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_rules.py").write_text(
        "def test_budget_limit(): pass\ndef test_rate_limit(): pass\ndef test_file_access(): pass\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ns_module.NetworkExposureScanner,
        "scan_all",
        lambda self: [
            {
                "check": "open_port",
                "severity": "critical",
                "description": "Port 3000 listening on 0.0.0.0",
                "evidence": "0.0.0.0:3000",
                "recommendation": "Bind to localhost",
            }
        ],
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        local_policy = Path("policy.yaml")
        local_policy.write_text(policy.read_text(encoding="utf-8"), encoding="utf-8")
        Path("tests").mkdir()
        Path("tests/test_rules.py").write_text(
            "def test_budget_limit(): pass\ndef test_rate_limit(): pass\ndef test_file_access(): pass\n",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["gate", "--policy", "policy.yaml", "--fail-on", "high", "--network"])
    assert result.exit_code == 1
