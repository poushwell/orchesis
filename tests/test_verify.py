"""Tests for orchesis verify checks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from orchesis.cli import main
from orchesis.verify import (
    Severity,
    OrchesisVerifier,
    check_config_schema_injection,
    check_openclaw_compatibility,
    check_openclaw_proxy_routing,
    check_proxy_connectivity,
    discover_mcp_config_paths,
    run_all_checks,
)


class TestConfigSchemaInjection:
    def test_detects_default_true(self, tmp_path: Path) -> None:
        config = {"agents": {"defaults": {"injectConfigSchema": True}}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_config_schema_injection(config_file)

        assert result.severity == Severity.CRITICAL
        assert "100,000" in result.message or "100,000" in (result.detail or "")
        assert result.fix is not None
        assert result.estimated_monthly_cost is not None

    def test_ok_when_explicitly_false(self, tmp_path: Path) -> None:
        config = {"agents": {"defaults": {"injectConfigSchema": False}}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_config_schema_injection(config_file)

        assert result.severity == Severity.OK

    def test_warns_when_missing_key(self, tmp_path: Path) -> None:
        config = {"agents": {}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_config_schema_injection(config_file)

        assert result.severity == Severity.CRITICAL

    def test_warns_when_config_not_found(self) -> None:
        result = check_config_schema_injection(Path("/nonexistent/openclaw.json"))
        assert result.severity == Severity.WARNING

    def test_no_config_path_searches_defaults(self) -> None:
        result = check_config_schema_injection(None)
        assert result.severity in (Severity.WARNING, Severity.CRITICAL, Severity.OK)


class TestProxyConnectivity:
    def test_ok_when_port_open(self) -> None:
        with patch("socket.create_connection") as mock_connection:
            mock_connection.return_value.__enter__.return_value = object()
            mock_connection.return_value.__exit__.return_value = None
            result = check_proxy_connectivity("127.0.0.1", 8080)
        assert result.severity == Severity.OK

    def test_critical_when_connection_refused(self) -> None:
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            result = check_proxy_connectivity("127.0.0.1", 8080)
        assert result.severity == Severity.CRITICAL
        assert result.fix is not None


class TestOpenClawProxyRouting:
    def test_ok_when_routed_to_orchesis(self, tmp_path: Path) -> None:
        config = {"proxy": {"url": "http://localhost:8080", "enabled": True}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_openclaw_proxy_routing(config_file)
        assert result.severity == Severity.OK

    def test_critical_when_no_proxy(self, tmp_path: Path) -> None:
        config = {}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_openclaw_proxy_routing(config_file)
        assert result.severity == Severity.CRITICAL

    def test_warning_when_disabled(self, tmp_path: Path) -> None:
        config = {"proxy": {"url": "http://localhost:8080", "enabled": False}}
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        result = check_openclaw_proxy_routing(config_file)
        assert result.severity == Severity.WARNING


class TestRunAllChecks:
    def test_returns_report_with_all_checks(self, tmp_path: Path) -> None:
        config = {
            "agents": {"defaults": {"injectConfigSchema": False}},
            "proxy": {"url": "http://localhost:8080", "enabled": True},
        }
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")

        with patch("socket.create_connection") as mock_connection:
            mock_connection.return_value.__enter__.return_value = object()
            mock_connection.return_value.__exit__.return_value = None
            report = run_all_checks(openclaw_config_path=config_file)

        assert len(report.results) >= 3
        names = [result.name for result in report.results]
        assert "config_schema_injection" in names
        assert "proxy_connectivity" in names
        assert "openclaw_proxy_routing" in names

    def test_config_schema_check_is_first(self, tmp_path: Path) -> None:
        config_file = tmp_path / "openclaw.json"
        config_file.write_text("{}", encoding="utf-8")

        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            report = run_all_checks(openclaw_config_path=config_file)

        assert report.results[0].name == "config_schema_injection"


class TestOpenClawCompatibility:
    def test_verify_openclaw_compat_pass(self, tmp_path: Path) -> None:
        policy = {
            "threat_intel": {
                "default_action": "block",
                "disabled_threats": ["ORCH-TA-002"],
            },
            "loop_detection": {"openclaw_memory_whitelist": True},
        }
        policy_file = tmp_path / "orchesis.yaml"
        policy_file.write_text(json.dumps(policy), encoding="utf-8")

        result = check_openclaw_compatibility(policy_file)
        assert result.severity == Severity.OK
        assert "OpenClaw-compatible" in result.message

    def test_verify_openclaw_compat_fail(self, tmp_path: Path) -> None:
        policy = {
            "threat_intel": {
                "default_action": "block",
                "disabled_threats": [],
            },
            "loop_detection": {"openclaw_memory_whitelist": True},
        }
        policy_file = tmp_path / "orchesis.yaml"
        policy_file.write_text(json.dumps(policy), encoding="utf-8")

        result = check_openclaw_compatibility(policy_file)
        assert result.severity == Severity.CRITICAL
        assert "issue" in result.message.lower()
        assert result.detail is not None
        assert "ORCH-TA-002" in result.detail

    def test_verify_openclaw_loop_whitelist(self, tmp_path: Path) -> None:
        policy = {
            "threat_intel": {
                "default_action": "warn",
                "disabled_threats": [],
            },
            "loop_detection": {"openclaw_memory_whitelist": False},
        }
        policy_file = tmp_path / "orchesis.yaml"
        policy_file.write_text(json.dumps(policy), encoding="utf-8")

        result = check_openclaw_compatibility(policy_file)
        assert result.severity == Severity.WARNING
        assert result.detail is not None
        assert "whitelist" in result.detail.lower()


class TestOrchesisVerifierExtended:
    """Extended ``orchesis verify`` checks (policy startup, ports, MCP, CLI exit)."""

    def test_verify_reports_policy_status(self, tmp_path: Path) -> None:
        pol = tmp_path / "policy.yaml"
        pol.write_text(
            "proxy:\n  target: https://example.com\n",
            encoding="utf-8",
        )
        verifier = OrchesisVerifier()
        result = verifier._check_policy_startup_validation(str(pol))  # noqa: SLF001
        assert result["status"] in ("PASS", "WARN")
        assert "policy.yaml" in result["message"]
        assert "warning" in result["message"].lower() or "0 warning" in result["message"].lower()

    def test_verify_policy_startup_fail_on_config_error(self, tmp_path: Path) -> None:
        pol = tmp_path / "bad.yaml"
        pol.write_text("{ not valid yaml [[[\n", encoding="utf-8")
        verifier = OrchesisVerifier()
        result = verifier._check_policy_startup_validation(str(pol))  # noqa: SLF001
        assert result["status"] == "FAIL"

    def test_verify_checks_port_availability(self, tmp_path: Path) -> None:
        pol = tmp_path / "p.yaml"
        pol.write_text("rules: []\n", encoding="utf-8")
        verifier = OrchesisVerifier()
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        with patch("orchesis.verify.socket.socket", return_value=mock_sock):
            result = verifier._check_listen_ports_available(str(pol))  # noqa: SLF001
        assert result["status"] == "PASS"
        assert "8080" in result["message"] and "8081" in result["message"]

    def test_verify_ports_warn_when_in_use(self, tmp_path: Path) -> None:
        pol = tmp_path / "p.yaml"
        pol.write_text("rules: []\n", encoding="utf-8")
        verifier = OrchesisVerifier()
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        with patch("orchesis.verify.socket.socket", return_value=mock_sock):
            result = verifier._check_listen_ports_available(str(pol))  # noqa: SLF001
        assert result["status"] == "WARN"

    def test_verify_checks_python_version(self) -> None:
        verifier = OrchesisVerifier()
        result = verifier._check_python_environment()  # noqa: SLF001
        assert result["status"] == "PASS"
        assert "Python" in result["message"]

    def test_verify_python_version_fail_below_310(self) -> None:
        verifier = OrchesisVerifier()
        with patch("sys.version_info", (3, 9, 0)):
            result = verifier._check_python_environment()  # noqa: SLF001
        assert result["status"] == "FAIL"

    def test_verify_discovers_mcp_configs(self, tmp_path: Path) -> None:
        mcp_file = tmp_path / "mcp.json"
        mcp_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        verifier = OrchesisVerifier()
        with patch("orchesis.verify.discover_mcp_config_paths", return_value=[mcp_file]):
            result = verifier._check_mcp_config_discovery()  # noqa: SLF001
        assert result["status"] == "PASS"
        assert "MCP config" in result["message"]
        assert str(mcp_file) in result["message"]

    def test_discover_mcp_config_paths_delegates(self) -> None:
        with patch("orchesis.scanner.discover_mcp_configs", return_value=[]):
            assert discover_mcp_config_paths() == []

    def test_verify_exit_code_zero_on_pass(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "orchesis.yaml").write_text(
            "proxy:\n"
            "  target: https://example.com\n"
            "loop_detection:\n"
            "  enabled: true\n"
            "  block_threshold: 5\n"
            "threat_intel:\n"
            "  enabled: true\n"
            "  disabled_threats: [ORCH-TA-002]\n"
            "budgets:\n"
            "  enabled: true\n"
            "recording:\n"
            "  enabled: true\n",
            encoding="utf-8",
        )
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock(status=200, getcode=lambda: 200)
        mock_cm.__exit__.return_value = None
        with (
            patch("orchesis.verify.socket.socket", return_value=mock_sock),
            patch("urllib.request.urlopen", return_value=mock_cm),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["verify", "--proxy", "http://127.0.0.1:65534"])
        assert result.exit_code == 0, result.output

    def test_verify_exit_code_one_on_fail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "orchesis.yaml").write_text("invalid: [\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "--proxy", "http://127.0.0.1:65534"])
        assert result.exit_code == 1
