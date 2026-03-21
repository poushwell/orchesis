"""Tests for orchesis verify checks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from orchesis.verify import (
    Severity,
    check_config_schema_injection,
    check_openclaw_proxy_routing,
    check_proxy_connectivity,
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
