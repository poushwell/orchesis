from __future__ import annotations

import json
from pathlib import Path

from orchesis.scanner import McpConfigScanner


def _scan_servers(tmp_path: Path, servers: dict) -> list:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return McpConfigScanner().scan(str(path)).findings


def _scan_one(tmp_path: Path, server: dict) -> list:
    return _scan_servers(tmp_path, {"s1": server})


def _has(findings: list, category: str, severity: str | None = None, needle: str | None = None) -> bool:
    for item in findings:
        if item.category != category:
            continue
        if severity is not None and item.severity != severity:
            continue
        if needle is not None and needle not in item.description and needle not in item.evidence:
            continue
        return True
    return False


def test_sse_http_no_tls(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"url": "http://example.com/sse", "transport": "sse", "auth": "token"})
    assert _has(findings, "transport_security", "high")


def test_sse_https_no_finding(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"url": "https://example.com/sse", "transport": "sse", "auth": "token"})
    assert not _has(findings, "transport_security")


def test_cross_server_exfil(tmp_path: Path) -> None:
    findings = _scan_servers(
        tmp_path,
        {
            "fs": {"command": "mcp-server-filesystem", "auth": "token"},
            "net": {"command": "mcp-server-fetch", "auth": "token"},
        },
    )
    assert _has(findings, "exfiltration_risk", "medium")


def test_single_server_no_exfil(tmp_path: Path) -> None:
    findings = _scan_servers(tmp_path, {"fs": {"command": "mcp-server-filesystem", "auth": "token"}})
    assert not _has(findings, "exfiltration_risk")


def test_shell_server_name(tmp_path: Path) -> None:
    findings = _scan_servers(tmp_path, {"shell-access": {"command": "node server.js", "auth": "token"}})
    assert _has(findings, "shell_execution", "high")


def test_terminal_command(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "terminal-bridge", "auth": "token"})
    assert _has(findings, "shell_execution", "high")


def test_exec_pattern(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "exec-server", "auth": "token"})
    assert _has(findings, "shell_execution", "high")


def test_sudo_in_args(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "bash", "args": ["sudo", "cat", "/etc/hosts"], "auth": "token"})
    assert _has(findings, "privilege_escalation", "critical")


def test_doas_in_args(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "bash", "args": ["doas", "cat", "/etc/hosts"], "auth": "token"})
    assert _has(findings, "privilege_escalation", "critical")


def test_path_traversal_args(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "node", "args": ["../../../etc/passwd"], "auth": "token"})
    assert _has(findings, "path_traversal", "high")


def test_windows_path_traversal(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "node", "args": ["..\\..\\windows\\system32"], "auth": "token"})
    assert _has(findings, "path_traversal", "high")


def test_wildcard_path(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "node", "args": ["/data/*"], "auth": "token"})
    assert _has(findings, "file_access", "medium", "Wildcard glob")


def test_glob_double_star(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"command": "node", "args": ["/home/**"], "auth": "token"})
    assert _has(findings, "file_access", "medium", "Wildcard glob")


def test_cors_missing_remote(tmp_path: Path) -> None:
    findings = _scan_one(tmp_path, {"url": "https://api.example.com/mcp", "auth": "token"})
    assert _has(findings, "cors_missing", "medium")


def test_cors_present_no_finding(tmp_path: Path) -> None:
    findings = _scan_one(
        tmp_path,
        {"url": "https://api.example.com/mcp", "auth": "token", "cors": {"allow": ["https://app.example.com"]}},
    )
    assert not _has(findings, "cors_missing")


def test_excessive_servers(tmp_path: Path) -> None:
    servers = {f"s{i}": {"command": "node", "auth": "token"} for i in range(11)}
    findings = _scan_servers(tmp_path, servers)
    assert _has(findings, "attack_surface", "medium", "11")


def test_ten_servers_no_finding(tmp_path: Path) -> None:
    servers = {f"s{i}": {"command": "node", "auth": "token"} for i in range(10)}
    findings = _scan_servers(tmp_path, servers)
    assert not _has(findings, "attack_surface")


def test_shared_credentials(tmp_path: Path) -> None:
    shared = "TokenValue1234567890"
    findings = _scan_servers(
        tmp_path,
        {
            "a": {"command": "node", "auth": "token", "env": {"API_TOKEN": shared}},
            "b": {"command": "node", "auth": "token", "env": {"SERVICE_TOKEN": shared}},
        },
    )
    assert _has(findings, "credential_sharing", "high")


def test_unique_credentials_no_finding(tmp_path: Path) -> None:
    findings = _scan_servers(
        tmp_path,
        {
            "a": {"command": "node", "auth": "token", "env": {"API_TOKEN": "TokenValue1234567890"}},
            "b": {"command": "node", "auth": "token", "env": {"SERVICE_TOKEN": "OtherValue1234567899"}},
        },
    )
    assert not _has(findings, "credential_sharing")


def test_phase1_phase2_unaffected(tmp_path: Path) -> None:
    findings = _scan_one(
        tmp_path,
        {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token", "autoApprove": True},
    )
    assert _has(findings, "supply_chain_cve", "critical")
    assert _has(findings, "permissions", "high")

