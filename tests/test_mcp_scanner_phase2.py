from __future__ import annotations

import json
from pathlib import Path

from orchesis.scanner import McpConfigScanner


def _scan(tmp_path: Path, server: dict) -> list:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"phase2": server}}), encoding="utf-8")
    return McpConfigScanner().scan(str(path)).findings


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


def test_unpinned_npx(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["mcp-server-fetch"], "auth": "token"})
    assert _has(findings, "version_pinning", "medium")


def test_unpinned_uvx(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "uvx", "args": ["mcp-server-fetch"], "auth": "token"})
    assert _has(findings, "version_pinning", "medium")


def test_latest_tag(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["mcp-server-fetch@latest"], "auth": "token"})
    assert _has(findings, "version_pinning", "medium")


def test_pinned_version_no_finding(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["mcp-server-fetch@1.2.3"], "auth": "token"})
    assert not _has(findings, "version_pinning")


def test_auto_approve_wildcard(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "autoApprove": ["*"]})
    assert _has(findings, "permissions", "high", "wildcard")


def test_auto_approve_true(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "autoApprove": True})
    assert _has(findings, "permissions", "high", "wildcard")


def test_auto_approve_large_list(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {"command": "node", "args": ["app"], "auth": "token", "autoApprove": ["a", "b", "c", "d", "e", "f"]},
    )
    assert _has(findings, "permissions", "high")


def test_auto_approve_small_list_no_finding(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "autoApprove": ["a", "b"]})
    assert not _has(findings, "permissions", "high", "autoApprove")


def test_admin_token_env_key(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "env": {"ADMIN_TOKEN": "x"}})
    assert _has(findings, "permissions", "high", "ADMIN_TOKEN")


def test_root_key_env(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "env": {"ROOT_KEY": "x"}})
    assert _has(findings, "permissions", "high", "ROOT_KEY")


def test_normal_env_key_no_finding(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["app"], "auth": "token", "env": {"API_KEY": "x"}})
    assert not _has(findings, "permissions", "high", "token name")


def test_url_package_install(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["https://example.com/pkg.tgz"], "auth": "token"})
    assert _has(findings, "supply_chain", "high", "URL")


def test_git_plus_https(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["git+https://github.com/org/repo.git"], "auth": "token"})
    assert _has(findings, "supply_chain", "high", "URL")


def test_sensitive_path_ssh(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["~/.ssh/id_rsa"], "auth": "token"})
    assert _has(findings, "file_access", "high")


def test_sensitive_path_sqlite(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["users.sqlite"], "auth": "token"})
    assert _has(findings, "file_access", "high")


def test_broad_path_root(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["/"], "auth": "token"})
    assert _has(findings, "file_access", "high", "overly broad")


def test_broad_path_home(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "node", "args": ["~"], "auth": "token"})
    assert _has(findings, "file_access", "high", "overly broad")


def test_phase1_checks_still_pass(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token"})
    assert _has(findings, "supply_chain_cve", "critical", "CVE-2025-6514")

