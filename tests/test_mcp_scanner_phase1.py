from __future__ import annotations

import json
from pathlib import Path

from orchesis.scanner import McpConfigScanner


def _scan_server(tmp_path: Path, server: dict) -> list:
    path = tmp_path / "mcp.json"
    payload = {"mcpServers": {"s1": server}}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return McpConfigScanner().scan(str(path)).findings


def _has(findings: list, category: str, severity: str | None = None, needle: str | None = None) -> bool:
    for item in findings:
        if item.category != category:
            continue
        if severity is not None and item.severity != severity:
            continue
        if needle is not None and needle not in item.evidence and needle not in item.description:
            continue
        return True
    return False


def test_cve_vulnerable_package(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["mcp-remote@0.1.15"], "auth": "token"})
    assert _has(findings, "supply_chain_cve", "critical", "CVE-2025-6514")


def test_cve_fixed_version_no_finding(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["mcp-remote@0.1.17"], "auth": "token"})
    assert not _has(findings, "supply_chain_cve")


def test_malicious_package_blocked(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["mcp-server-free"], "auth": "token"})
    assert _has(findings, "malicious_package", "critical", "mcp-server-free")


def test_typosquatting_detected(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["mcp-server-filesytem"], "auth": "token"})
    assert _has(findings, "typosquatting", "high")


def test_typosquatting_exact_match_no_finding(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["mcp-server-filesystem"], "auth": "token"})
    assert not _has(findings, "typosquatting")


def test_unsafe_npx_y(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["-y", "mcp-server-fetch"], "auth": "token"})
    assert _has(findings, "supply_chain", "high", "npx -y")


def test_npx_y_with_version_no_finding(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "npx", "args": ["-y", "mcp-server-fetch@1.0.0"], "auth": "token"})
    assert not _has(findings, "supply_chain", "high", "npx -y")


def test_entropy_secret_in_args(tmp_path: Path) -> None:
    token = "A9f2K1x0Qw7Lm3N8Zp4Rt6Yv2Hb9Jk3"
    findings = _scan_server(tmp_path, {"command": "node", "args": [token], "auth": "token"})
    assert _has(findings, "secret_leak", "high", "High-entropy")


def test_low_entropy_no_finding(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "node", "args": ["normal-argument-123"], "auth": "token"})
    assert not _has(findings, "secret_leak", "high", "High-entropy")


def test_aws_key_in_env(tmp_path: Path) -> None:
    findings = _scan_server(
        tmp_path,
        {"command": "node", "args": ["app"], "env": {"AWS_ACCESS_KEY_ID": "AKIA1234567890ABCDEF"}, "auth": "token"},
    )
    assert _has(findings, "secret_leak", "critical", "AWS Access Key")


def test_github_pat_in_args(tmp_path: Path) -> None:
    findings = _scan_server(
        tmp_path,
        {"command": "node", "args": ["ghp_abcdefghijklmnopqrstuvwxyz1234567890"], "auth": "token"},
    )
    assert _has(findings, "secret_leak", "critical", "GitHub PAT")


def test_anthropic_key_detected(tmp_path: Path) -> None:
    findings = _scan_server(
        tmp_path,
        {"command": "node", "args": ["sk-ant-abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-1234"], "auth": "token"},
    )
    assert _has(findings, "secret_leak", "critical", "Anthropic API Key")


def test_jwt_detected(tmp_path: Path) -> None:
    jwt = "ey" + "A" * 25 + "." + "B" * 25 + "." + "C" * 25
    findings = _scan_server(tmp_path, {"command": "node", "args": [jwt], "auth": "token"})
    assert _has(findings, "secret_leak", "high", "JWT Token")


def test_privileged_mode(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--privileged"], "auth": "token"})
    assert _has(findings, "docker_security", "critical", "--privileged")


def test_docker_socket_mount(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock"], "auth": "token"})
    assert _has(findings, "docker_security", "critical", "/var/run/docker.sock")


def test_sensitive_ssh_mount(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "-v", "~/.ssh:/root/.ssh:ro"], "auth": "token"})
    assert _has(findings, "docker_security", "critical", "~/.ssh")


def test_network_host(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--network=host"], "auth": "token"})
    assert _has(findings, "docker_security", "high", "--network=host")


def test_mount_without_ro(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "-v", "~/.aws:/root/.aws"], "auth": "token"})
    assert _has(findings, "docker_security", "high", "read-only")


def test_running_as_root(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "alpine:3.20"], "auth": "token"})
    assert _has(findings, "docker_security", "medium", "runs as root")


def test_no_resource_limits(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--user", "1000:1000", "alpine:3.20"], "auth": "token"})
    assert _has(findings, "docker_security", "medium", "resource limits")


def test_seccomp_unconfined(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--security-opt", "seccomp=unconfined"], "auth": "token"})
    assert _has(findings, "docker_security", "high", "unconfined")


def test_dangerous_cap_add(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--cap-add", "SYS_ADMIN"], "auth": "token"})
    assert _has(findings, "docker_security", "high", "SYS_ADMIN")


def test_image_no_digest(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"command": "docker", "args": ["run", "--user", "1000:1000", "--memory=256m"], "image": "docker.io/library/alpine", "auth": "token"})
    assert _has(findings, "docker_security", "medium", "digest or tag")


def test_clean_config_no_docker_findings(tmp_path: Path) -> None:
    findings = _scan_server(
        tmp_path,
        {
            "command": "docker",
            "args": [
                "run",
                "--user",
                "1000:1000",
                "--memory=256m",
                "--cpus=1",
                "--pids-limit=128",
                "-v",
                "/workspace:/workspace:ro",
                "--cap-add",
                "CHOWN",
                "alpine:3.20",
            ],
            "auth": "token",
            "docker": {"user": "1000:1000"},
            "image": "docker.io/library/alpine:3.20@sha256:abc",
        },
    )
    assert not any(item.category == "docker_security" and item.severity in {"critical", "high", "medium"} for item in findings)


def test_existing_checks_still_pass(tmp_path: Path) -> None:
    findings = _scan_server(tmp_path, {"url": "http://0.0.0.0:8080", "tools": ["*"]})
    categories = {item.category for item in findings}
    assert "binding_exposure" in categories
    assert "no_auth" in categories
    assert "dangerous_tools" in categories

