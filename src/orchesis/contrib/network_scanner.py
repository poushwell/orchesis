"""Local-only network exposure scanner."""

from __future__ import annotations

import os
import platform
import socket
import stat
from pathlib import Path
from typing import Any

from orchesis.contrib.secret_scanner import SecretScanner


class NetworkExposureScanner:
    """Scan local environment for network exposure risks."""

    def __init__(self):
        self._secret_scanner = SecretScanner()

    def scan_all(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for method in (
            self.check_open_ports,
            self.check_firewall_status,
            self.check_config_file_permissions,
            self.check_env_files,
            self.check_known_agent_configs,
        ):
            try:
                findings.extend(method())
            except Exception:
                continue
        return findings

    def check_open_ports(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        ports = [3000, 3001, 8080, 8081, 18789, 9090, 5432, 3306, 27017]
        for port in ports:
            try:
                localhost_open = self._can_connect("127.0.0.1", port)
                zero_open = self._can_connect("0.0.0.0", port)
                if localhost_open and zero_open:
                    findings.append(
                        self._finding(
                            "open_port",
                            "critical",
                            f"Port {port} appears externally accessible",
                            f"0.0.0.0:{port}",
                            "Bind service to 127.0.0.1 or enforce authentication.",
                        )
                    )
                elif localhost_open:
                    findings.append(
                        self._finding(
                            "localhost_ws",
                            "info",
                            f"Port {port} listening on localhost",
                            f"127.0.0.1:{port}",
                            "Localhost services can still be targeted via browser-based attacks.",
                        )
                    )
            except Exception:
                continue
        return findings

    def check_firewall_status(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        try:
            os_name = platform.system().lower()
            if os_name == "windows":
                return [self._finding("firewall_status", "info", "Firewall status check limited on Windows", "netsh required", "Verify Windows Defender Firewall is enabled.")]
            if os_name == "darwin":
                if not Path("/etc/pf.conf").exists():
                    findings.append(
                        self._finding(
                            "no_firewall",
                            "medium",
                            "No pf firewall configuration detected",
                            "/etc/pf.conf missing",
                            "Enable pf or host firewall controls.",
                        )
                    )
            else:
                if not any(Path(path).exists() for path in ("/sbin/iptables", "/usr/sbin/nft")):
                    findings.append(
                        self._finding(
                            "no_firewall",
                            "medium",
                            "No firewall tooling detected",
                            "iptables/nft not found",
                            "Enable ufw/iptables/nftables.",
                        )
                    )
        except Exception:
            return []
        return findings

    def check_config_file_permissions(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        candidates = [
            Path.home() / ".clawdbot",
            Path.home() / ".config" / "claude",
            Path.home() / ".cursor" / "mcp.json",
            Path(".vscode") / "mcp.json",
            Path("policy.yaml"),
            Path(".env"),
            Path(".env.local"),
            Path(".env.production"),
            Path("openclaw.json"),
            Path("device.json"),
            Path("soul.md"),
        ]
        if os.name == "nt":
            return findings
        for path in candidates:
            try:
                if not path.exists():
                    continue
                st_mode = path.stat().st_mode
                if bool(st_mode & stat.S_IROTH):
                    findings.append(
                        self._finding(
                            "config_perms",
                            "high",
                            f"{path} is world-readable",
                            oct(st_mode & 0o777),
                            f"chmod 600 {path}",
                        )
                    )
                elif bool(st_mode & stat.S_IRGRP):
                    findings.append(
                        self._finding(
                            "config_perms",
                            "medium",
                            f"{path} is group-readable",
                            oct(st_mode & 0o777),
                            f"chmod 640 or stricter for {path}",
                        )
                    )
            except Exception:
                continue
        return findings

    def check_env_files(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        env_paths = [
            Path(".env"),
            Path(".env.local"),
            Path(".env.production"),
            Path(".env.development"),
        ]
        for env_path in env_paths:
            try:
                if not env_path.exists() or not env_path.is_file():
                    continue
                content = env_path.read_text(encoding="utf-8")
                secrets = self._secret_scanner.scan_text(content)
                if not secrets:
                    continue
                severity = "high"
                if os.name != "nt":
                    mode = env_path.stat().st_mode
                    if bool(mode & stat.S_IROTH):
                        severity = "critical"
                findings.append(
                    self._finding(
                        "env_secrets",
                        severity,
                        f"{env_path} contains {len(secrets)} potential secret(s)",
                        ", ".join(str(item["pattern"]) for item in secrets[:3]),
                        "Move secrets to secure vault/environment and restrict file permissions.",
                    )
                )
            except Exception:
                continue
        return findings

    def check_known_agent_configs(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        openclaw_path = Path("openclaw.json")
        try:
            if openclaw_path.exists():
                content = openclaw_path.read_text(encoding="utf-8")
                if "auth" not in content.lower():
                    findings.append(
                        self._finding(
                            "known_agent_config",
                            "high",
                            "openclaw.json appears to miss authentication config",
                            str(openclaw_path),
                            "Configure gateway authentication mode and non-default token.",
                        )
                    )
        except Exception:
            pass

        soul_path = Path("soul.md")
        try:
            if soul_path.exists():
                secrets = self._secret_scanner.scan_text(soul_path.read_text(encoding="utf-8"))
                if secrets:
                    findings.append(
                        self._finding(
                            "known_agent_config",
                            "high",
                            "soul.md may contain credential-like secrets",
                            str(soul_path),
                            "Remove secrets from soul.md and rotate credentials.",
                        )
                    )
        except Exception:
            pass
        return findings

    def _can_connect(self, host: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            return sock.connect_ex((host, int(port))) == 0
        finally:
            sock.close()

    def _finding(
        self,
        check: str,
        severity: str,
        description: str,
        evidence: str,
        recommendation: str,
    ) -> dict[str, Any]:
        return {
            "check": check,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        }
