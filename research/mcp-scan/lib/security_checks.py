"""Security checks for MCP server configurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

from .config_parser import MCPServerEntry


@dataclass
class Finding:
    check_id: str
    severity: str
    category: str
    title: str
    description: str
    evidence: str
    server_name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CHECKS = [
    "MCP-001: Hardcoded API key in env",
    "MCP-002: Hardcoded token in args",
    "MCP-003: Sensitive env var exposed",
    "MCP-004: Shell access granted",
    "MCP-005: Filesystem access unrestricted",
    "MCP-006: Network access unrestricted",
    "MCP-007: Sudo/admin execution",
    "MCP-008: No version pinning",
    "MCP-009: Unknown/unverified package",
    "MCP-010: Local path execution",
    "MCP-011: Empty or minimal config",
    "MCP-012: Excessive server count",
    "MCP-013: Duplicate server names",
]

_API_KEY_PATTERNS = [
    re.compile(r"sk-(proj|ant)-[a-zA-Z0-9_\-]{8,}", re.I),
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{20,}", re.I),
    re.compile(r"github_pat_[a-zA-Z0-9_]{20,}", re.I),
    re.compile(r"Bearer\s+[a-zA-Z0-9\-_\.]{16,}", re.I),
    re.compile(r"[a-z]+://[^:@/\s]+:[^@/\s]+@", re.I),
]
_SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "apikey", "database_url", "aws_secret"}
_SHELL_CMDS = {"bash", "sh", "cmd", "powershell", "pwsh", "zsh", "run", "exec", "docker"}
_KNOWN_GOOD_PREFIXES = (
    "@modelcontextprotocol/",
    "modelcontextprotocol-",
    "mcp-server-",
    "mcp_",
)


def run_all_checks(servers: list[MCPServerEntry]) -> list[Finding]:
    findings: list[Finding] = []
    if len(servers) == 0:
        findings.append(
            Finding(
                check_id="MCP-011",
                severity="low",
                category="configuration",
                title="Empty or minimal config",
                description="No servers configured.",
                evidence="servers=0",
                server_name="__config__",
            )
        )
        return findings

    if len(servers) > 20:
        findings.append(
            Finding(
                check_id="MCP-012",
                severity="medium",
                category="configuration",
                title="Excessive server count",
                description="Config includes more than 20 MCP servers.",
                evidence=f"servers={len(servers)}",
                server_name="__config__",
            )
        )

    names: dict[str, int] = {}
    for s in servers:
        names[s.name] = names.get(s.name, 0) + 1
    for name, count in names.items():
        if count > 1:
            findings.append(
                Finding(
                    check_id="MCP-013",
                    severity="medium",
                    category="configuration",
                    title="Duplicate server names",
                    description="Same server name appears multiple times.",
                    evidence=f"{name} x{count}",
                    server_name=name,
                )
            )

    for server in servers:
        findings.extend(check_hardcoded_secrets(server))
        findings.extend(check_permissions(server))
        findings.extend(check_versioning(server))
    return findings


def check_hardcoded_secrets(server: MCPServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in server.env.items():
        key_l = key.lower()
        if any(mark in key_l for mark in _SENSITIVE_KEYS):
            findings.append(
                Finding(
                    check_id="MCP-003",
                    severity="high",
                    category="secrets",
                    title="Sensitive env var exposed",
                    description="Environment contains sensitive variable name.",
                    evidence=f"{key}=***",
                    server_name=server.name,
                )
            )
        if _looks_secret(value):
            findings.append(
                Finding(
                    check_id="MCP-001",
                    severity="critical",
                    category="secrets",
                    title="Hardcoded API key in env",
                    description="Potential credential value found in env.",
                    evidence=_redact_value(value),
                    server_name=server.name,
                )
            )

    args_joined = " ".join(server.args)
    if _looks_secret(args_joined):
        findings.append(
            Finding(
                check_id="MCP-002",
                severity="critical",
                category="secrets",
                title="Hardcoded token in args",
                description="Potential credential value found in command args.",
                evidence=_redact_value(args_joined),
                server_name=server.name,
            )
        )
    return findings


def check_permissions(server: MCPServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    cmd = server.command.strip().lower()
    args_joined = " ".join(server.args).lower()

    if cmd in _SHELL_CMDS:
        findings.append(
            Finding(
                check_id="MCP-004",
                severity="high",
                category="permissions",
                title="Shell access granted",
                description="Server command is a shell interpreter.",
                evidence=server.command,
                server_name=server.name,
            )
        )
    # npx/uvx wrappers can still grant shell-like execution via args.
    if cmd in {"npx", "uvx"} and any(marker in args_joined for marker in (" exec ", " shell ", " bash ")):
        findings.append(
            Finding(
                check_id="MCP-004",
                severity="high",
                category="permissions",
                title="Shell access granted",
                description="Package runner args indicate shell/exec behavior.",
                evidence=_trim(f"{server.command} {' '.join(server.args)}", 120),
                server_name=server.name,
            )
        )
    if cmd.startswith("sudo") or cmd.startswith("runas"):
        findings.append(
            Finding(
                check_id="MCP-007",
                severity="critical",
                category="permissions",
                title="Sudo/admin execution",
                description="Server appears to execute with elevated privileges.",
                evidence=server.command,
                server_name=server.name,
            )
        )

    if "/" in args_joined or "c:\\" in args_joined:
        if "--allowed" not in args_joined and "--root" not in args_joined and "--dir" not in args_joined:
            findings.append(
                Finding(
                    check_id="MCP-005",
                    severity="high",
                    category="permissions",
                    title="Filesystem access unrestricted",
                    description="Paths detected without obvious restriction flags.",
                    evidence=_trim(args_joined, 120),
                    server_name=server.name,
                )
            )

    if ("http://" in args_joined or "https://" in args_joined or "fetch" in args_joined) and "--allowlist" not in args_joined:
        findings.append(
            Finding(
                check_id="MCP-006",
                severity="medium",
                category="permissions",
                title="Network access unrestricted",
                description="Network-capable behavior without allowlist marker.",
                evidence=_trim(args_joined, 120),
                server_name=server.name,
            )
        )
    return findings


def check_versioning(server: MCPServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    cmd = server.command.strip().lower()
    args = [str(a).strip() for a in server.args]
    args_joined = " ".join(args)

    if cmd in {"npx", "uvx", "pip", "pip3"}:
        pkg = _first_package_arg(args)
        if pkg and not _has_version_pin(pkg, cmd):
            findings.append(
                Finding(
                    check_id="MCP-008",
                    severity="high",
                    category="versioning",
                    title="No version pinning",
                    description="Dependency appears unpinned.",
                    evidence=pkg,
                    server_name=server.name,
                )
            )
        if pkg and not _known_good_package(pkg):
            findings.append(
                Finding(
                    check_id="MCP-009",
                    severity="medium",
                    category="supply_chain",
                    title="Unknown/unverified package",
                    description="Package does not match known MCP naming patterns.",
                    evidence=pkg,
                    server_name=server.name,
                )
            )

    if _looks_local_execution(server.command, args_joined):
        findings.append(
            Finding(
                check_id="MCP-010",
                severity="medium",
                category="supply_chain",
                title="Local path execution",
                description="Command or args use local file path execution.",
                evidence=_trim(f"{server.command} {args_joined}", 120),
                server_name=server.name,
            )
        )
    return findings


def _looks_secret(text: str) -> bool:
    if not text:
        return False
    for pattern in _API_KEY_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _redact_value(value: str) -> str:
    if not value:
        return ""
    text = value.strip()
    for pattern in _API_KEY_PATTERNS:
        m = pattern.search(text)
        if m:
            token = m.group(0)
            if token.lower().startswith("sk-proj-"):
                return "sk-proj-****"
            if token.lower().startswith("sk-ant-"):
                return "sk-ant-****"
            if token.startswith("AKIA"):
                return "AKIA****"
            if token.lower().startswith("gh"):
                return "gh*_****"
            return token[:4] + "****"
    return _trim(text, 32)


def _trim(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return text[:n] + "..."


def _first_package_arg(args: list[str]) -> str:
    for arg in args:
        if not arg or arg.startswith("-"):
            continue
        return arg
    return ""


def _has_version_pin(pkg: str, cmd: str) -> bool:
    if cmd in {"npx", "uvx"}:
        return "@" in pkg and not pkg.startswith("@")
    if cmd in {"pip", "pip3"}:
        return "==" in pkg
    return False


def _known_good_package(pkg: str) -> bool:
    lower = pkg.lower()
    if any(lower.startswith(prefix) for prefix in _KNOWN_GOOD_PREFIXES):
        return True
    return "mcp" in lower


def _looks_local_execution(command: str, args_joined: str) -> bool:
    cmd = command.strip().lower()
    if cmd.startswith("./") or cmd.startswith("../") or cmd.startswith("/") or ":" in cmd[:3]:
        return True
    lower_args = args_joined.lower()
    return any(marker in lower_args for marker in (" ./", " ../", " /", " c:\\", " .py", " .js"))
