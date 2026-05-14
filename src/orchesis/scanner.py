"""Static security scanners for skill, MCP config, and policy files."""

from __future__ import annotations

import html as html_module
import json
import logging
import math
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

import yaml

from importlib.metadata import PackageNotFoundError, version as _package_version

from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.secret_scanner import SecretScanner

_LOGGER = logging.getLogger(__name__)

try:
    ORCHESIS_VERSION = _package_version("orchesis")
except PackageNotFoundError:
    ORCHESIS_VERSION = "0.0.0"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

REMEDIATION_GUIDE = {
    "supply_chain_cve": "Update package to fixed version listed in CVE advisory.",
    "malicious_package": "Remove this package immediately. It is confirmed malicious.",
    "typosquatting": "Verify package name against official registry. Use exact name.",
    "supply_chain": "Pin package to exact version using @X.Y.Z or ==X.Y.Z syntax.",
    "version_pinning": "Add explicit version: npx package@1.2.3 or uvx package==1.2.3",
    "secret_leak": "Move secrets to environment variables or a secrets manager. Never hardcode.",
    "docker_security": "Review Docker security hardening guide: use --user, drop capabilities, add resource limits.",
    "permissions": "Restrict autoApprove to specific tools only. Avoid wildcards.",
    "transport_security": "Use HTTPS/WSS for all remote connections. Never transmit over plaintext.",
    "shell_execution": "Restrict shell access to specific commands. Use allowlists.",
    "privilege_escalation": "Remove sudo/doas from MCP server commands. Run with least privilege.",
    "path_traversal": "Validate and sanitize all path arguments. Use absolute paths with allowlists.",
    "file_access": "Restrict filesystem access to specific subdirectories only.",
    "exfiltration_risk": "Audit data flow between filesystem and network servers. Add approval gates.",
    "attack_surface": "Reduce server count. Split into separate configs per use case.",
    "credential_sharing": "Use unique credentials per server. Rotate shared secrets immediately.",
    "cors_missing": "Add explicit CORS configuration with allowed origins allowlist.",
    "binding_exposure": "Bind to 127.0.0.1 instead of 0.0.0.0. Use reverse proxy for external access.",
    "no_auth": "Enable authentication. Add API key or token to server configuration.",
    "websocket_no_origin_check": "Add origin validation to WebSocket server configuration.",
    "suspicious_url": "Verify URL legitimacy. Use HTTPS. Avoid raw IPs and suspicious domains.",
    "dangerous_tools": "Restrict tool list to minimum required. Remove shell_execute, exec, file_write.",
    "deprecated_package": "Replace deprecated package with a maintained alternative.",
    "registry_verification": "Verify npm/PyPI publisher, scope, and package integrity before installing.",
    "prompt_injection": "Sanitize tool descriptions; treat them as untrusted. Review third-party tool packs.",
    "insufficient_logging": "Enable structured audit logging for MCP tool calls and auth failures.",
    "shadow_server": "Prefer managed MCP endpoints with change control; avoid ad-hoc local scripts and stray ports.",
    "context_oversharing": "Scope credentials and directory allowlists per server; remove wildcards from permissions.",
    "command_injection_risk": "Remove shell metacharacters from args; invoke binaries directly without sh -c.",
    "token_management": "Use short-lived tokens per server, unique credentials, and a secrets manager.",
    "cursor_ide_config": "Review Cursor rules and workspace trust; keep permission bypass flags disabled.",
    "claude_code_config": "Tighten Claude Code permissions allow-list; pin budgets for expensive models.",
    "paperclip_config": "Enable Paperclip permission checks, cap budgets, and store secrets outside adapter env.",
    "openclaw_config": "Keep OpenClaw sandbox on, enable loop detection, and require tool approval.",
    "safety_bypass": "Disable safety-bypass flags; enforce approvals and least-privilege tool access.",
    "a2a_security": "Require strong auth (OAuth 2.1/JWT/OIDC), signed AgentCards, and TLS for A2A endpoints.",
    "runtime_hygiene": "Add timeouts, rate limits, container resource caps, restart policies, and stable ports.",
    "network_segmentation": "Avoid exposing local resources on remote endpoints; fix port clashes; prefer 127.0.0.1 over localhost.",
}

VULNERABLE_PACKAGES = {
    "mcp-remote": {
        "fixed": "0.1.16",
        "cvss": 9.6,
        "cve": "CVE-2025-6514",
        "desc": "SSRF via unvalidated redirect allows credential theft",
    },
    "@modelcontextprotocol/server-filesystem": {
        "fixed": "0.6.3",
        "cvss": 7.5,
        "cve": "CVE-2025-5589",
        "desc": "Path traversal allows reading files outside allowed dirs",
    },
    "framelink-figma-mcp": {
        "fixed": "0.6.3",
        "cvss": 8.1,
        "cve": "CVE-2025-5891",
        "desc": "SSRF in design file fetch",
    },
    "gemini-mcp-tool": {
        "fixed": None,
        "cvss": 9.8,
        "cve": "CVE-2025-6001",
        "desc": "RCE via unsanitized tool input, no fix available",
    },
    "@anthropic/mcp-server-git": {
        "fixed": "1.0.1",
        "cvss": 7.2,
        "cve": "CVE-2025-5234",
        "desc": "Arbitrary file read via symlink following",
    },
    "mcp-server-kubernetes": {
        "fixed": "0.3.1",
        "cvss": 8.5,
        "cve": "CVE-2025-7102",
        "desc": "Privilege escalation via unscoped RBAC",
    },
    "@anthropic/mcp-inspector": {
        "fixed": "0.14.1",
        "cvss": 8.4,
        "cve": "CVE-2025-6891",
        "desc": "XSS in inspector UI allows session hijack",
    },
    "mcp-server-slack": {
        "fixed": "0.5.2",
        "cvss": 7.8,
        "cve": "CVE-2025-7234",
        "desc": "Token exfiltration via crafted channel name",
    },
}

# Authoritative CVE metadata for _check_supply_chain_cves (same keys as VULNERABLE_PACKAGES).
MCP_CVE_DATABASE: dict[str, dict[str, Any]] = VULNERABLE_PACKAGES

MALICIOUS_PACKAGES = [
    "mcp-server-free",
    "mcp-tool-helper",
    "claude-mcp-utils",
    "mcp-assistant-pro",
    "openai-mcp-bridge",
]

KNOWN_GOOD_PACKAGES = [
    "mcp-server-filesystem",
    "mcp-server-brave-search",
    "mcp-server-fetch",
    "mcp-server-github",
    "mcp-server-git",
    "mcp-server-postgres",
    "mcp-server-sqlite",
    "mcp-server-slack",
    "mcp-server-puppeteer",
    "mcp-server-memory",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
]

LEGITIMATE_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@anthropic/mcp-server-git",
    "@anthropic/mcp-inspector",
    "mcp-remote",
    "framelink-figma-mcp",
]

MCP_SCANNER_DEPRECATED_PACKAGES = {
    "mcp-server-sqlite-npx": "Use @modelcontextprotocol/server-sqlite instead",
    "claude-mcp-server": "Abandoned; use official @anthropic packages",
    "mcp-server-openai-legacy": "Use mcp-remote with OpenAI endpoint instead",
}

TRUSTED_SCOPES = ("@modelcontextprotocol", "@anthropic", "@google", "@microsoft")

PYPI_PUBLISHER_HINTS = (
    "anthropic",
    "modelcontextprotocol",
    "mcp",
    "google",
    "microsoft",
    "openai",
)

EXTENDED_SECRET_PATTERNS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key", "critical"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub PAT", "critical"),
    (r"\bsk-ant-[A-Za-z0-9\-]{40,}\b", "Anthropic API Key", "critical"),
    (r"\bsk-proj-[A-Za-z0-9\-]{40,}\b", "OpenAI Project Key", "critical"),
    (r"\bstripe_[a-zA-Z]+_[A-Za-z0-9]{24,}\b", "Stripe Key", "high"),
    (r"\bey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}", "JWT Token", "high"),
]

SENSITIVE_MOUNTS = ["~/.ssh", "~/.aws", "~/.kube", "/etc", "~/.gnupg", "~/.config"]
DANGEROUS_CAPS = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"]
DEPRECATED_PACKAGES = {
    "mcp-server-fetch": "Consider @modelcontextprotocol/server-fetch instead",
    "mcp-tools": "Package unmaintained since 2024-06",
    "mcp-server-basic": "Superseded by official SDK",
    "langchain-mcp": "Use official MCP SDK directly",
}
SHELL_SERVER_PATTERNS = [
    r"\bshell\b",
    r"\bterminal\b",
    r"\bexec\b",
    r"\bbash\b",
    r"\bzsh\b",
    r"\bpowershell\b",
    r"\bcmd\b",
    r"\brun\b",
]
ADMIN_TOKEN_PATTERNS = [
    r"\bADMIN[_\-]?TOKEN\b",
    r"\bROOT[_\-]?KEY\b",
    r"\bSUPERUSER[_\-]?\w*\b",
    r"\bMASTER[_\-]?KEY\b",
    r"\bGOD[_\-]?MODE\b",
    r"\bFULL[_\-]?ACCESS\b",
]
SENSITIVE_ARG_PATHS = [
    r"~/\.ssh",
    r"~/\.gnupg",
    r"~/\.config",
    r"~/Library/Keychains",
    r"AppData[/\\]Roaming",
    r"\.sqlite$",
    r"\.db$",
    r"wallet\.dat",
    r"keystore",
    r"/proc/\d+",
]
BROAD_PATHS = ["/", "~", "$HOME", "/home", "/users", "C:\\", "C:/"]

INJECTION_MARKERS = [
    "ignore previous",
    "ignore above",
    "disregard",
    "forget instructions",
    "you are now",
    "act as",
    "new instructions:",
    "system:",
    "admin:",
    "override:",
    "<system>",
    "```system",
    "important:",
    "note to ai:",
    "ignore all",
    "do not follow",
    "bypass",
    "jailbreak",
]

STANDARD_MCP_URL_PORTS = frozenset({80, 443, 3000, 8080, 8081})

RAW_SHELL_COMMANDS = frozenset(
    {"sh", "bash", "cmd", "powershell", "pwsh", "cmd.exe", "powershell.exe"}
)

UNIVERSAL_SAFETY_BYPASS_KEYS = frozenset(
    k.lower()
    for k in (
        "dangerouslySkipPermissions",
        "dangerously_skip_permissions",
        "skip_permissions",
        "skipPermissions",
        "noPermissions",
        "no_permissions",
        "unsafe_mode",
        "unsafeMode",
        "trust_all",
        "trustAll",
        "auto_approve",
        "autoApprove",
        "disable_safety",
        "disableSafety",
    )
)

PAPERCLIP_SECRET_SUBSTRINGS = (
    "sk-",
    "ghp_",
    "xoxb-",
    "xoxp-",
    "akia",
    "gho_",
    "glpat-",
)


@dataclass(frozen=True)
class RuleInfo:
    """Registered MCP scanner rule metadata (subset of all emitted rule_ids)."""

    rule_id: str
    category: str
    default_severity: str
    owasp_mapping: str | None = None
    description: str = ""


def _cross_service_env_name_hints(env_key: str) -> tuple[str, ...] | None:
    k = env_key.upper().strip()
    if k in {"DATABASE_URL", "DB_CONNECTION"}:
        return ("db", "sql", "postgres", "mysql", "mongo", "data", "database")
    if k == "REDIS_URL":
        return ("redis", "cache")
    if "AWS_ACCESS_KEY" in k:
        return ("aws", "amazon", "s3", "ec2")
    if "AWS_SECRET" in k:
        return ("aws", "amazon", "s3", "ec2")
    if "GITHUB_TOKEN" in k:
        return ("github", "git", "gh")
    if k == "OPENAI_API_KEY":
        return ("openai", "gpt", "chatgpt", "llm")
    return None


@dataclass
class ScanFinding:
    """Single security finding from a static scan (severity, category, location, evidence)."""

    severity: str
    category: str
    description: str
    location: str
    evidence: str
    rule_id: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        if not self.remediation:
            self.remediation = REMEDIATION_GUIDE.get(
                self.category, "Review and address this security issue."
            )


@dataclass
class ScanReport:
    """Aggregated scan outcome for one file or config (findings, scores, summary)."""

    target: str
    target_type: str
    findings: list[ScanFinding]
    risk_score: int
    summary: str
    scanned_at: str
    server_scores: dict[str, int] = field(default_factory=dict)
    attack_surface_score: int = 0
    rules_checked: int = 0
    unique_findings: int = 0
    dedup_count: int = 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _calc_risk_score(findings: list[ScanFinding]) -> int:
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
    score = sum(weights.get(item.severity.lower(), 0) for item in findings)
    return min(100, score)


def _build_summary(findings: list[ScanFinding]) -> str:
    if not findings:
        return "No findings detected."
    by_sev: dict[str, int] = {}
    for item in findings:
        key = item.severity.lower()
        by_sev[key] = by_sev.get(key, 0) + 1
    parts = ", ".join(f"{count} {sev}" for sev, count in sorted(by_sev.items()))
    return f"{len(findings)} findings: {parts}."


def _line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(threshold.lower(), 0)


def format_report_text(report: ScanReport, threshold: str = "info") -> str:
    lines = [f"Scanning: {report.target} ({report.target_type})", ""]
    filtered = [
        item for item in report.findings if severity_meets_threshold(item.severity, threshold)
    ]
    if not filtered:
        lines.append("Findings: none")
    else:
        lines.append("Findings:")
        for item in filtered:
            lines.append(
                f"  [{item.severity.upper():<8}] {item.category:<18} {item.location}: {item.description}"
            )
            lines.append(f"             → {item.remediation}")
    server_scores = getattr(report, "server_scores", {}) or {}
    if server_scores:
        lines.append("")
        lines.append("Server Risk Scores:")
        for server_name, score in sorted(server_scores.items()):
            lines.append(f"  {server_name}: {int(score):>3}/100")
    lines.extend(
        [
            "",
            f"Risk Score: {report.risk_score}/100",
            f"Attack Surface Score: {int(getattr(report, 'attack_surface_score', 0))}/100",
            f"Summary: {report.summary}",
        ]
    )
    return "\n".join(lines)


def format_report_markdown(report: ScanReport, threshold: str = "info") -> str:
    lines = [f"# Scan Report: `{report.target}`", "", f"- Type: `{report.target_type}`"]
    lines.append(f"- Risk Score: `{report.risk_score}/100`")
    lines.append(f"- Attack Surface Score: `{int(getattr(report, 'attack_surface_score', 0))}/100`")
    lines.append(f"- Summary: {report.summary}")
    lines.append("")
    lines.append("## Findings")
    filtered = [
        item for item in report.findings if severity_meets_threshold(item.severity, threshold)
    ]
    if not filtered:
        lines.append("- None")
    else:
        for item in filtered:
            lines.append(
                f"- **{item.severity.upper()}** `{item.category}` `{item.location}` - {item.description}"
            )
            lines.append(f"  - **Remediation:** {item.remediation}")
    server_scores = getattr(report, "server_scores", {}) or {}
    if server_scores:
        lines.append("")
        lines.append("## Server Risk Scores")
        for server_name, score in sorted(server_scores.items()):
            lines.append(f"- `{server_name}`: `{int(score)}/100`")
    return "\n".join(lines)


class SkillScanner:
    """Scan SKILL.md files for suspicious patterns."""

    _URL_RE = re.compile(r"https?://[^\s)>\"]+")

    def __init__(self) -> None:
        self._secret_scanner = SecretScanner()
        self._ioc_matcher = IoCMatcher(enable_opt_in_v1_1=True)

    def scan(self, path: str) -> ScanReport:
        source = Path(path)
        content = source.read_text(encoding="utf-8")
        findings: list[ScanFinding] = []

        for finding in self._secret_scanner.scan_text(content):
            line = _line_number(content, int(finding["position"]))
            findings.append(
                ScanFinding(
                    severity=str(finding["severity"]),
                    category="secret_leak",
                    description=str(finding["description"]),
                    location=f"line {line}",
                    evidence=str(finding["match"]),
                )
            )

        for match in self._URL_RE.finditer(content):
            url = match.group(0)
            line = _line_number(content, match.start())
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if parsed.scheme != "https":
                findings.append(
                    ScanFinding(
                        severity="info",
                        category="suspicious_url",
                        description="Non-HTTPS URL",
                        location=f"line {line}",
                        evidence=url,
                    )
                )
            if any(token in host for token in ("webhook.site", "requestbin", "ngrok")):
                findings.append(
                    ScanFinding(
                        severity="high",
                        category="suspicious_url",
                        description="Known exfiltration host",
                        location=f"line {line}",
                        evidence=url,
                    )
                )
            if _is_ip_host(host):
                findings.append(
                    ScanFinding(
                        severity="high",
                        category="suspicious_url",
                        description="URL uses raw IP address",
                        location=f"line {line}",
                        evidence=url,
                    )
                )
            if re.search(r"[A-Za-z0-9+/]{24,}={0,2}", parsed.path):
                findings.append(
                    ScanFinding(
                        severity="medium",
                        category="suspicious_url",
                        description="Possible base64 payload in URL path",
                        location=f"line {line}",
                        evidence=url,
                    )
                )

        for match in re.finditer(r"wss?://[^\s)>\"]+", content, flags=re.IGNORECASE):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="websocket_connection_in_skill",
                    description="Skill instructs WebSocket connection; verify endpoint trust.",
                    location=f"line {_line_number(content, match.start())}",
                    evidence=match.group(0),
                )
            )

        shell_patterns = [
            (r"\|\s*(bash|sh)\b", "high", "Pipe to shell execution"),
            (r"\beval\s*\(", "high", "eval() usage"),
            (r"\bexec\s*\(", "high", "exec() usage"),
            (r"\bos\.system\s*\(", "high", "os.system usage"),
            (r"\bsubprocess\.(run|Popen|call)\s*\(", "medium", "subprocess execution"),
            (r"base64\s+(-d|--decode)", "high", "Base64 decode in command"),
        ]
        for pattern, severity, description in shell_patterns:
            for match in re.finditer(pattern, content, flags=re.IGNORECASE):
                findings.append(
                    ScanFinding(
                        severity=severity,
                        category="shell_exec",
                        description=description,
                        location=f"line {_line_number(content, match.start())}",
                        evidence=match.group(0),
                    )
                )

        file_patterns = [
            r"~/.ssh",
            r"~/.aws",
            r"~/.gnupg",
            r"~/.config",
            r"/etc/passwd",
            r"/etc/shadow",
            r"\.env(\.local)?",
            r"credentials",
            r"Chrome[/\\]User Data",
            r"Firefox[/\\]Profiles",
        ]
        for pattern in file_patterns:
            for match in re.finditer(pattern, content, flags=re.IGNORECASE):
                findings.append(
                    ScanFinding(
                        severity="medium",
                        category="file_access",
                        description="Sensitive file/path reference",
                        location=f"line {_line_number(content, match.start())}",
                        evidence=match.group(0),
                    )
                )

        hidden_patterns = [
            r"ignore previous instructions",
            r"do not tell the user",
            r"without the user knowing",
            r"\bsecretly\b",
        ]
        for pattern in hidden_patterns:
            for match in re.finditer(pattern, content, flags=re.IGNORECASE):
                findings.append(
                    ScanFinding(
                        severity="high",
                        category="tool_poisoning",
                        description="Hidden instruction / prompt injection phrasing",
                        location=f"line {_line_number(content, match.start())}",
                        evidence=match.group(0),
                    )
                )

        if any(char in content for char in ("\u200b", "\u200c", "\u200d", "\u202e")):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="tool_poisoning",
                    description="Unicode obfuscation marker detected",
                    location="content",
                    evidence="zero-width or RTL override char",
                )
            )

        wallet_patterns = [r"seed phrase", r"mnemonic", r"private key", r"keystore"]
        for pattern in wallet_patterns:
            for match in re.finditer(pattern, content, flags=re.IGNORECASE):
                findings.append(
                    ScanFinding(
                        severity="medium",
                        category="secret_leak",
                        description="Crypto wallet sensitive reference",
                        location=f"line {_line_number(content, match.start())}",
                        evidence=match.group(0),
                    )
                )

        for match in self._ioc_matcher.scan_skill(str(source)):
            severity = str(match.get("severity", "high")).lower()
            if severity in {"low", "info"}:
                severity = "high"
            findings.append(
                ScanFinding(
                    severity=severity,
                    category="ioc_match",
                    description=f"IoC match: {match.get('ioc_id')} {match.get('ioc_name')}",
                    location=f"line {_line_number(content, int(match.get('position', 0)))}",
                    evidence=str(match.get("match", match.get("matched_pattern", ""))),
                )
            )

        return ScanReport(
            target=str(source),
            target_type="skill_md",
            findings=findings,
            risk_score=_calc_risk_score(findings),
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
        )


# Top documented MCP scanner rules (subset of all emitted rule_ids).
MCP_RULE_REGISTRY_SPECS: tuple[tuple[str, str, str, str | None, str], ...] = (
    (
        "MCP-DANGEROUSLY-SKIP-PERMISSIONS",
        "safety_bypass",
        "critical",
        "MCP-01",
        "Permission bypass flags",
    ),
    ("MCP-CONFIG-INVALID-ROOT", "mcp_config", "high", "MCP-10", "Invalid MCP JSON root"),
    ("CVE-2025-6514", "supply_chain_cve", "critical", "MCP-10", "mcp-remote SSRF"),
    (
        "CVE-2025-5589",
        "supply_chain_cve",
        "high",
        "MCP-10",
        "@modelcontextprotocol/server-filesystem traversal",
    ),
    ("CVE-2025-5891", "supply_chain_cve", "high", "MCP-10", "framelink-figma-mcp SSRF"),
    ("CVE-2025-6001", "supply_chain_cve", "critical", "MCP-10", "gemini-mcp-tool RCE"),
    ("CVE-2025-5234", "supply_chain_cve", "high", "MCP-10", "mcp-server-git symlink read"),
    ("CVE-2025-7102", "supply_chain_cve", "high", "MCP-10", "mcp-server-kubernetes RBAC"),
    ("CVE-2025-6891", "supply_chain_cve", "high", "MCP-10", "mcp-inspector XSS"),
    ("CVE-2025-7234", "supply_chain_cve", "high", "MCP-10", "mcp-server-slack token exfil"),
    (
        "CVE-2026-25253",
        "websocket_no_origin_check",
        "high",
        "MCP-06",
        "CSWSH / missing origin check",
    ),
    ("BIND-EXPOSE-0000", "binding_exposure", "critical", "MCP-06", "Binds to 0.0.0.0"),
    (
        "WS-NO-ORIGIN-001",
        "websocket_no_origin_check",
        "high",
        "MCP-06",
        "WebSocket without origin validation",
    ),
    ("HTTP-NO-CORS-001", "http_no_cors", "medium", "MCP-06", "HTTP without CORS/origin config"),
    ("NO-AUTH-001", "no_auth", "high", "MCP-07", "MCP server without auth"),
    ("DANGEROUS-TOOLS-LIST", "dangerous_tools", "medium", "MCP-05", "High-risk tools enabled"),
    ("DANGEROUS-TOOLS-WILD", "dangerous_tools", "high", "MCP-05", "Wildcard tool permissions"),
    ("HTTP-INSECURE-REMOTE", "suspicious_url", "high", "MCP-06", "Plain HTTP to non-localhost"),
    ("SECRET-IN-ENV", "secret_leak", "high", "MCP-09", "Secret material in env"),
    ("IMAGE-UNTRUSTED-REGISTRY", "supply_chain", "medium", "MCP-10", "Non-trusted image registry"),
    ("VERSION-NOT-PINNED", "version_pinning", "medium", "MCP-10", "Unpinned package version"),
    ("TYPO-SQUAT-001", "typosquatting", "high", "MCP-10", "Possible typosquat package"),
    ("MALICIOUS-PACKAGE-001", "malicious_package", "critical", "MCP-10", "Known malicious package"),
    (
        "CLAUDE-BASH-UNRESTRICTED",
        "claude_code_config",
        "critical",
        "MCP-05",
        "Claude Code Bash(*) permission",
    ),
    ("OPENCLAW-AUTO-APPROVE", "openclaw_config", "high", "MCP-05", "OpenClaw auto-approve tools"),
    ("OPENCLAW-SANDBOX-OFF", "openclaw_config", "critical", "MCP-05", "OpenClaw sandbox disabled"),
    ("OPENCLAW-LOOP-OFF", "openclaw_config", "high", "MCP-05", "OpenClaw loop detection off"),
    ("A2A-AGENTCARD-HTTP", "a2a_security", "medium", "MCP-07", "A2A agent card over HTTP"),
    ("PORT-COLLISION-001", "network_segmentation", "high", "MCP-06", "MCP port collision"),
    ("TOKEN-SHARED-001", "credential_sharing", "high", "MCP-09", "Shared token across servers"),
    ("PAPERCLIP-SECRET-ENV", "paperclip_config", "high", "MCP-09", "Paperclip adapter env secret"),
)


class McpConfigScanner:
    """Scan MCP configuration files for security issues."""

    RULE_REGISTRY: ClassVar[dict[str, RuleInfo]] = {
        rid: RuleInfo(
            rule_id=rid,
            category=cat,
            default_severity=sev,
            owasp_mapping=owasp,
            description=desc,
        )
        for rid, cat, sev, owasp, desc in MCP_RULE_REGISTRY_SPECS
    }

    @classmethod
    def get_rule_count(cls) -> int:
        return len(cls.RULE_REGISTRY)

    @classmethod
    def get_rules_by_category(cls, category: str) -> list[RuleInfo]:
        c = category.strip().lower()
        return [r for r in cls.RULE_REGISTRY.values() if r.category.lower() == c]

    @staticmethod
    def _server_name_from_location(location: str) -> str:
        if location.startswith("$.mcpServers."):
            rest = location[len("$.mcpServers.") :]
            for sep in (".", "["):
                if sep in rest:
                    return rest.split(sep, 1)[0]
            return rest or "__global__"
        return "__global__"

    @staticmethod
    def _dedupe_mcp_findings(findings: list[ScanFinding]) -> tuple[list[ScanFinding], int]:
        if not findings:
            return [], 0
        buckets: dict[tuple[str, str], list[ScanFinding]] = defaultdict(list)
        for f in findings:
            srv = McpConfigScanner._server_name_from_location(f.location)
            rid = (f.rule_id or "").strip() or "__none__"
            buckets[(srv, rid)].append(f)
        removed_by_server: dict[str, int] = {}
        for (srv, _rid), lst in buckets.items():
            if len(lst) > 1:
                removed_by_server[srv] = removed_by_server.get(srv, 0) + len(lst) - 1
        for srv, n in removed_by_server.items():
            if n > 0:
                _LOGGER.debug("Deduped %d findings for server %s", n, srv)
        first_pos: dict[tuple[str, str], int] = {}
        for i, f in enumerate(findings):
            srv = McpConfigScanner._server_name_from_location(f.location)
            rid = (f.rule_id or "").strip() or "__none__"
            k = (srv, rid)
            if k not in first_pos:
                first_pos[k] = i
        keys_sorted = sorted(first_pos.keys(), key=lambda k: first_pos[k])
        out: list[ScanFinding] = []
        for k in keys_sorted:
            grp = buckets[k]
            best = max(grp, key=lambda x: SEVERITY_ORDER.get(x.severity.lower(), 0))
            out.append(best)
        removed = len(findings) - len(out)
        return out, removed

    @staticmethod
    def _universal_bypass_rule_id(normalized_key: str) -> str:
        skip = frozenset(
            {
                "dangerouslyskippermissions",
                "dangerously_skip_permissions",
                "skip_permissions",
                "skippermissions",
            }
        )
        if normalized_key in skip:
            return "MCP-DANGEROUSLY-SKIP-PERMISSIONS"
        slug = normalized_key.replace(" ", "_").upper()
        return f"MCP-UNIVERSAL-{slug}"[:80]

    def __init__(self) -> None:
        self._secret_scanner = SecretScanner(ignore_patterns=["generic_secret"])

    def _iter_servers(self, payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        candidates = payload.get("mcpServers")
        if not isinstance(candidates, dict):
            candidates = payload.get("servers")
        if not isinstance(candidates, dict):
            return []
        servers: list[tuple[str, dict[str, Any]]] = []
        for name, item in candidates.items():
            if isinstance(name, str) and isinstance(item, dict):
                servers.append((name, item))
        return servers

    def scan(self, path: str) -> ScanReport:
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        findings: list[ScanFinding] = []

        if not isinstance(payload, dict):
            findings.append(
                ScanFinding(
                    rule_id="MCP-CONFIG-INVALID-ROOT",
                    severity="high",
                    category="mcp_config",
                    description="Invalid top-level JSON structure",
                    location="$",
                    evidence="non-object root",
                )
            )
            return ScanReport(
                target=str(source),
                target_type="mcp_config",
                findings=findings,
                risk_score=_calc_risk_score(findings),
                summary=_build_summary(findings),
                scanned_at=_now_iso(),
                rules_checked=len(McpConfigScanner.RULE_REGISTRY),
                unique_findings=len(findings),
                dedup_count=0,
            )

        servers = self._iter_servers(payload)
        shared_cred_index: dict[str, set[str]] = defaultdict(set)
        port_index: defaultdict[int, list[str]] = defaultdict(list)
        for name, server in servers:
            prefix = f"$.mcpServers.{name}"
            host = str(server.get("host", "")).strip()
            url = str(server.get("url", "")).strip()
            bind = str(server.get("bind", "")).strip()
            endpoint = url or bind or host
            transport = str(server.get("transport", "")).strip().lower()
            has_ws_transport = (
                url.startswith("ws://")
                or url.startswith("wss://")
                or transport in {"ws", "websocket"}
                or bool(server.get("websocket"))
            )
            has_http_transport = url.startswith("http://") or url.startswith("https://")
            cors_cfg = server.get("cors")
            allowed_origins = server.get("allowedOrigins") or server.get("allowed_origins")
            has_origin_validation = bool(cors_cfg) or bool(allowed_origins)

            if "0.0.0.0" in endpoint:
                findings.append(
                    ScanFinding(
                        rule_id="BIND-EXPOSE-0000",
                        severity="critical",
                        category="binding_exposure",
                        description=f"server '{name}' binds to 0.0.0.0",
                        location=f"{prefix}.url",
                        evidence=endpoint,
                    )
                )

            if has_ws_transport and not has_origin_validation:
                findings.append(
                    ScanFinding(
                        rule_id="WS-NO-ORIGIN-001",
                        severity="high",
                        category="websocket_no_origin_check",
                        description="WebSocket transport without origin validation",
                        location=prefix,
                        evidence=(  # CVE-2026-25253 https://nvd.nist.gov/vuln/detail/CVE-2026-25253
                            "WebSocket server without origin validation is vulnerable to "
                            "cross-site WebSocket hijacking (CVE-2026-25253)"
                        ),
                    )
                )

            if has_http_transport and not has_origin_validation:
                findings.append(
                    ScanFinding(
                        rule_id="HTTP-NO-CORS-001",
                        severity="medium",
                        category="http_no_cors",
                        description="HTTP endpoint without explicit CORS/origin configuration",
                        location=prefix,
                        evidence=url or endpoint,
                    )
                )

            if has_ws_transport and any(token in endpoint for token in ("127.0.0.1", "localhost")):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0004",
                        severity="info",
                        category="localhost_bypass_risk",
                        description="Localhost WebSocket may still be reachable from browser context",
                        location=prefix,
                        evidence=(
                            "Localhost binding does not protect against browser-based WebSocket attacks. "
                            "See CVE-2026-25253."
                        ),
                    )
                )

            auth = server.get("auth")
            token = server.get("token")
            api_key = server.get("apiKey")
            if auth in (None, "", False) and not token and not api_key:
                findings.append(
                    ScanFinding(
                        rule_id="NO-AUTH-001",
                        severity="high",
                        category="no_auth",
                        description=f"server '{name}' has no authentication configured",
                        location=prefix,
                        evidence="auth/token/apiKey missing",
                    )
                )

            tools = server.get("tools")
            if isinstance(tools, list):
                normalized_tools = [str(item).lower() for item in tools]
                if any(
                    item in normalized_tools for item in ("shell_execute", "file_write", "exec")
                ):
                    findings.append(
                        ScanFinding(
                            rule_id="DANGEROUS-TOOLS-LIST",
                            severity="medium",
                            category="dangerous_tools",
                            description=f"server '{name}' enables dangerous tools",
                            location=f"{prefix}.tools",
                            evidence=", ".join(normalized_tools),
                        )
                    )
                if "*" in normalized_tools:
                    findings.append(
                        ScanFinding(
                            rule_id="DANGEROUS-TOOLS-WILD",
                            severity="high",
                            category="dangerous_tools",
                            description=f"server '{name}' uses wildcard tool permissions",
                            location=f"{prefix}.tools",
                            evidence="*",
                        )
                    )

            if url:
                parsed = urlparse(url)
                host_part = parsed.hostname or ""
                if parsed.scheme == "http" and host_part not in {"localhost", "127.0.0.1"}:
                    findings.append(
                        ScanFinding(
                            rule_id="HTTP-INSECURE-REMOTE",
                            severity="high",
                            category="suspicious_url",
                            description=f"server '{name}' uses non-HTTPS remote URL",
                            location=f"{prefix}.url",
                            evidence=url,
                        )
                    )

            env = server.get("env")
            if isinstance(env, dict):
                for key, value in env.items():
                    if not isinstance(value, str):
                        continue
                    matches = self._secret_scanner.scan_text(f"{key}={value}")
                    if matches:
                        findings.append(
                            ScanFinding(
                                rule_id="SECRET-IN-ENV",
                                severity="high",
                                category="secret_leak",
                                description=f"plain-text secret in env var '{key}'",
                                location=f"{prefix}.env.{key}",
                                evidence=matches[0]["match"],
                            )
                        )

            image = server.get("image")
            if isinstance(image, str) and image:
                trusted = ("docker.io/", "ghcr.io/", "mcr.microsoft.com/")
                if not image.startswith(trusted):
                    findings.append(
                        ScanFinding(
                            rule_id="IMAGE-UNTRUSTED-REGISTRY",
                            severity="medium",
                            category="supply_chain",
                            description=f"server '{name}' uses untrusted image registry",
                            location=f"{prefix}.image",
                            evidence=image,
                        )
                    )

            package = server.get("package")
            if isinstance(package, str) and package:
                if any(token in package for token in ("^", "~", "@latest", ">=", "*")):
                    findings.append(
                        ScanFinding(
                            rule_id="VERSION-NOT-PINNED",
                            severity="medium",
                            category="version_pinning",
                            description=f"server '{name}' package is not pinned exactly",
                            location=f"{prefix}.package",
                            evidence=package,
                        )
                    )

            self._check_supply_chain(name, server, findings)
            self._check_permissions(name, server, findings)
            self._check_network_and_config(name, server, findings)
            self._check_docker_security(name, server, findings)
            self._check_supply_chain_cves(name, server, findings)
            self._check_typosquatting(name, server, findings)
            self._check_deprecated_packages(name, server, findings)
            self._check_registry_verification(name, server, findings)
            self._check_prompt_injection_surface(name, server, findings)
            self._check_logging_config(name, server, findings)
            self._check_shadow_servers(name, server, findings)
            self._check_context_oversharing(name, server, findings)
            self._check_command_injection_risk(name, server, findings)
            self._check_token_management(name, server, findings, shared_cred_index)
            self._check_cursor_config(name, server, findings)
            self._check_claude_code_config(name, server, findings)
            self._check_paperclip_config(name, server, findings)
            self._check_openclaw_config(name, server, findings)
            self._check_dangerous_permissions_universal(name, server, findings)
            self._check_a2a_security(name, server, findings)
            self._check_runtime_hygiene(name, server, findings)
            self._check_network_segmentation(name, server, findings)
            self._record_server_listen_port(name, server, port_index)

        self._check_token_management(None, None, findings, shared_cred_index)
        self._check_network_port_collisions(port_index, findings)
        self._check_cross_server(servers, findings)
        findings, dedup_count = McpConfigScanner._dedupe_mcp_findings(findings)
        unique_findings = len(findings)
        server_scores = self._compute_server_scores(servers, findings)
        critical_count = sum(1 for item in findings if item.severity == "critical")
        high_count = sum(1 for item in findings if item.severity == "high")
        attack_surface_score = min(100, len(servers) * 5 + critical_count * 15 + high_count * 8)

        return ScanReport(
            target=str(source),
            target_type="mcp_config",
            findings=findings,
            risk_score=_calc_risk_score(findings),
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
            server_scores=server_scores,
            attack_surface_score=attack_surface_score,
            rules_checked=len(McpConfigScanner.RULE_REGISTRY),
            unique_findings=unique_findings,
            dedup_count=dedup_count,
        )

    def _check_supply_chain(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        args = self._extract_args(server)
        command = str(server.get("command", "") or "")
        command_norm = command.strip().lower()
        tokens = self._command_tokens(command, args)
        package_tokens = [token for token in tokens if self._is_package_like(token)]

        for package in package_tokens:
            if package.strip().lower() == command_norm:
                continue
            pkg_name, version = self._split_package_and_version(package)
            if pkg_name in VULNERABLE_PACKAGES:
                meta = VULNERABLE_PACKAGES[pkg_name]
                fixed = meta.get("fixed")
                if fixed is None:
                    findings.append(
                        ScanFinding(
                            rule_id=str(meta["cve"]),
                            severity="critical",
                            category="supply_chain_cve",
                            description=(
                                f"Known vulnerable package '{pkg_name}' ({meta['cve']}, CVSS {meta['cvss']}) "
                                "has no safe version available"
                            ),
                            location=f"$.mcpServers.{name}.args",
                            evidence=package,
                        )
                    )
                elif version is None:
                    findings.append(
                        ScanFinding(
                            rule_id=str(meta["cve"]),
                            severity="high",
                            category="supply_chain_cve",
                            description=(
                                f"Known vulnerable package '{pkg_name}' present without pinned version "
                                f"(fixed in {fixed}, {meta['cve']})"
                            ),
                            location=f"$.mcpServers.{name}.args",
                            evidence=package,
                        )
                    )
                elif self._semver_lt(version, str(fixed)):
                    findings.append(
                        ScanFinding(
                            rule_id=str(meta["cve"]),
                            severity="critical",
                            category="supply_chain_cve",
                            description=(
                                f"Package '{pkg_name}@{version}' is below fixed version {fixed} "
                                f"({meta['cve']}, CVSS {meta['cvss']})"
                            ),
                            location=f"$.mcpServers.{name}.args",
                            evidence=package,
                        )
                    )

            if pkg_name in MALICIOUS_PACKAGES:
                findings.append(
                    ScanFinding(
                        rule_id="MALICIOUS-PACKAGE-001",
                        severity="critical",
                        category="malicious_package",
                        description=f"Known malicious package '{pkg_name}' detected",
                        location=f"$.mcpServers.{name}.args",
                        evidence=package,
                    )
                )

            if pkg_name and pkg_name not in KNOWN_GOOD_PACKAGES:
                near = self._nearest_package(pkg_name, KNOWN_GOOD_PACKAGES)
                if near is not None:
                    candidate, distance = near
                    if 1 <= distance <= 2:
                        findings.append(
                            ScanFinding(
                                rule_id="TYPO-SQUAT-001",
                                severity="high",
                                category="typosquatting",
                                description=f"Potential typosquatting: '{pkg_name}' is similar to '{candidate}'",
                                location=f"$.mcpServers.{name}.args",
                                evidence=package,
                            )
                        )

            if (
                pkg_name
                and pkg_name not in MALICIOUS_PACKAGES
                and pkg_name not in VULNERABLE_PACKAGES
                and self._is_unpinned_package_token(command_norm, package)
            ):
                findings.append(
                    ScanFinding(
                        rule_id="VERSION-NOT-PINNED",
                        severity="medium",
                        category="version_pinning",
                        description="Package not pinned to explicit version — may pull breaking or malicious updates",
                        location=f"$.mcpServers.{name}.args",
                        evidence=package,
                    )
                )
            if pkg_name in DEPRECATED_PACKAGES:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0018",
                        severity="low",
                        category="deprecated_package",
                        description=f"Package '{pkg_name}' is deprecated or abandoned",
                        location=f"$.mcpServers.{name}.args",
                        evidence=package,
                        remediation=DEPRECATED_PACKAGES[pkg_name],
                    )
                )

        for arg in args:
            arg_lower = str(arg).lower()
            if "@latest" in arg_lower:
                findings.append(
                    ScanFinding(
                        rule_id="VERSION-NOT-PINNED",
                        severity="medium",
                        category="version_pinning",
                        description="Package not pinned to explicit version — may pull breaking or malicious updates",
                        location=f"$.mcpServers.{name}.args",
                        evidence=str(arg),
                    )
                )
                break

        if command.lower().strip() == "npx":
            has_yes = any(str(arg).strip() == "-y" for arg in args)
            has_pinned_pkg = any(
                self._split_package_and_version(token)[1] is not None for token in package_tokens
            )
            if has_yes and not has_pinned_pkg:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0020",
                        severity="high",
                        category="supply_chain",
                        description="npx -y installs latest version without confirmation",
                        location=f"$.mcpServers.{name}.args",
                        evidence=" ".join([command] + [str(item) for item in args]),
                    )
                )

        for arg in args:
            if not isinstance(arg, str):
                continue
            text = arg.strip()
            if not text:
                continue
            if (
                self._looks_like_secret_candidate(text)
                and self._shannon_entropy(text) > 4.5
                and len(text) >= 20
            ):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0021",
                        severity="high",
                        category="secret_leak",
                        description="High-entropy string in args (possible secret)",
                        location=f"$.mcpServers.{name}.args",
                        evidence=text[:64],
                    )
                )

        for arg in args:
            value = str(arg)
            lower = value.lower()
            if (
                lower.startswith("http://")
                or lower.startswith("https://")
                or lower.startswith("git+https://")
                or lower.startswith("git+ssh://")
                or bool(re.search(r"github\.com/.*/archive/", lower))
            ):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0022",
                        severity="high",
                        category="supply_chain",
                        description="Package installed from URL — bypasses registry security checks",
                        location=f"$.mcpServers.{name}.args",
                        evidence=value,
                    )
                )

        for arg in args:
            value = str(arg)
            for pattern in SENSITIVE_ARG_PATHS:
                if re.search(pattern, value, flags=re.IGNORECASE):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0023",
                            severity="high",
                            category="file_access",
                            description="Sensitive path detected in command arguments",
                            location=f"$.mcpServers.{name}.args",
                            evidence=value,
                        )
                    )
                    break

        for arg in args:
            value = str(arg).strip()
            path_candidate = (
                value.split(":", 1)[0]
                if ":" in value and not value.startswith(("http://", "https://"))
                else value
            )
            if path_candidate in BROAD_PATHS:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0024",
                        severity="high",
                        category="file_access",
                        description="Filesystem access granted to root/home directory — overly broad scope",
                        location=f"$.mcpServers.{name}.args",
                        evidence=value,
                    )
                )

        env = server.get("env")
        if isinstance(env, dict):
            env_values = [f"{k}={v}" for k, v in env.items() if isinstance(v, str)]
        else:
            env_values = []
        for text in [str(item) for item in args if isinstance(item, str)] + env_values:
            for pattern, label, severity in EXTENDED_SECRET_PATTERNS:
                match = re.search(pattern, text)
                if match:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0025",
                            severity=severity,
                            category="secret_leak",
                            description=f"{label} detected",
                            location=f"$.mcpServers.{name}",
                            evidence=match.group(0),
                        )
                    )

    def _check_permissions(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        auto_approve = server.get("autoApprove")
        if auto_approve is True:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0026",
                    severity="high",
                    category="permissions",
                    description="autoApprove wildcard grants unrestricted tool execution without human confirmation",
                    location=f"$.mcpServers.{name}.autoApprove",
                    evidence="true",
                )
            )
        elif isinstance(auto_approve, list):
            normalized = [str(item).strip() for item in auto_approve]
            if "*" in normalized:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0027",
                        severity="high",
                        category="permissions",
                        description="autoApprove wildcard grants unrestricted tool execution without human confirmation",
                        location=f"$.mcpServers.{name}.autoApprove",
                        evidence="*",
                    )
                )
            elif len(normalized) > 5:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0028",
                        severity="high",
                        category="permissions",
                        description="autoApprove includes too many entries and weakens approval controls",
                        location=f"$.mcpServers.{name}.autoApprove",
                        evidence=str(len(normalized)),
                    )
                )

        env = server.get("env")
        if isinstance(env, dict):
            for key in env:
                key_text = str(key)
                for pattern in ADMIN_TOKEN_PATTERNS:
                    if re.search(pattern, key_text, flags=re.IGNORECASE):
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0029",
                                severity="high",
                                category="permissions",
                                description="Admin-level token name in env suggests elevated privilege credential",
                                location=f"$.mcpServers.{name}.env.{key_text}",
                                evidence=key_text,
                            )
                        )
                        break

    def _check_network_and_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        args = self._extract_args(server)
        command = str(server.get("command", "") or "")
        command_lower = command.lower()
        server_name_lower = name.lower()
        url = str(server.get("url", "") or "").strip()
        transport = str(server.get("transport", "") or "").strip().lower()
        parsed = urlparse(url) if url else None
        host = (parsed.hostname or "").lower() if parsed else ""
        remote_http = bool(
            parsed and parsed.scheme in {"http", "https"} and host not in {"localhost", "127.0.0.1"}
        )

        if (
            transport == "sse"
            and parsed
            and parsed.scheme == "http"
            and host not in {"localhost", "127.0.0.1"}
        ):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0030",
                    severity="high",
                    category="transport_security",
                    description="SSE transport over unencrypted HTTP exposes agent traffic",
                    location=f"$.mcpServers.{name}.url",
                    evidence=url,
                )
            )

        if any(re.search(pattern, server_name_lower) for pattern in SHELL_SERVER_PATTERNS) or any(
            re.search(pattern, command_lower) for pattern in SHELL_SERVER_PATTERNS
        ):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0031",
                    severity="high",
                    category="shell_execution",
                    description="Server enables shell/command execution — high privilege risk",
                    location=f"$.mcpServers.{name}",
                    evidence=f"name={name}; command={command}",
                )
            )

        token_stream = [command_lower] + [str(arg).lower() for arg in args]
        if any("sudo" in token or "doas" in token for token in token_stream):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0032",
                    severity="critical",
                    category="privilege_escalation",
                    description="sudo/doas in command grants root-level execution",
                    location=f"$.mcpServers.{name}.args",
                    evidence=" ".join([command] + args),
                )
            )

        for arg in args:
            value = str(arg)
            if "../" in value or "..\\" in value:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0033",
                        severity="high",
                        category="path_traversal",
                        description="Path traversal sequence in args — potential directory escape",
                        location=f"$.mcpServers.{name}.args",
                        evidence=value,
                    )
                )
            if ("/" in value or "\\" in value) and any(
                token in value for token in ("*", "**", "?")
            ):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0034",
                        severity="medium",
                        category="file_access",
                        description="Wildcard glob in path argument — overly broad file access",
                        location=f"$.mcpServers.{name}.args",
                        evidence=value,
                    )
                )

        cors_cfg = server.get("cors")
        allowed_origins = (
            server.get("allowedOrigins")
            or server.get("allowed_origins")
            or server.get("corsOrigins")
        )
        has_origin_validation = bool(cors_cfg) or bool(allowed_origins)
        if remote_http and not has_origin_validation:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0035",
                    severity="medium",
                    category="cors_missing",
                    description="Remote HTTP server without explicit CORS configuration",
                    location=f"$.mcpServers.{name}",
                    evidence=url,
                )
            )

    def _check_cross_server(
        self, servers: list[tuple[str, dict[str, Any]]], findings: list[ScanFinding]
    ) -> None:
        has_filesystem = False
        has_network = False
        server_count = len(servers)
        shared_values: dict[str, set[str]] = {}

        for name, server in servers:
            command = str(server.get("command", "") or "").lower()
            transport = str(server.get("transport", "") or "").lower()
            if "filesystem" in command or "files" in command:
                has_filesystem = True
            if "fetch" in command or "http" in command or transport == "sse":
                has_network = True

            env = server.get("env")
            if isinstance(env, dict):
                for value in env.values():
                    if not isinstance(value, str):
                        continue
                    secret = value.strip()
                    if not self._looks_like_shared_secret(secret):
                        continue
                    shared_values.setdefault(secret, set()).add(name)

        if has_filesystem and has_network:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0036",
                    severity="medium",
                    category="exfiltration_risk",
                    description="Config combines filesystem + network access — potential exfiltration path",
                    location="$.mcpServers (combined)",
                    evidence="filesystem + network/fetch/sse servers present",
                )
            )

        if server_count > 10:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0037",
                    severity="medium",
                    category="attack_surface",
                    description=f"Config defines {server_count} MCP servers — large attack surface",
                    location="$.mcpServers",
                    evidence=str(server_count),
                )
            )

        for value, names in shared_values.items():
            if len(names) >= 2:
                findings.append(
                    ScanFinding(
                        rule_id="TOKEN-SHARED-001",
                        severity="high",
                        category="credential_sharing",
                        description=(
                            "Same credential value shared across multiple servers — single point of compromise"
                        ),
                        location="$.mcpServers",
                        evidence=f"value={value[:8]}... used by {', '.join(sorted(names))}",
                    )
                )

    @staticmethod
    def _looks_like_shared_secret(value: str) -> bool:
        if len(value) < 16:
            return False
        low = value.lower()
        if low in {"password", "secret", "token", "apikey", "api_key", "changeme", "default"}:
            return False
        return bool(re.search(r"[a-zA-Z]", value) and re.search(r"\d", value))

    @staticmethod
    def _compute_server_scores(
        servers: list[tuple[str, dict[str, Any]]], findings: list[ScanFinding]
    ) -> dict[str, int]:
        weights = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
        scores: dict[str, int] = {name: 0 for name, _ in servers}
        for finding in findings:
            for name in list(scores.keys()):
                prefix = f"$.mcpServers.{name}"
                if finding.location.startswith(prefix):
                    scores[name] += int(weights.get(finding.severity.lower(), 0))
                    break
        return {name: min(100, score) for name, score in scores.items()}

    def _check_docker_security(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        args = self._extract_args(server)
        args_text = " ".join(str(item) for item in args)
        command = str(server.get("command", "")).strip().lower()
        docker_cfg = server.get("docker")
        if not isinstance(docker_cfg, dict):
            docker_cfg = {}
        container_cfg = server.get("container")
        if not isinstance(container_cfg, dict):
            container_cfg = {}

        has_docker_context = bool(
            docker_cfg
            or container_cfg
            or str(server.get("image", "")).strip()
            or "docker" in args_text
            or command == "docker"
        )
        if not has_docker_context:
            return

        if "--privileged" in args:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0039",
                    severity="critical",
                    category="docker_security",
                    description="Container runs in privileged mode",
                    location=f"$.mcpServers.{name}.args",
                    evidence="--privileged",
                )
            )

        if "/var/run/docker.sock" in args_text:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0040",
                    severity="critical",
                    category="docker_security",
                    description="Docker socket mount detected",
                    location=f"$.mcpServers.{name}.args",
                    evidence="/var/run/docker.sock",
                )
            )

        for mount in self._extract_mount_specs(args):
            src = mount["source"]
            full = mount["raw"]
            if any(path in src for path in SENSITIVE_MOUNTS):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0041",
                        severity="critical",
                        category="docker_security",
                        description="Sensitive host path mount detected",
                        location=f"$.mcpServers.{name}.args",
                        evidence=full,
                    )
                )
                if not mount["read_only"]:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0042",
                            severity="high",
                            category="docker_security",
                            description="Sensitive host mount without read-only flag (:ro)",
                            location=f"$.mcpServers.{name}.args",
                            evidence=full,
                        )
                    )

        if "--network=host" in args or "--net=host" in args:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0043",
                    severity="high",
                    category="docker_security",
                    description="Container uses host network mode",
                    location=f"$.mcpServers.{name}.args",
                    evidence="--network=host",
                )
            )

        has_user = (
            "--user" in args or bool(docker_cfg.get("user")) or bool(container_cfg.get("user"))
        )
        if not has_user:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0044",
                    severity="medium",
                    category="docker_security",
                    description="Container likely runs as root",
                    location=f"$.mcpServers.{name}",
                    evidence="missing --user and docker.user",
                )
            )

        has_limits = any(
            str(arg).startswith("--memory")
            or str(arg).startswith("--cpus")
            or str(arg).startswith("--pids-limit")
            for arg in args
        )
        if not has_limits:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0045",
                    severity="medium",
                    category="docker_security",
                    description="Container has no resource limits (--memory/--cpus/--pids-limit)",
                    location=f"$.mcpServers.{name}.args",
                    evidence=args_text or "no args",
                )
            )

        if "seccomp=unconfined" in args_text or "apparmor=unconfined" in args_text:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0046",
                    severity="high",
                    category="docker_security",
                    description="Security profile disabled (seccomp/apparmor unconfined)",
                    location=f"$.mcpServers.{name}.args",
                    evidence=args_text,
                )
            )

        image = str(server.get("image", "") or "")
        if image and "@sha256:" not in image and ":" not in image:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0047",
                    severity="medium",
                    category="docker_security",
                    description="Docker image not pinned to digest or tag",
                    location=f"$.mcpServers.{name}.image",
                    evidence=image,
                )
            )

        for idx, arg in enumerate(args):
            if str(arg) == "--cap-add":
                next_arg = str(args[idx + 1]) if idx + 1 < len(args) else ""
                if next_arg.upper() in DANGEROUS_CAPS:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0048",
                            severity="high",
                            category="docker_security",
                            description=f"Dangerous Linux capability added: {next_arg}",
                            location=f"$.mcpServers.{name}.args",
                            evidence=f"--cap-add {next_arg}",
                        )
                    )

    def _check_supply_chain_cves(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        """CVE database pass: substring match, semver vs fixed, CVSS-based severity."""
        prefix = f"$.mcpServers.{name}"
        command = str(server.get("command", "") or "")
        args = self._extract_args(server)
        package_field = str(server.get("package", "") or "")
        haypieces = [command, package_field, *args]
        for vuln_pkg, meta in MCP_CVE_DATABASE.items():
            if not any(h and vuln_pkg in h for h in haypieces):
                continue
            version: str | None = None
            evidence = ""
            for hay in haypieces:
                if not hay or vuln_pkg not in hay:
                    continue
                for part in re.split(r"\s+", hay.strip()):
                    if vuln_pkg not in part:
                        continue
                    _, ver = self._split_package_and_version(part.strip().strip("\"'`,"))
                    if ver:
                        version = ver
                        evidence = part
                        break
                if version:
                    break
            if not evidence:
                for hay in haypieces:
                    if hay and vuln_pkg in hay:
                        evidence = hay[:200]
                        break
            fixed = meta.get("fixed")
            cvss = float(meta.get("cvss") or 0.0)
            cve = str(meta.get("cve", ""))
            desc = str(meta.get("desc", ""))
            if fixed is None:
                severity = "critical"
            elif version is not None and not self._semver_lt(version, str(fixed)):
                continue
            else:
                if cvss >= 9.0:
                    severity = "critical"
                elif cvss >= 7.0:
                    severity = "high"
                else:
                    severity = "medium"
            summary = f"{cve}: {desc}" if desc else cve
            if fixed is None:
                summary = f"{summary} (no fix available)"
            findings.append(
                ScanFinding(
                    rule_id=cve or "CVE-UNKNOWN",
                    severity=severity,
                    category="supply_chain_cve",
                    description=summary,
                    location=prefix,
                    evidence=evidence or vuln_pkg,
                )
            )

    def _check_typosquatting(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        command = str(server.get("command", "") or "")
        args = self._extract_args(server)
        tokens = self._command_tokens(command, args)
        pkg_field = str(server.get("package", "") or "").strip()
        if pkg_field:
            tokens.append(pkg_field)
        legit_exact = set(LEGITIMATE_PACKAGES)
        warned: set[str] = set()
        for tok in tokens:
            if not tok or tok.startswith("-"):
                continue
            clean = tok.strip().strip("\"'`,")
            if not clean or len(clean) > 160:
                continue
            pkg_name, _ver = self._split_package_and_version(clean)
            probe = pkg_name or clean
            if not probe or probe in legit_exact:
                continue
            for leg in LEGITIMATE_PACKAGES:
                dist = self._levenshtein(probe, leg)
                if 1 <= dist <= 2:
                    if probe in warned:
                        break
                    warned.add(probe)
                    findings.append(
                        ScanFinding(
                            rule_id="TYPO-SQUAT-001",
                            severity="high",
                            category="typosquatting",
                            description=(
                                f"Package name '{probe}' is {dist} edits from legitimate '{leg}' — "
                                "possible typosquatting"
                            ),
                            location=f"{prefix}.args",
                            evidence=clean,
                        )
                    )
                    break

    def _check_deprecated_packages(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        command = str(server.get("command", "") or "")
        args = self._extract_args(server)
        package_field = str(server.get("package", "") or "")
        blob = " ".join([command, package_field, *args])
        if not blob.strip():
            return
        for deprecated_name, hint in MCP_SCANNER_DEPRECATED_PACKAGES.items():
            if deprecated_name in blob:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0051",
                        severity="medium",
                        category="deprecated_package",
                        description=f"Deprecated package '{deprecated_name}': {hint}",
                        location=prefix,
                        evidence=deprecated_name,
                    )
                )

    def _check_registry_verification(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        command = str(server.get("command", "") or "").strip().lower()
        args = self._extract_args(server)
        if command in {"npx", "npm", "yarn"}:
            warned_scope = False
            warned_unscoped = False
            for arg in args:
                if not isinstance(arg, str):
                    continue
                raw = arg.strip()
                if not raw or raw.startswith("-"):
                    continue
                if raw.startswith("@") and "/" in raw:
                    scope = raw.split("/", 1)[0]
                    if scope and scope not in TRUSTED_SCOPES:
                        if not warned_scope:
                            warned_scope = True
                            findings.append(
                                ScanFinding(
                                    rule_id="MCP-AUT-0052",
                                    severity="info",
                                    category="registry_verification",
                                    description=f"Unverified npm scope: {scope}",
                                    location=f"{prefix}.args",
                                    evidence=raw[:200],
                                )
                            )
                elif self._is_package_like(raw) and "@" not in raw and "/" not in raw:
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", raw) and not warned_unscoped:
                        warned_unscoped = True
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0053",
                                severity="info",
                                category="registry_verification",
                                description="Unscoped npm package — verify publisher",
                                location=f"{prefix}.args",
                                evidence=raw[:200],
                            )
                        )
        if command in {"uvx", "pip", "pipx"}:
            for arg in args:
                if not isinstance(arg, str):
                    continue
                raw = arg.strip()
                if not raw or raw.startswith("-"):
                    continue
                if raw.startswith(("http://", "https://", "git+", "./", "../")):
                    continue
                base = raw.split("==", 1)[0].split("[", 1)[0].strip()
                if not base or "/" in base or "\\" in base or len(base) > 120:
                    continue
                low = base.lower()
                if any(hint in low for hint in PYPI_PUBLISHER_HINTS):
                    continue
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0054",
                        severity="info",
                        category="registry_verification",
                        description="Unverified PyPI distribution name — verify publisher",
                        location=f"{prefix}.args",
                        evidence=base[:200],
                    )
                )
                break

    @staticmethod
    def _mcp_text_has_injection_marker(text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        return any(marker in low for marker in INJECTION_MARKERS)

    @staticmethod
    def _arg_has_shell_metacharacter(text: str) -> bool:
        if not text:
            return False
        if "&&" in text or "||" in text:
            return True
        if "|" in text or ";" in text:
            return True
        if "$(" in text or "`" in text:
            return True
        if ">>" in text:
            return True
        i = 0
        while True:
            j = text.find(">", i)
            if j == -1:
                break
            left = text[j - 1] if j > 0 else ""
            right = text[j + 1] if j + 1 < len(text) else ""
            if left not in "<=-|" and right != "=":
                return True
            i = j + 1
        return False

    @staticmethod
    def _server_has_logging_signals(server: dict[str, Any]) -> bool:
        for key in server:
            lk = str(key).lower()
            if lk in {"log", "logging", "log_level", "debug", "verbose"}:
                return True
        env = server.get("env")
        if isinstance(env, dict):
            for key in env:
                ku = str(key).upper()
                if ku in {"LOG_FILE", "LOG_LEVEL"}:
                    return True
                if str(key).lower() == "log_level":
                    return True
        return False

    @staticmethod
    def _server_debug_logging_enabled(server: dict[str, Any]) -> bool:
        ll = server.get("log_level")
        if isinstance(ll, str) and ll.strip().lower() in {"debug", "verbose", "trace"}:
            return True
        env = server.get("env")
        if not isinstance(env, dict):
            return False
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            ku = str(key).upper()
            if ku == "LOG_LEVEL" or str(key).lower() == "log_level":
                if value.strip().lower() in {"debug", "verbose", "trace"}:
                    return True
        return False

    @staticmethod
    def _config_value_contains_wildcard_star(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip() == "*"
        if isinstance(value, list):
            return any(
                McpConfigScanner._config_value_contains_wildcard_star(item) for item in value
            )
        if isinstance(value, dict):
            return any(
                McpConfigScanner._config_value_contains_wildcard_star(v) for v in value.values()
            )
        return False

    def _check_prompt_injection_surface(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        for block_key in ("tools", "tool_definitions"):
            block = server.get(block_key)
            if not isinstance(block, list):
                continue
            for idx, tool in enumerate(block):
                if not isinstance(tool, dict):
                    continue
                desc = tool.get("description")
                if not isinstance(desc, str) or not desc:
                    continue
                loc = f"{prefix}.{block_key}[{idx}].description"
                if len(desc) > 500:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0055",
                            severity="medium",
                            category="prompt_injection",
                            description="Suspiciously long tool description",
                            location=loc,
                            evidence=f"{len(desc)} chars",
                        )
                    )
                if self._mcp_text_has_injection_marker(desc):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0056",
                            severity="high",
                            category="prompt_injection",
                            description="Tool description contains possible prompt-injection / instruction override text",
                            location=loc,
                            evidence=desc[:200],
                        )
                    )
        env = server.get("env")
        if isinstance(env, dict):
            for ekey, evalue in env.items():
                if isinstance(evalue, str) and self._mcp_text_has_injection_marker(evalue):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0057",
                            severity="high",
                            category="prompt_injection",
                            description="Env value contains possible prompt-injection / instruction override text",
                            location=f"{prefix}.env.{ekey}",
                            evidence=str(ekey),
                        )
                    )

    def _check_logging_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        if self._server_debug_logging_enabled(server):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0058",
                    severity="medium",
                    category="insufficient_logging",
                    description="Debug logging may expose sensitive data in production",
                    location=prefix,
                    evidence="log_level/debug/verbose/trace",
                )
            )
        if not self._server_has_logging_signals(server):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0059",
                    severity="medium",
                    category="insufficient_logging",
                    description="No logging configured — incidents invisible",
                    location=prefix,
                    evidence="no log/logging/log_level/debug keys or LOG_* env",
                )
            )

    def _check_shadow_servers(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        command = str(server.get("command", "") or "").strip()
        if command:
            norm = command.replace("\\", "/").lower()
            risky_path = (
                command.startswith("./")
                or command.startswith("../")
                or "/home/" in norm
                or "/tmp/" in norm
                or "c:/users" in norm
                or (command.startswith("/") and not command.startswith("//"))
            )
            if risky_path:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0060",
                        severity="high",
                        category="shadow_server",
                        description="Local script as MCP server — unauditable, no update path",
                        location=f"{prefix}.command",
                        evidence=command[:200],
                    )
                )
        url = str(server.get("url", "") or "").strip()
        if not url:
            return
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme not in {"http", "https", "ws", "wss"}:
            return
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme in {"https", "wss"} else 80
        host = (parsed.hostname or "").lower()
        if port not in STANDARD_MCP_URL_PORTS:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0061",
                    severity="info",
                    category="shadow_server",
                    description="Non-standard port — may indicate shadow/dev server",
                    location=f"{prefix}.url",
                    evidence=f"{url} (port {port})",
                )
            )
        if port is not None and port > 10000 and host in {"127.0.0.1", "localhost"}:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0062",
                    severity="medium",
                    category="shadow_server",
                    description="High-port localhost — likely development/temporary",
                    location=f"{prefix}.url",
                    evidence=url,
                )
            )

    def _check_context_oversharing(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        name_lower = name.lower()
        env = server.get("env")
        if isinstance(env, dict):
            for ekey, evalue in env.items():
                if not isinstance(evalue, str) or not evalue.strip():
                    continue
                hints = _cross_service_env_name_hints(str(ekey))
                if hints is None:
                    continue
                if not any(h in name_lower for h in hints):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0063",
                            severity="high",
                            category="context_oversharing",
                            description="Cross-service credential sharing — blast radius risk",
                            location=f"{prefix}.env.{ekey}",
                            evidence=str(ekey),
                        )
                    )
        scope_like_keys = frozenset(
            {"permissions", "scope", "scopes", "allowedscopes", "allowed_scopes"}
        )
        stack: list[tuple[Any, int]] = [(server, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 6 or not isinstance(current, dict):
                continue
            for key, value in current.items():
                kl = str(key).lower()
                if kl in scope_like_keys and self._config_value_contains_wildcard_star(value):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0064",
                            severity="critical",
                            category="context_oversharing",
                            description="Wildcard permissions — unrestricted access",
                            location=f"{prefix}.{key}",
                            evidence="*",
                        )
                    )
                if isinstance(value, dict):
                    stack.append((value, depth + 1))
                elif (
                    isinstance(value, list)
                    and kl == "tools"
                    and self._config_value_contains_wildcard_star(value)
                ):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0065",
                            severity="critical",
                            category="context_oversharing",
                            description="Wildcard permissions — unrestricted access",
                            location=f"{prefix}.{key}",
                            evidence="*",
                        )
                    )
        for sk, raw in server.items():
            lk = str(sk).lower()
            if lk not in {"alloweddirectories", "allowed_paths", "allowedpaths"}:
                continue
            paths = raw if isinstance(raw, list) else [raw]
            for p in paths:
                ps = str(p).strip()
                if not ps:
                    continue
                ps_low = ps.lower()
                if (
                    ps in {"/", "~", "C:\\", "C:/"}
                    or ps.startswith("~/")
                    or ps_low in {"c:\\", "c:/"}
                ):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0066",
                            severity="high",
                            category="context_oversharing",
                            description="Overly broad directory access",
                            location=f"{prefix}.{sk}",
                            evidence=ps[:200],
                        )
                    )
                    break

    def _check_command_injection_risk(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        args = self._extract_args(server)
        for arg in args:
            av = str(arg)
            if self._arg_has_shell_metacharacter(av):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0067",
                        severity="critical",
                        category="command_injection_risk",
                        description="Shell metacharacters in args — command injection risk",
                        location=f"{prefix}.args",
                        evidence=av[:200],
                    )
                )
                break
        command = str(server.get("command", "") or "").strip()
        if command:
            first = command.split()[0]
            base = Path(first.replace("\\", "/")).name.lower()
            if base in RAW_SHELL_COMMANDS:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0068",
                        severity="critical",
                        category="command_injection_risk",
                        description="Raw shell as MCP server — arbitrary command execution",
                        location=f"{prefix}.command",
                        evidence=command[:200],
                    )
                )
        env = server.get("env")
        if isinstance(env, dict):
            for ekey, evalue in env.items():
                if isinstance(evalue, str) and self._arg_has_shell_metacharacter(evalue):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0069",
                            severity="high",
                            category="command_injection_risk",
                            description="Shell metacharacters in env values",
                            location=f"{prefix}.env.{ekey}",
                            evidence=str(ekey),
                        )
                    )
                    break

    def _check_token_management(
        self,
        name: str | None,
        server: dict[str, Any] | None,
        findings: list[ScanFinding],
        shared_cred_index: dict[str, set[str]],
    ) -> None:
        if server is None or name is None:
            for value, names in shared_cred_index.items():
                if len(names) < 2:
                    continue
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0070",
                        severity="high",
                        category="token_management",
                        description="Shared credential across servers — compromising one compromises all",
                        location="$.mcpServers",
                        evidence=(
                            f"{len(names)} servers; value_prefix={value[:24]}..."
                            if len(value) > 24
                            else str(value)
                        ),
                    )
                )
            return
        prefix = f"$.mcpServers.{name}"
        env = server.get("env")
        if not isinstance(env, dict):
            return
        for ekey, evalue in env.items():
            if not isinstance(evalue, str):
                continue
            el = str(ekey).lower()
            if not any(part in el for part in ("token", "key", "secret")):
                continue
            evs = evalue.strip()
            if len(evs) > 100:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0071",
                        severity="info",
                        category="token_management",
                        description="Long-lived credential — consider short-lived tokens",
                        location=f"{prefix}.env.{ekey}",
                        evidence=str(ekey),
                    )
                )
            if len(evs) >= 16:
                shared_cred_index[evs].add(name)

    @staticmethod
    def _config_truthy_bypass(value: Any) -> bool:
        if value is True:
            return True
        if isinstance(value, (int, float)) and int(value) == 1:
            return True
        if isinstance(value, str):
            return value.strip().lower() in {"yes", "true", "1"}
        return False

    def _deep_search_keys(
        self, root: Any, target_keys: frozenset[str] | set[str]
    ) -> list[tuple[str, Any]]:
        """Recursively find (original_key, value) where key matches any target (case-insensitive). Handles cycles."""
        targets_lower = frozenset(str(x).lower() for x in target_keys)
        results: list[tuple[str, Any]] = []
        seen_ids: set[int] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                i = id(node)
                if i in seen_ids:
                    return
                seen_ids.add(i)
                for k, v in node.items():
                    ks = str(k)
                    if ks.lower() in targets_lower:
                        results.append((ks, v))
                    if isinstance(v, (dict, list)):
                        walk(v)
            elif isinstance(node, list):
                i = id(node)
                if i in seen_ids:
                    return
                seen_ids.add(i)
                for item in node:
                    walk(item)

        walk(root)
        return results

    @staticmethod
    def _server_json_blob(server: dict[str, Any]) -> str:
        try:
            return json.dumps(server, default=str).lower()
        except (TypeError, ValueError):
            return str(server).lower()

    def _check_cursor_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        blob = self._server_json_blob(server)
        env = server.get("env")
        if isinstance(env, dict):
            for ek in env:
                if str(ek).upper() == "CURSOR_RULES":
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0072",
                            severity="info",
                            category="cursor_ide_config",
                            description="Cursor rules file referenced — verify no injection in rules",
                            location=f"{prefix}.env.{ek}",
                            evidence=str(ek),
                        )
                    )
                    break
        if ".cursor/rules" in blob:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0073",
                    severity="info",
                    category="cursor_ide_config",
                    description="Cursor rules file referenced — verify no injection in rules",
                    location=prefix,
                    evidence=".cursor/rules",
                )
            )
        for key, value in self._deep_search_keys(
            server, frozenset({"dangerouslySkipPermissions", "dangerously_skip_permissions"})
        ):
            if self._config_truthy_bypass(value):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-DANGEROUSLY-SKIP-PERMISSIONS",
                        severity="critical",
                        category="cursor_ide_config",
                        description="Cursor permission bypass enabled — all safety checks disabled",
                        location=prefix,
                        evidence=key,
                    )
                )
                break
        for wt_key in ("workspace_trust", "workspaceTrust", "trusted_folders", "trustedFolders"):
            raw = server.get(wt_key)
            if raw is None:
                continue
            paths: list[str] = []
            if isinstance(raw, str):
                paths = [raw]
            elif isinstance(raw, list):
                paths = [str(p) for p in raw if p is not None]
            elif isinstance(raw, dict):
                paths = [str(x) for x in raw.values() if isinstance(x, (str, int, float))]
            for p in paths:
                pl = p.strip().lower().replace("\\", "/")
                if not pl:
                    continue
                if pl.startswith("~") or pl.startswith("/home") or pl.startswith("/users"):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0075",
                            severity="medium",
                            category="cursor_ide_config",
                            description="Overly broad workspace trust",
                            location=f"{prefix}.{wt_key}",
                            evidence=p[:200],
                        )
                    )
                    break
                if pl.startswith("c:/users"):
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0076",
                            severity="medium",
                            category="cursor_ide_config",
                            description="Overly broad workspace trust",
                            location=f"{prefix}.{wt_key}",
                            evidence=p[:200],
                        )
                    )
                    break

    def _check_claude_code_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        blob = self._server_json_blob(server)
        permissions = server.get("permissions")
        if isinstance(permissions, dict):
            allow = permissions.get("allow")
            if isinstance(allow, list):
                for entry in allow:
                    if not isinstance(entry, str):
                        continue
                    e = entry.strip()
                    if e == "Bash(*)":
                        findings.append(
                            ScanFinding(
                                rule_id="CLAUDE-BASH-UNRESTRICTED",
                                severity="critical",
                                category="claude_code_config",
                                description="Unrestricted bash execution",
                                location=f"{prefix}.permissions.allow",
                                evidence=e,
                            )
                        )
                    elif e == "Read(*)":
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0078",
                                severity="high",
                                category="claude_code_config",
                                description="Unrestricted file read access",
                                location=f"{prefix}.permissions.allow",
                                evidence=e,
                            )
                        )
                    elif e == "Write(*)":
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0079",
                                severity="critical",
                                category="claude_code_config",
                                description="Unrestricted file write access",
                                location=f"{prefix}.permissions.allow",
                                evidence=e,
                            )
                        )
                    elif e == "WebFetch(*)":
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0080",
                                severity="medium",
                                category="claude_code_config",
                                description="Unrestricted web access",
                                location=f"{prefix}.permissions.allow",
                                evidence=e,
                            )
                        )
                    elif e.startswith("mcp__") and "*" in e:
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0081",
                                severity="high",
                                category="claude_code_config",
                                description="Wildcard MCP tool permission",
                                location=f"{prefix}.permissions.allow",
                                evidence=e,
                            )
                        )
        if "claude.md" in blob or ".claude/" in blob:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0082",
                    severity="info",
                    category="claude_code_config",
                    description="Claude Code project config detected — verify CLAUDE.md integrity",
                    location=prefix,
                    evidence="CLAUDE.md / .claude/",
                )
            )
        model = server.get("model")
        if isinstance(model, str) and model.strip():
            ml = model.lower()
            if any(tok in ml for tok in ("opus", "o1", "gpt-4")):
                top_keys = {str(k).lower() for k in server}
                if "budget" not in top_keys and "max_cost" not in top_keys:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0083",
                            severity="medium",
                            category="claude_code_config",
                            description="Expensive model without budget limit",
                            location=f"{prefix}.model",
                            evidence=model[:120],
                        )
                    )

    def _paperclip_fingerprint(self, server: dict[str, Any]) -> bool:
        if not isinstance(server, dict):
            return False
        keys_lower = {str(k).lower() for k in server}
        if "adapterconfig" in keys_lower or "paperclip" in keys_lower:
            return True
        if isinstance(server.get("heartbeat"), dict):
            return True
        if isinstance(server.get("budget"), dict):
            return True
        return False

    def _check_paperclip_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        if not self._paperclip_fingerprint(server):
            return
        prefix = f"$.mcpServers.{name}"
        for key, value in self._deep_search_keys(
            server, frozenset({"dangerouslySkipPermissions", "dangerously_skip_permissions"})
        ):
            if self._config_truthy_bypass(value):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-DANGEROUSLY-SKIP-PERMISSIONS",
                        severity="critical",
                        category="paperclip_config",
                        description="All Paperclip permission checks disabled — agent has unrestricted access",
                        location=prefix,
                        evidence=key,
                    )
                )
                break
        adapter = server.get("adapterConfig")
        if not isinstance(adapter, dict):
            adapter = server.get("adapter_config")
        if isinstance(adapter, dict):
            aenv = adapter.get("env")
            if isinstance(aenv, dict):
                for ek, ev in aenv.items():
                    if not isinstance(ev, str):
                        continue
                    low = ev.lower()
                    if any(pat in low for pat in PAPERCLIP_SECRET_SUBSTRINGS):
                        findings.append(
                            ScanFinding(
                                rule_id="PAPERCLIP-SECRET-ENV",
                                severity="high",
                                category="paperclip_config",
                                description="Plaintext credentials in Paperclip adapter config",
                                location=f"{prefix}.adapterConfig.env.{ek}",
                                evidence=str(ek),
                            )
                        )
                        break
        budget = server.get("budget")
        if not isinstance(budget, dict):
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0086",
                    severity="medium",
                    category="paperclip_config",
                    description="No budget cap or very high budget — runaway cost risk",
                    location=prefix,
                    evidence="budget missing",
                )
            )
        else:
            raw_max = budget.get("max")
            num = None
            if isinstance(raw_max, (int, float)):
                num = float(raw_max)
            elif isinstance(raw_max, str):
                try:
                    num = float(raw_max.strip())
                except ValueError:
                    num = None
            if num is not None:
                if num > 100:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0087",
                            severity="medium",
                            category="paperclip_config",
                            description="No budget cap or very high budget — runaway cost risk",
                            location=f"{prefix}.budget",
                            evidence=str(raw_max),
                        )
                    )
                if num <= 0:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0088",
                            severity="medium",
                            category="paperclip_config",
                            description="Budget set to zero or negative — likely misconfiguration",
                            location=f"{prefix}.budget",
                            evidence=str(raw_max),
                        )
                    )
            elif "max" not in budget:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0089",
                        severity="medium",
                        category="paperclip_config",
                        description="No budget cap or very high budget — runaway cost risk",
                        location=f"{prefix}.budget",
                        evidence="budget.max missing",
                    )
                )
        heartbeat = server.get("heartbeat")
        if isinstance(heartbeat, dict):
            interval = heartbeat.get("interval")
            iv: int | None = None
            if isinstance(interval, (int, float)):
                iv = int(interval)
            elif isinstance(interval, str):
                try:
                    iv = int(float(interval.strip()))
                except ValueError:
                    iv = None
            if iv is not None:
                if iv > 60000:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0090",
                            severity="medium",
                            category="paperclip_config",
                            description="Slow heartbeat interval — delayed failure detection",
                            location=f"{prefix}.heartbeat",
                            evidence=str(iv),
                        )
                    )
                if iv < 1000:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0091",
                            severity="medium",
                            category="paperclip_config",
                            description="Extremely fast heartbeat — unnecessary overhead",
                            location=f"{prefix}.heartbeat",
                            evidence=str(iv),
                        )
                    )

    def _openclaw_fingerprint(self, server: dict[str, Any]) -> bool:
        keys_lower = {str(k).lower() for k in server}
        return bool(
            keys_lower & {"sandbox", "maxtokens", "sessiondefaults", "loopdetection"}
            or "openclaw" in keys_lower
        )

    def _openclaw_has_elevated_key(self, root: Any) -> bool:
        seen_ids: set[int] = set()

        def walk(node: Any) -> bool:
            if isinstance(node, dict):
                i = id(node)
                if i in seen_ids:
                    return False
                seen_ids.add(i)
                for k, v in node.items():
                    if "elevated" in str(k).lower() and v is not None and v is not False:
                        return True
                    if isinstance(v, (dict, list)) and walk(v):
                        return True
            elif isinstance(node, list):
                i = id(node)
                if i in seen_ids:
                    return False
                seen_ids.add(i)
                for item in node:
                    if walk(item):
                        return True
            return False

        return walk(root)

    def _check_openclaw_config(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        if not self._openclaw_fingerprint(server):
            return
        prefix = f"$.mcpServers.{name}"
        oc: dict[str, Any] = (
            server["openclaw"] if isinstance(server.get("openclaw"), dict) else server
        )
        sandbox = oc.get("sandbox")
        if isinstance(sandbox, dict) and sandbox.get("enabled") is False:
            if self._openclaw_has_elevated_key(server):
                findings.append(
                    ScanFinding(
                        rule_id="OPENCLAW-SANDBOX-OFF",
                        severity="critical",
                        category="openclaw_config",
                        description="Sandbox disabled with elevated permissions — full system access",
                        location=f"{prefix}.sandbox",
                        evidence="enabled=false with elevated",
                    )
                )
        max_tokens = oc.get("maxTokens")
        if max_tokens is None:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0093",
                    severity="medium",
                    category="openclaw_config",
                    description="No token limit or very high limit — cost blowout risk",
                    location=prefix,
                    evidence="maxTokens absent",
                )
            )
        else:
            try:
                mt = int(float(str(max_tokens).strip()))
            except (TypeError, ValueError):
                mt = None
            if mt is not None and mt > 200_000:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0094",
                        severity="medium",
                        category="openclaw_config",
                        description="No token limit or very high limit — cost blowout risk",
                        location=f"{prefix}.maxTokens",
                        evidence=str(max_tokens),
                    )
                )
        session_defaults = oc.get("sessionDefaults")
        if isinstance(session_defaults, dict) and self._config_truthy_bypass(
            session_defaults.get("autoApproveTools")
        ):
            findings.append(
                ScanFinding(
                    rule_id="OPENCLAW-AUTO-APPROVE",
                    severity="high",
                    category="openclaw_config",
                    description="Auto-approve all tool calls — no human-in-the-loop",
                    location=f"{prefix}.sessionDefaults",
                    evidence="autoApproveTools",
                )
            )
        loop_det = oc.get("loopDetection")
        if isinstance(loop_det, dict) and loop_det.get("enabled") is False:
            findings.append(
                ScanFinding(
                    rule_id="OPENCLAW-LOOP-OFF",
                    severity="high",
                    category="openclaw_config",
                    description="Loop detection disabled — agents can loop indefinitely",
                    location=f"{prefix}.loopDetection",
                    evidence="enabled=false",
                )
            )

    def _check_dangerous_permissions_universal(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        warned: set[str] = set()
        for key, value in self._deep_search_keys(server, UNIVERSAL_SAFETY_BYPASS_KEYS):
            if not self._config_truthy_bypass(value):
                continue
            kl = key.lower()
            if kl in warned:
                continue
            warned.add(kl)
            findings.append(
                ScanFinding(
                    rule_id=self._universal_bypass_rule_id(kl),
                    severity="critical",
                    category="safety_bypass",
                    description=f"Safety bypass flag '{key}' enabled — all protections disabled",
                    location=prefix,
                    evidence=key,
                )
            )

    @staticmethod
    def _a2a_collect_nodes(server: dict[str, Any]) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for key in ("a2a", "agentCard", "agent_card"):
            block = server.get(key)
            if isinstance(block, dict):
                nodes.append(block)
        return nodes

    @staticmethod
    def _a2a_collect_key_names(obj: Any, depth: int = 0) -> set[str]:
        names: set[str] = set()
        if depth > 12 or not isinstance(obj, dict):
            return names
        for k, v in obj.items():
            names.add(str(k).lower())
            if isinstance(v, dict):
                names |= McpConfigScanner._a2a_collect_key_names(v, depth + 1)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        names |= McpConfigScanner._a2a_collect_key_names(item, depth + 1)
        return names

    @staticmethod
    def _a2a_iter_string_values(obj: Any, depth: int = 0) -> Any:
        if depth > 12:
            return
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from McpConfigScanner._a2a_iter_string_values(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                yield from McpConfigScanner._a2a_iter_string_values(item, depth + 1)

    @staticmethod
    def _a2a_auth_type_acceptable(raw: Any) -> bool:
        if isinstance(raw, str):
            t = raw.strip().lower()
            return t in {"oauth2", "jwt", "oidc"} or "oauth" in t
        if isinstance(raw, dict):
            for cand in (raw.get("type"), raw.get("scheme"), raw.get("method")):
                if isinstance(cand, str) and McpConfigScanner._a2a_auth_type_acceptable(cand):
                    return True
        return False

    @staticmethod
    def _a2a_has_signature_signals(keys_lower: set[str]) -> bool:
        for k in keys_lower:
            if k in {"signature", "signed", "verify"}:
                return True
            if "signature" in k:
                return True
            if k.startswith("verify") or k.endswith("_verify"):
                return True
        return False

    @staticmethod
    def _a2a_find_authentication_value(obj: Any, depth: int = 0) -> Any:
        if depth > 12 or not isinstance(obj, dict):
            return None
        for k, v in obj.items():
            if str(k).lower() == "authentication":
                return v
        for v in obj.values():
            if isinstance(v, dict):
                found = McpConfigScanner._a2a_find_authentication_value(v, depth + 1)
                if found is not None:
                    return found
        return None

    def _check_a2a_security(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        url = str(server.get("url", "") or "").strip()
        if url and ".well-known/agent-card.json" in url:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0098",
                    severity="info",
                    category="a2a_security",
                    description="A2A discovery endpoint — verify access controls",
                    location=f"{prefix}.url",
                    evidence=url[:200],
                )
            )
        nodes = self._a2a_collect_nodes(server)
        if not nodes:
            return
        merged_keys: set[str] = set()
        for node in nodes:
            merged_keys |= self._a2a_collect_key_names(node)
        has_auth = "authentication" in merged_keys
        if not has_auth:
            findings.append(
                ScanFinding(
                    rule_id="MCP-AUT-0099",
                    severity="critical",
                    category="a2a_security",
                    description="AgentCard without authentication — any agent can connect",
                    location=prefix,
                    evidence="missing authentication",
                )
            )
        else:
            auth_val: Any = None
            for node in nodes:
                auth_val = self._a2a_find_authentication_value(node)
                if auth_val is not None:
                    break
            if not self._a2a_auth_type_acceptable(auth_val):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0100",
                        severity="high",
                        category="a2a_security",
                        description="Weak A2A authentication — use OAuth 2.1 or JWT",
                        location=prefix,
                        evidence=str(auth_val)[:120] if auth_val is not None else "authentication",
                    )
                )
            if not self._a2a_has_signature_signals(merged_keys):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0101",
                        severity="high",
                        category="a2a_security",
                        description="Unsigned AgentCard — identity unverifiable",
                        location=prefix,
                        evidence="no signature/signed/verify",
                    )
                )
        http_plain_seen = False
        for node in nodes:
            for s in self._a2a_iter_string_values(node):
                low = s.strip().lower()
                if not low.startswith("http://"):
                    continue
                if low.startswith("http://localhost") or low.startswith("http://127.0.0.1"):
                    continue
                findings.append(
                    ScanFinding(
                        rule_id="A2A-AGENTCARD-HTTP",
                        severity="critical",
                        category="a2a_security",
                        description="Agent-to-agent communication without TLS",
                        location=prefix,
                        evidence=s[:200],
                    )
                )
                http_plain_seen = True
                break
            if http_plain_seen:
                break
        self._a2a_token_ttl_scan(nodes, prefix, findings)

    def _a2a_token_ttl_scan(
        self, nodes: list[dict[str, Any]], prefix: str, findings: list[ScanFinding]
    ) -> None:
        def walk(o: Any, depth: int = 0) -> bool:
            if depth > 10 or not isinstance(o, dict):
                return False
            kl = {str(x).lower() for x in o.keys()}
            tokenish = bool(
                kl
                & {"token", "tokens", "accesstoken", "access_token", "bearertoken", "credentials"}
            )
            if tokenish:
                ttl_raw = None
                for tk in ("ttl", "expiresIn", "expires_in", "lifetime"):
                    for k in o:
                        if str(k).lower() == tk.lower():
                            ttl_raw = o.get(k)
                            break
                    if ttl_raw is not None:
                        break
                if ttl_raw is None:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0103",
                            severity="medium",
                            category="a2a_security",
                            description="Long-lived A2A tokens — use short-lived credentials",
                            location=prefix,
                            evidence="token config without ttl/expiresIn",
                        )
                    )
                    return True
                try:
                    ttl_num = float(str(ttl_raw).strip())
                except (TypeError, ValueError):
                    return False
                if ttl_num > 3600:
                    findings.append(
                        ScanFinding(
                            rule_id="MCP-AUT-0104",
                            severity="medium",
                            category="a2a_security",
                            description="Long-lived A2A tokens — use short-lived credentials",
                            location=prefix,
                            evidence=f"ttl={ttl_raw}",
                        )
                    )
                    return True
            for v in o.values():
                if isinstance(v, dict) and walk(v, depth + 1):
                    return True
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and walk(item, depth + 1):
                            return True
            return False

        for node in nodes:
            if walk(node):
                break

    @staticmethod
    def _server_endpoint_remote_host(server: dict[str, Any]) -> tuple[bool, str]:
        for key in ("url", "bind", "host"):
            raw = str(server.get(key) or "").strip()
            if not raw:
                continue
            parsed = urlparse(raw if "://" in raw else f"//{raw}")
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
                return False, host
            return True, host
        return False, ""

    @staticmethod
    def _has_runtime_docker_block(server: dict[str, Any]) -> bool:
        if isinstance(server.get("docker"), dict) or isinstance(server.get("container"), dict):
            return True
        return bool(str(server.get("image", "") or "").strip())

    @staticmethod
    def _docker_block_has_resource_limits(cfg: dict[str, Any]) -> bool:
        keys_lower = {str(k).lower() for k in cfg}
        if keys_lower & {"memory", "mem_limit", "cpus", "cpu_limit", "nanocpus", "nano_cpus"}:
            return True
        hc = cfg.get("HostConfig")
        if isinstance(hc, dict):
            hkl = {str(k).lower() for k in hc}
            if hkl & {"memory", "memlimit", "cpus", "cpushares", "nano_cpus"}:
                return True
        res = cfg.get("resources")
        if isinstance(res, dict) and res:
            return True
        return False

    @staticmethod
    def _docker_block_has_restart_policy(cfg: dict[str, Any]) -> bool:
        keys_lower = {str(k).lower() for k in cfg}
        if "restart" in keys_lower or "restartpolicy" in keys_lower:
            return True
        hc = cfg.get("HostConfig")
        if isinstance(hc, dict) and any(str(k).lower() in {"restartpolicy", "restart"} for k in hc):
            return True
        return False

    def _check_runtime_hygiene(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        is_remote, _ = self._server_endpoint_remote_host(server)
        top_keys = {str(k).lower() for k in server}
        env = server.get("env")
        env_keys_upper = {str(k).upper() for k in env} if isinstance(env, dict) else set()
        if is_remote:
            if not (top_keys & {"timeout", "requesttimeout"} or "TIMEOUT" in env_keys_upper):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0105",
                        severity="medium",
                        category="runtime_hygiene",
                        description="No request timeout — hung requests tie up resources",
                        location=prefix,
                        evidence="no timeout/requestTimeout/TIMEOUT",
                    )
                )
            if not (
                top_keys & {"ratelimit", "rate_limit"}
                or env_keys_upper & {"MAX_REQUESTS", "RATE_LIMIT"}
            ):
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0106",
                        severity="medium",
                        category="runtime_hygiene",
                        description="No rate limiting configured — DoS risk",
                        location=prefix,
                        evidence="no rateLimit/rate_limit/MAX_REQUESTS/RATE_LIMIT",
                    )
                )
        if self._has_runtime_docker_block(server):
            limited = False
            for block_key in ("docker", "container"):
                blk = server.get(block_key)
                if isinstance(blk, dict) and self._docker_block_has_resource_limits(blk):
                    limited = True
                    break
            if not limited:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0107",
                        severity="medium",
                        category="runtime_hygiene",
                        description="Container without resource limits — can consume host resources",
                        location=prefix,
                        evidence="docker/container without memory/cpu limits",
                    )
                )
            has_restart = False
            for block_key in ("docker", "container"):
                blk = server.get(block_key)
                if isinstance(blk, dict) and self._docker_block_has_restart_policy(blk):
                    has_restart = True
                    break
            if not has_restart:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0108",
                        severity="info",
                        category="runtime_hygiene",
                        description="No restart policy — server won't auto-recover",
                        location=prefix,
                        evidence="docker/container",
                    )
                )
        port_raw = server.get("port")
        if port_raw is not None:
            try:
                pnum = int(port_raw)
            except (TypeError, ValueError):
                pnum = None
            if pnum == 0:
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0109",
                        severity="info",
                        category="runtime_hygiene",
                        description="Random port assignment — may cause connectivity issues",
                        location=f"{prefix}.port",
                        evidence="0",
                    )
                )

    @staticmethod
    def _env_suggests_local_resource(key: str, value: str) -> bool:
        ku = key.upper()
        low = value.lower()
        if ku in {"DATABASE_URL", "REDIS_URL"}:
            return bool(
                "localhost" in low
                or "127.0.0.1" in low
                or "/tmp/" in low
                or "unix:" in low
                or "/var/run/" in low
            )
        if ku == "FILE_PATH":
            return bool("/" in value or "\\" in value)
        if ku in {"ALLOWED_DIRECTORIES", "ALLOWED_PATHS"}:
            return bool("/" in value or "\\" in value or "~" in value)
        return False

    def _check_network_segmentation(
        self, name: str, server: dict[str, Any], findings: list[ScanFinding]
    ) -> None:
        prefix = f"$.mcpServers.{name}"
        is_remote, _ = self._server_endpoint_remote_host(server)
        if not is_remote:
            pass
        else:
            env = server.get("env")
            if isinstance(env, dict):
                for ek, ev in env.items():
                    if not isinstance(ev, str):
                        continue
                    if self._env_suggests_local_resource(str(ek), ev):
                        findings.append(
                            ScanFinding(
                                rule_id="MCP-AUT-0110",
                                severity="high",
                                category="network_segmentation",
                                description="External server with local resource access — data exfiltration vector",
                                location=f"{prefix}.env.{ek}",
                                evidence=str(ek),
                            )
                        )
                        break
        url = str(server.get("url", "") or "").strip()
        if url:
            parsed = urlparse(url)
            if (parsed.hostname or "").lower() == "localhost":
                findings.append(
                    ScanFinding(
                        rule_id="MCP-AUT-0111",
                        severity="info",
                        category="network_segmentation",
                        description="Use 127.0.0.1 instead of localhost — prevents DNS rebinding",
                        location=f"{prefix}.url",
                        evidence=url[:200],
                    )
                )

    @staticmethod
    def _record_server_listen_port(
        name: str, server: dict[str, Any], port_index: dict[int, list[str]]
    ) -> None:
        praw = server.get("port")
        port_val: int | None = None
        if isinstance(praw, (int, float)):
            try:
                port_val = int(praw)
            except (TypeError, ValueError):
                port_val = None
        elif isinstance(praw, str) and praw.strip().isdigit():
            port_val = int(praw.strip())
        if port_val is None:
            for key in ("url", "bind", "host"):
                raw = str(server.get(key) or "").strip()
                if not raw:
                    continue
                parsed = urlparse(raw if "://" in raw else f"//{raw}")
                if parsed.port is not None:
                    port_val = parsed.port
                    break
        if port_val is not None:
            port_index[port_val].append(name)

    @staticmethod
    def _check_network_port_collisions(
        port_index: defaultdict[int, list[str]] | dict[int, list[str]],
        findings: list[ScanFinding],
    ) -> None:
        for port, names in port_index.items():
            uniq = sorted({n for n in names})
            if len(uniq) < 2:
                continue
            findings.append(
                ScanFinding(
                    rule_id="PORT-COLLISION-001",
                    severity="medium",
                    category="network_segmentation",
                    description=f"Port collision: servers {', '.join(uniq)} both on port {port}",
                    location="$.mcpServers",
                    evidence=str(port),
                )
            )

    @staticmethod
    def _extract_args(server: dict[str, Any]) -> list[str]:
        args = server.get("args")
        if not isinstance(args, list):
            return []
        return [str(item) for item in args]

    @staticmethod
    def _command_tokens(command: str, args: list[str]) -> list[str]:
        tokens: list[str] = []
        if command:
            tokens.extend(part for part in re.split(r"\s+", command.strip()) if part)
        for arg in args:
            tokens.extend(part for part in re.split(r"\s+", arg.strip()) if part)
        return tokens

    @staticmethod
    def _is_package_like(token: str) -> bool:
        if not token or token.startswith("-"):
            return False
        if "/" in token and not token.startswith("@"):
            # keep scoped npm packages, ignore plain paths
            return token.count("/") == 1 and token.startswith("@")
        if token.endswith((".js", ".mjs", ".cjs", ".py", ".sh", ".json")):
            return False
        if token.startswith(("http://", "https://", "ws://", "wss://", "/")):
            return False
        return bool(re.search(r"[a-zA-Z]", token))

    @staticmethod
    def _is_unpinned_package_token(command_norm: str, token: str) -> bool:
        clean = token.strip().strip("\"'`,")
        if not clean:
            return False
        if clean.startswith("-"):
            return False
        if "@latest" in clean.lower():
            return True
        if command_norm == "uvx":
            if "==" in clean:
                return False
            if clean.startswith(("http://", "https://", "git+https://", "git+ssh://")):
                return False
            return bool(re.search(r"[A-Za-z]", clean))
        if command_norm == "npx":
            name, version = McpConfigScanner._split_package_and_version(clean)
            if not name:
                return False
            return version is None
        return False

    @staticmethod
    def _split_package_and_version(token: str) -> tuple[str, str | None]:
        normalized = token.strip().strip("\"'`,")
        if not normalized:
            return "", None
        if normalized.startswith("@"):
            # scoped package, version appears after second '@'
            at_pos = normalized.rfind("@")
            if at_pos > 0 and "/" in normalized[:at_pos]:
                version = normalized[at_pos + 1 :]
                if re.fullmatch(r"\d+(?:\.\d+){0,2}", version):
                    return normalized[:at_pos], version
                return normalized, None
            return normalized, None
        if "@" in normalized:
            name, version = normalized.rsplit("@", 1)
            if re.fullmatch(r"\d+(?:\.\d+){0,2}", version):
                return name, version
        return normalized, None

    @staticmethod
    def _semver_lt(left: str, right: str) -> bool:
        def _parts(value: str) -> list[int]:
            pieces = [int(p) for p in re.findall(r"\d+", value)[:3]]
            while len(pieces) < 3:
                pieces.append(0)
            return pieces

        a = _parts(left)
        b = _parts(right)
        return tuple(a) < tuple(b)

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            curr = [i]
            for j, cb in enumerate(b, start=1):
                cost = 0 if ca == cb else 1
                curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
            prev = curr
        return prev[-1]

    def _nearest_package(self, candidate: str, known: list[str]) -> tuple[str, int] | None:
        best_name = ""
        best_dist = 10**9
        for target in known:
            dist = self._levenshtein(candidate, target)
            if dist < best_dist:
                best_dist = dist
                best_name = target
        if not best_name:
            return None
        return best_name, best_dist

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        length = float(len(value))
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _looks_like_secret_candidate(value: str) -> bool:
        if value.startswith("-"):
            return False
        if "/" in value or "\\" in value:
            return False
        if value.lower().startswith(("http://", "https://", "ws://", "wss://")):
            return False
        return bool(re.search(r"[A-Za-z]", value) and re.search(r"\d", value))

    @staticmethod
    def _extract_mount_specs(args: list[str]) -> list[dict[str, Any]]:
        mounts: list[dict[str, Any]] = []
        idx = 0
        while idx < len(args):
            arg = str(args[idx])
            spec = ""
            if arg in {"-v", "--volume"} and idx + 1 < len(args):
                spec = str(args[idx + 1])
                idx += 2
            elif arg.startswith("-v") and len(arg) > 2:
                spec = arg[2:]
                idx += 1
            elif arg.startswith("--volume="):
                spec = arg.split("=", 1)[1]
                idx += 1
            else:
                idx += 1
            if not spec:
                continue
            parts = spec.split(":")
            source = parts[0] if parts else spec
            read_only = any(part == "ro" for part in parts[2:]) or (
                len(parts) == 3 and parts[-1] == "ro"
            )
            mounts.append({"raw": spec, "source": source, "read_only": read_only})
        return mounts


class PolicyScanner:
    """Scan Orchesis policy.yaml for weaknesses."""

    def scan(self, path: str) -> ScanReport:
        source = Path(path)
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        findings: list[ScanFinding] = []
        if not isinstance(payload, dict):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="policy_yaml",
                    description="Invalid policy format",
                    location="$",
                    evidence="top-level is not a mapping",
                )
            )
            return ScanReport(
                target=str(source),
                target_type="policy_yaml",
                findings=findings,
                risk_score=_calc_risk_score(findings),
                summary=_build_summary(findings),
                scanned_at=_now_iso(),
            )

        default_tier = str(payload.get("default_trust_tier", "")).lower()
        if default_tier in {"operator", "principal", "admin"}:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="weak_default_tier",
                    description="Default trust tier is too permissive",
                    location="default_trust_tier",
                    evidence=default_tier,
                )
            )

        rules = payload.get("rules")
        rules_list = rules if isinstance(rules, list) else []
        has_rate_limit = any(
            isinstance(item, dict) and item.get("name") == "rate_limit" for item in rules_list
        )
        has_budget = any(
            isinstance(item, dict) and item.get("name") == "budget_limit" for item in rules_list
        )
        has_denied_paths = any(
            isinstance(item, dict)
            and item.get("name") == "file_access"
            and isinstance(item.get("denied_paths"), list)
            and len(item.get("denied_paths")) > 0
            for item in rules_list
        )
        has_denied_sql = any(
            isinstance(item, dict)
            and item.get("name") == "sql_restriction"
            and isinstance(item.get("denied_operations"), list)
            and len(item.get("denied_operations")) > 0
            for item in rules_list
        )

        if not has_rate_limit:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="missing_rate_limits",
                    description="No rate limits defined",
                    location="rules",
                    evidence="missing rule: rate_limit",
                )
            )
        if not has_budget:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="missing_budget_limits",
                    description="No budget limits defined",
                    location="rules",
                    evidence="missing rule: budget_limit",
                )
            )
        if not (has_denied_paths or has_denied_sql):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="missing_denies",
                    description="No denied paths/operations configured",
                    location="rules",
                    evidence="missing denied_paths and denied_operations",
                )
            )

        for index, rule in enumerate(rules_list):
            if not isinstance(rule, dict):
                continue
            if rule.get("name") != "file_access":
                continue
            allowed_paths = rule.get("allowed_paths")
            if isinstance(allowed_paths, list):
                if any(item in ("/", "*", "/*") for item in allowed_paths):
                    findings.append(
                        ScanFinding(
                            severity="high",
                            category="broad_file_access",
                            description="Overly broad allowed path",
                            location=f"rules[{index}].allowed_paths",
                            evidence=str(allowed_paths),
                        )
                    )

        agents = payload.get("agents")
        if not isinstance(agents, list) or len(agents) == 0:
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="missing_agents",
                    description="No explicit agent definitions",
                    location="agents",
                    evidence="all agents use default behavior",
                )
            )

        alerts = payload.get("alerts")
        if not isinstance(alerts, dict) or len(alerts) == 0:
            findings.append(
                ScanFinding(
                    severity="low",
                    category="missing_alerts",
                    description="No alert configuration found",
                    location="alerts",
                    evidence="alerts section missing",
                )
            )

        api = payload.get("api")
        token = api.get("token") if isinstance(api, dict) else None
        if not isinstance(token, str) or len(token.strip()) < 12:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="weak_api_token",
                    description="Missing or weak API token",
                    location="api.token",
                    evidence="missing or too short",
                )
            )

        return ScanReport(
            target=str(source),
            target_type="policy_yaml",
            findings=findings,
            risk_score=_calc_risk_score(findings),
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
        )


def discover_mcp_configs() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".config" / "claude" / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
        Path(".vscode") / "mcp.json",
        Path(".claude") / "mcp.json",
    ]
    return [path for path in candidates if path.exists()]


def detect_target_type(path: Path) -> str:
    lowered = path.name.lower()
    if lowered.endswith(".md"):
        return "skill_md"
    if lowered in {"claude_desktop_config.json", "mcp.json"}:
        return "mcp_config"
    if lowered in {"policy.yaml", "policy.yml"}:
        return "policy_yaml"
    return "unknown"


def scan_path(path: Path) -> list[ScanReport]:
    if path.is_dir():
        reports: list[ScanReport] = []
        for file_path in sorted(item for item in path.rglob("*") if item.is_file()):
            if detect_target_type(file_path) == "unknown":
                continue
            reports.extend(scan_path(file_path))
        return reports

    target_type = detect_target_type(path)
    if target_type == "skill_md":
        return [SkillScanner().scan(str(path))]
    if target_type == "mcp_config":
        return [McpConfigScanner().scan(str(path))]
    if target_type == "policy_yaml":
        return [PolicyScanner().scan(str(path))]
    return []


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    server_scores = getattr(report, "server_scores", {}) or {}
    attack_surface_score = int(getattr(report, "attack_surface_score", 0))
    return {
        "target": report.target,
        "target_type": report.target_type,
        "findings": [asdict(item) for item in report.findings],
        "risk_score": report.risk_score,
        "server_scores": dict(server_scores),
        "attack_surface_score": attack_surface_score,
        "summary": report.summary,
        "scanned_at": report.scanned_at,
        "rules_checked": int(getattr(report, "rules_checked", 0)),
        "unique_findings": int(getattr(report, "unique_findings", 0)),
        "dedup_count": int(getattr(report, "dedup_count", 0)),
    }


def grade_from_findings(findings: list[ScanFinding]) -> tuple[str, int]:
    """Letter grade and 0–100 score from finding severities (penalize critical/high/medium/low)."""
    critical = high = medium = low = 0
    for item in findings:
        sev = str(item.severity).lower().strip()
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        elif sev == "low":
            low += 1
    score = 100 - (critical * 25 + high * 10 + medium * 3 + low * 1)
    score = max(0, min(100, score))
    if score >= 100:
        letter = "A+"
    elif score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    else:
        letter = "F"
    return letter, score


def build_report_export_dict(report: ScanReport) -> dict[str, Any]:
    """Structured dict for JSON export (grade + metadata + report fields)."""
    letter, gscore = grade_from_findings(report.findings)
    body = report_to_dict(report)
    return {
        **body,
        "grade": {"letter": letter, "score": gscore},
        "export_metadata": {
            "orchesis_version": ORCHESIS_VERSION,
            "exported_at": _now_iso(),
            "scan_time": report.scanned_at,
        },
    }


def report_to_json(report: ScanReport, *, indent: int = 2) -> str:
    """Pretty JSON for one scan report including grade and export metadata."""
    return json.dumps(build_report_export_dict(report), ensure_ascii=False, indent=indent)


def reports_to_json(
    reports: list[ScanReport],
    *,
    llm_findings_by_target: dict[str, list[dict[str, Any]]] | None = None,
    network_findings: list[dict[str, Any]] | None = None,
    indent: int = 2,
) -> str:
    """Multi-report JSON with grade/metadata per report; optional network_findings."""
    items: list[dict[str, Any]] = []
    for r in reports:
        d = build_report_export_dict(r)
        if llm_findings_by_target is not None:
            d["llm_findings"] = llm_findings_by_target.get(r.target, [])
        items.append(d)
    root: dict[str, Any] = {"reports": items}
    if network_findings:
        root["network_findings"] = network_findings
    return json.dumps(root, ensure_ascii=False, indent=indent)


def _severity_sort_key(sev: str) -> int:
    return int(SEVERITY_ORDER.get(str(sev).lower(), 0))


def _mcp_server_from_location(location: str) -> str | None:
    m = re.search(r"(?:^|\.)mcpServers\.([A-Za-z0-9_-]+)", location)
    return m.group(1) if m else None


def _group_findings_by_mcp_server(
    findings: list[ScanFinding],
) -> list[tuple[str, list[ScanFinding]]]:
    buckets: dict[str, list[ScanFinding]] = defaultdict(list)
    for f in findings:
        key = _mcp_server_from_location(f.location)
        if key is None:
            key = "(other)"
        buckets[key].append(f)
    keys_named = sorted(k for k in buckets if k != "(other)")
    out: list[tuple[str, list[ScanFinding]]] = []
    for k in keys_named:
        out.append(
            (
                k,
                sorted(
                    buckets[k],
                    key=lambda f: _severity_sort_key(str(f.severity)),
                    reverse=True,
                ),
            )
        )
    if "(other)" in buckets:
        out.append(
            (
                "(other)",
                sorted(
                    buckets["(other)"],
                    key=lambda f: _severity_sort_key(str(f.severity)),
                    reverse=True,
                ),
            )
        )
    return out


def _html_rows_for_findings(findings_sorted: list[ScanFinding]) -> str:
    rows: list[str] = []
    for f in findings_sorted:
        sev = str(f.severity).lower()
        rank = _severity_sort_key(sev)
        cls = {
            "critical": "sev-critical",
            "high": "sev-high",
            "medium": "sev-medium",
            "low": "sev-low",
            "info": "sev-info",
        }.get(sev, "sev-info")
        rows.append(
            f'<tr data-severity-rank="{rank}">'
            f'<td class="{cls}">{html_module.escape(sev)}</td>'
            f"<td>{html_module.escape(f.rule_id or '')}</td>"
            f"<td>{html_module.escape(f.category)}</td>"
            f"<td>{html_module.escape(f.description)}</td>"
            f"<td>{html_module.escape(f.location)}</td>"
            "</tr>"
        )
    return (
        "\n".join(rows)
        if rows
        else '<tr data-severity-rank="0"><td colspan="5">No findings</td></tr>'
    )


_SORTABLE_TABLE_SCRIPT = """
<script>
(function(){
function rank(tr){return parseInt(tr.getAttribute("data-severity-rank")||"0",10);}
document.querySelectorAll("table.sortable").forEach(function(table){
  var th = table.tHead && table.tHead.rows[0] && table.tHead.rows[0].cells[0];
  if (!th) return;
  var asc = false;
  th.style.cursor = "pointer";
  th.title = "Click to sort by severity";
  th.addEventListener("click", function(){
    asc = !asc;
    var tb = table.tBodies[0];
    var rows = Array.prototype.slice.call(tb.rows);
    rows.sort(function(a,b){ var da = rank(a), db = rank(b); return asc ? da - db : db - da; });
    rows.forEach(function(r){ tb.appendChild(r); });
  });
});
})();
</script>
"""


def _findings_tables_html(report: ScanReport) -> str:
    findings_sorted = sorted(
        report.findings, key=lambda f: _severity_sort_key(str(f.severity)), reverse=True
    )
    if report.target_type == "mcp_config" and report.findings:
        groups = _group_findings_by_mcp_server(report.findings)
        if len(groups) == 1 and groups[0][0] == "(other)":
            body = _html_rows_for_findings(findings_sorted)
            return f"""<h2>Findings</h2>
<table class="sortable" id="t-main">
<thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Description</th><th>Location</th></tr></thead>
<tbody>
{body}
</tbody>
</table>"""
        parts: list[str] = []
        for i, (server_name, flist) in enumerate(groups):
            body = _html_rows_for_findings(flist)
            esc = html_module.escape(server_name)
            parts.append(
                f"<h3>Server: {esc}</h3>\n"
                f'<table class="sortable" id="t-srv-{i}">\n'
                "<thead><tr><th>Severity</th><th>Rule</th><th>Category</th>"
                "<th>Description</th><th>Location</th></tr></thead>\n<tbody>\n"
                f"{body}\n</tbody>\n</table>"
            )
        return "<h2>Findings by server</h2>\n" + "\n".join(parts)
    body = _html_rows_for_findings(findings_sorted)
    return f"""<h2>Findings</h2>
<table class="sortable" id="t-main">
<thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Description</th><th>Location</th></tr></thead>
<tbody>
{body}
</tbody>
</table>"""


def _network_findings_html_section(findings: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in sorted(
        findings,
        key=lambda d: _severity_sort_key(str(d.get("severity", "info")).lower()),
        reverse=True,
    ):
        sev = str(item.get("severity", "info")).lower()
        rnk = _severity_sort_key(sev)
        cls = {
            "critical": "sev-critical",
            "high": "sev-high",
            "medium": "sev-medium",
            "low": "sev-low",
            "info": "sev-info",
        }.get(sev, "sev-info")
        rows.append(
            f'<tr data-severity-rank="{rnk}">'
            f'<td class="{cls}">{html_module.escape(sev)}</td>'
            f"<td>{html_module.escape(str(item.get('check', '')))}</td>"
            f"<td>{html_module.escape(str(item.get('description', '')))}</td>"
            f"<td>{html_module.escape(str(item.get('evidence', '')))}</td>"
            f"<td>{html_module.escape(str(item.get('recommendation', '')))}</td>"
            "</tr>"
        )
    tbody = (
        "\n".join(rows)
        if rows
        else '<tr data-severity-rank="0"><td colspan="5">No findings</td></tr>'
    )
    return f"""<h2>Network exposure</h2>
<table class="sortable" id="t-net">
<thead><tr><th>Severity</th><th>Check</th><th>Description</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>
{tbody}
</tbody>
</table>"""


_HTML_PAGE_STYLES = """
body { font-family: system-ui, sans-serif; margin: 1.5rem; background: #0f1419; color: #e6edf3; }
h1 { font-size: 1.35rem; }
h2 { font-size: 1.1rem; margin-top: 1.25rem; }
h3 { font-size: 1rem; margin-top: 1rem; color: #8b949e; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin: 1rem 0; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 0.75rem 1rem; }
.card strong { display: block; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }
.sev-break { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0 1rem; }
.pill { padding: 0.2rem 0.55rem; border-radius: 999px; font-size: 0.8rem; }
.pill-critical { background: #3d1111; color: #ff7b72; }
.pill-high { background: #3d2811; color: #ffa657; }
.pill-medium { background: #3d3411; color: #d4a72c; }
.pill-low { background: #11283d; color: #79c0ff; }
.pill-info { background: #21262d; color: #8b949e; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { border: 1px solid #30363d; padding: 0.45rem 0.5rem; text-align: left; vertical-align: top; }
th { background: #161b22; color: #8b949e; }
.sev-critical { color: #ff7b72; font-weight: 600; }
.sev-high { color: #ffa657; font-weight: 600; }
.sev-medium { color: #d4a72c; }
.sev-low { color: #79c0ff; }
.sev-info { color: #8b949e; }
footer { margin-top: 2rem; font-size: 0.8rem; color: #8b949e; }
.grade { font-size: 2rem; font-weight: 700; }
section { margin-bottom: 2.5rem; padding-bottom: 2rem; border-bottom: 1px solid #30363d; }
section:last-of-type { border-bottom: none; }
"""


def report_to_html(report: ScanReport, *, include_footer: bool = True) -> str:
    """Self-contained HTML page for one scan report (inline CSS/JS, no external assets)."""
    letter, gscore = grade_from_findings(report.findings)
    counts: dict[str, int] = defaultdict(int)
    for f in report.findings:
        counts[str(f.severity).lower()] += 1
    crit = counts.get("critical", 0)
    hig = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)
    inf = counts.get("info", 0)
    server_count = len(report.server_scores) if report.server_scores else 0
    if server_count == 0 and report.target_type == "mcp_config":
        server_count = 1

    tables = _findings_tables_html(report)
    exported = _now_iso()
    title = html_module.escape(Path(report.target).name or report.target)
    inner = f"""<h1>Scan report</h1>
<p>Target: {html_module.escape(report.target)} ({html_module.escape(report.target_type)})</p>
<div class="summary">
  <div class="card"><strong>Letter grade</strong><span class="grade">{html_module.escape(letter)}</span> ({gscore}/100)</div>
  <div class="card"><strong>Findings</strong>{len(report.findings)}</div>
  <div class="card"><strong>Servers (scored)</strong>{server_count}</div>
  <div class="card"><strong>Risk score</strong>{int(report.risk_score)}</div>
</div>
<div class="sev-break">
  <span class="pill pill-critical">critical: {crit}</span>
  <span class="pill pill-high">high: {hig}</span>
  <span class="pill pill-medium">medium: {med}</span>
  <span class="pill pill-low">low: {low}</span>
  <span class="pill pill-info">info: {inf}</span>
</div>
<p>{html_module.escape(report.summary)}</p>
{tables}"""
    if not include_footer:
        return inner
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Orchesis scan — {title}</title>
<style>
{_HTML_PAGE_STYLES}
</style>
</head>
<body>
{inner}
{_SORTABLE_TABLE_SCRIPT}
<footer>Scanned by Orchesis MCP Scanner v{html_module.escape(str(ORCHESIS_VERSION))} on {html_module.escape(exported)}</footer>
</body>
</html>
"""


def reports_to_html(
    reports: list[ScanReport],
    *,
    network_findings: list[dict[str, Any]] | None = None,
) -> str:
    """Combine multiple reports (and optional network findings) into one HTML document."""
    net = network_findings or []
    exported = _now_iso()
    if not reports and not net:
        return report_to_html(
            ScanReport(
                target="(empty)",
                target_type="none",
                findings=[],
                risk_score=0,
                summary="No reports",
                scanned_at=_now_iso(),
            )
        )
    if not reports and net:
        net_block = _network_findings_html_section(net)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Orchesis scan — network</title>
<style>
{_HTML_PAGE_STYLES}
</style>
</head>
<body>
<h1>Network exposure scan</h1>
{net_block}
{_SORTABLE_TABLE_SCRIPT}
<footer>Scanned by Orchesis MCP Scanner v{html_module.escape(str(ORCHESIS_VERSION))} on {html_module.escape(exported)}</footer>
</body>
</html>
"""
    if len(reports) == 1 and not net:
        return report_to_html(reports[0])
    parts = [report_to_html(r, include_footer=False) for r in reports]
    net_section = f"<section>{_network_findings_html_section(net)}</section>" if net else ""
    body = "".join(f"<section>{p}</section>" for p in parts) + net_section
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Orchesis scan — combined</title>
<style>
{_HTML_PAGE_STYLES}
</style>
</head>
<body>
<h1>Combined scan reports</h1>
{body}
{_SORTABLE_TABLE_SCRIPT}
<footer>Scanned by Orchesis MCP Scanner v{html_module.escape(str(ORCHESIS_VERSION))} on {html_module.escape(exported)}</footer>
</body>
</html>
"""
