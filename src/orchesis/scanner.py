"""Static security scanners for skill, MCP config, and policy files."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.secret_scanner import SecretScanner

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanFinding:
    severity: str
    category: str
    description: str
    location: str
    evidence: str


@dataclass
class ScanReport:
    target: str
    target_type: str
    findings: list[ScanFinding]
    risk_score: int
    summary: str
    scanned_at: str


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
    filtered = [item for item in report.findings if severity_meets_threshold(item.severity, threshold)]
    if not filtered:
        lines.append("Findings: none")
    else:
        lines.append("Findings:")
        for item in filtered:
            lines.append(
                f"  [{item.severity.upper():<8}] {item.category:<18} {item.location}: {item.description}"
            )
    lines.extend(
        [
            "",
            f"Risk Score: {report.risk_score}/100",
            f"Summary: {report.summary}",
        ]
    )
    return "\n".join(lines)


def format_report_markdown(report: ScanReport, threshold: str = "info") -> str:
    lines = [f"# Scan Report: `{report.target}`", "", f"- Type: `{report.target_type}`"]
    lines.append(f"- Risk Score: `{report.risk_score}/100`")
    lines.append(f"- Summary: {report.summary}")
    lines.append("")
    lines.append("## Findings")
    filtered = [item for item in report.findings if severity_meets_threshold(item.severity, threshold)]
    if not filtered:
        lines.append("- None")
    else:
        for item in filtered:
            lines.append(
                f"- **{item.severity.upper()}** `{item.category}` `{item.location}` - {item.description}"
            )
    return "\n".join(lines)


class SkillScanner:
    """Scan SKILL.md files for suspicious patterns."""

    _URL_RE = re.compile(r"https?://[^\s)>\"]+")

    def __init__(self) -> None:
        self._secret_scanner = SecretScanner()
        self._ioc_matcher = IoCMatcher()

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


class McpConfigScanner:
    """Scan MCP configuration files for security issues."""

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
            )

        for name, server in self._iter_servers(payload):
            prefix = f"$.mcpServers.{name}"
            host = str(server.get("host", "")).strip()
            url = str(server.get("url", "")).strip()
            bind = str(server.get("bind", "")).strip()
            endpoint = url or bind or host
            if "0.0.0.0" in endpoint:
                findings.append(
                    ScanFinding(
                        severity="critical",
                        category="binding_exposure",
                        description=f"server '{name}' binds to 0.0.0.0",
                        location=f"{prefix}.url",
                        evidence=endpoint,
                    )
                )

            auth = server.get("auth")
            token = server.get("token")
            api_key = server.get("apiKey")
            if auth in (None, "", False) and not token and not api_key:
                findings.append(
                    ScanFinding(
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
                if any(item in normalized_tools for item in ("shell_execute", "file_write", "exec")):
                    findings.append(
                        ScanFinding(
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
                            severity="medium",
                            category="version_pinning",
                            description=f"server '{name}' package is not pinned exactly",
                            location=f"{prefix}.package",
                            evidence=package,
                        )
                    )

        return ScanReport(
            target=str(source),
            target_type="mcp_config",
            findings=findings,
            risk_score=_calc_risk_score(findings),
            summary=_build_summary(findings),
            scanned_at=_now_iso(),
        )


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
        has_rate_limit = any(isinstance(item, dict) and item.get("name") == "rate_limit" for item in rules_list)
        has_budget = any(isinstance(item, dict) and item.get("name") == "budget_limit" for item in rules_list)
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
    return {
        "target": report.target,
        "target_type": report.target_type,
        "findings": [asdict(item) for item in report.findings],
        "risk_score": report.risk_score,
        "summary": report.summary,
        "scanned_at": report.scanned_at,
    }
