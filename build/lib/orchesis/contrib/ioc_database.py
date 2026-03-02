"""In-memory Indicators of Compromise (IoC) database and matcher."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IoC:
    id: str
    name: str
    category: str
    source: str
    severity: str
    indicators: list[str]
    description: str
    cve: str | None = None
    mitre_atlas: str | None = None


IOC_DATABASE: list[IoC] = [
    IoC(
        id="CLAWH-001",
        name="ClawHavoc AMOS Dropper",
        category="malicious_skill",
        source="Aikido Security, Feb 2026",
        severity="critical",
        indicators=[
            r"curl\s+-[sS]*\s+https?://\d+\.\d+\.\d+\.\d+",
            r"base64\s+-[dD]",
            r"osascript\s+-e",
            r"/tmp/\.\w+",
            r"launchctl\s+load",
            r"chmod\s+\+x\s+/tmp/",
        ],
        description="Atomic macOS stealer distributed via malicious skills.",
    ),
    IoC(
        id="CLAWH-002",
        name="Credential Harvesting Skill",
        category="credential_theft",
        source="Snyk, Feb 2026",
        severity="critical",
        indicators=[
            r"(?i)send.*api[_\s]?key.*to",
            r"(?i)post.*credentials.*http",
            r"(?i)upload.*\.ssh",
            r"(?i)read.*\.aws/credentials",
            r"(?i)cat.*/etc/shadow",
            r"webhook\.site",
            r"requestbin\.com",
            r"ngrok\.io",
            r"pipedream\.net",
        ],
        description="Skills attempting to exfiltrate credentials.",
    ),
    IoC(
        id="INJECT-001",
        name="Hidden Instruction Injection",
        category="prompt_injection",
        source="Zenity Research, Feb 2026",
        severity="high",
        indicators=[
            r"(?i)ignore\s+(all\s+)?previous\s+instructions",
            r"(?i)do\s+not\s+tell\s+the\s+user",
            r"(?i)secretly\s+",
            r"(?i)without\s+(the\s+)?user('s)?\s+knowledge",
            r"(?i)you\s+are\s+now\s+a\s+",
            r"(?i)new\s+instructions?\s*:",
            r"(?i)system\s+prompt\s*:",
            r"(?i)override\s+(all\s+)?safety",
            r"\u200b",
            r"\u200c",
            r"\u200d",
            r"\u2066",
            r"\u2067",
            r"\u202e",
        ],
        description="Hidden instructions and Unicode obfuscation for prompt injection.",
    ),
    IoC(
        id="CVE-2026-25253",
        name="OpenClaw Gateway Token Theft",
        category="gateway_attack",
        source="Depthfirst, Feb 2026",
        severity="critical",
        cve="CVE-2026-25253",
        indicators=[
            r"gatewayUrl\s*=",
            r"ws://[^/]*:\d+/ws",
            r"token\s*=\s*[a-zA-Z0-9_\-]{20,}",
        ],
        description="Crafted URL exfiltration via WebSocket token theft.",
    ),
    IoC(
        id="SUPPLY-001",
        name="Typosquatting MCP Package",
        category="malicious_package",
        source="Composio, Feb 2026",
        severity="high",
        indicators=[
            r"mcp-server-(?:git|fs|db)\d",
            r"@[a-z]+-unofficial/",
            r"openclaw-(?:plugin|skill|addon)-\w+",
        ],
        description="Typosquatted packages imitating official MCP servers.",
    ),
    IoC(
        id="STEAL-001",
        name="OpenClaw File Theft",
        category="infostealer",
        source="Hudson Rock, Feb 2026",
        severity="critical",
        indicators=[
            r"openclaw\.json",
            r"device\.json",
            r"soul\.md",
            r"\.clawdbot/",
            r"gateway\.lock",
            r"gateway\.auth\.token",
        ],
        description="Infostealers targeting OpenClaw config and gateway tokens.",
    ),
]


class IoCMatcher:
    """Match text/files against IoC database."""

    def __init__(self, iocs: list[IoC] | None = None, custom_iocs: list[IoC] | None = None):
        self._iocs = list(iocs or IOC_DATABASE)
        if custom_iocs:
            self._iocs.extend(custom_iocs)
        self._compiled: dict[str, list[tuple[re.Pattern[str], str]]] = {
            ioc.id: [(re.compile(pattern), pattern) for pattern in ioc.indicators]
            for ioc in self._iocs
        }

    def scan_text(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not isinstance(text, str) or not text:
            return findings
        for ioc in self._iocs:
            for compiled, source_pattern in self._compiled.get(ioc.id, []):
                for match in compiled.finditer(text):
                    findings.append(
                        {
                            "ioc_id": ioc.id,
                            "ioc_name": ioc.name,
                            "category": ioc.category,
                            "severity": ioc.severity,
                            "matched_pattern": source_pattern,
                            "position": match.start(),
                            "match": match.group(0),
                        }
                    )
        return findings

    def scan_file(self, path: str) -> list[dict[str, Any]]:
        source = Path(path)
        if not source.exists() or not source.is_file():
            return []
        try:
            content = source.read_text(encoding="utf-8")
        except OSError:
            return []
        findings = self.scan_text(content)
        for item in findings:
            item["path"] = str(source)
        return findings

    def scan_skill(self, path: str) -> list[dict[str, Any]]:
        return self.scan_file(path)

    def get_ioc(self, ioc_id: str) -> IoC | None:
        for ioc in self._iocs:
            if ioc.id == ioc_id:
                return ioc
        return None

    def list_iocs(self, category: str | None = None, severity: str | None = None) -> list[IoC]:
        result = self._iocs
        if isinstance(category, str) and category:
            result = [ioc for ioc in result if ioc.category == category]
        if isinstance(severity, str) and severity:
            result = [ioc for ioc in result if ioc.severity == severity]
        return result
