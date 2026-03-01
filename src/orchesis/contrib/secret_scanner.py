"""Secret scanner utilities for static text and tool payloads."""

from __future__ import annotations

import re
from typing import Any

# Pattern registry: name -> (regex, severity, description)
SECRET_PATTERNS: dict[str, tuple[re.Pattern[str], str, str]] = {
    # API Keys
    "openai_key": (
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        "critical",
        "OpenAI API key",
    ),
    "anthropic_key": (
        re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"),
        "critical",
        "Anthropic API key",
    ),
    "aws_access_key": (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical",
        "AWS Access Key ID",
    ),
    "aws_secret_key": (
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}"),
        "critical",
        "AWS Secret Access Key",
    ),
    "github_token": (
        re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
        "critical",
        "GitHub Personal Access Token",
    ),
    "github_fine_grained": (
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        "critical",
        "GitHub Fine-Grained Token",
    ),
    "stripe_key": (
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "critical",
        "Stripe Live Secret Key",
    ),
    "slack_token": (
        re.compile(r"xox[bpors]-[0-9A-Za-z\-]{10,}"),
        "high",
        "Slack Token",
    ),
    "slack_webhook": (
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ),
        "high",
        "Slack Webhook URL",
    ),
    "telegram_token": (
        re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        "high",
        "Telegram Bot Token",
    ),
    "google_api_key": (
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "high",
        "Google API Key",
    ),
    # Private Keys & Certs
    "private_key": (
        re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
        "Private Key",
    ),
    "ssh_private": (
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "critical",
        "SSH Private Key",
    ),
    # Database URLs
    "postgres_url": (
        re.compile(r"postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]+"),
        "critical",
        "PostgreSQL Connection URL with credentials",
    ),
    "mysql_url": (
        re.compile(r"mysql://[^\s]+:[^\s]+@[^\s]+"),
        "critical",
        "MySQL Connection URL with credentials",
    ),
    "mongodb_url": (
        re.compile(r"mongodb(?:\+srv)?://[^\s]+:[^\s]+@[^\s]+"),
        "critical",
        "MongoDB Connection URL with credentials",
    ),
    "redis_url": (
        re.compile(r"redis://[^\s]*:[^\s]+@[^\s]+"),
        "high",
        "Redis Connection URL with credentials",
    ),
    # JWT & Bearer
    "jwt_token": (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "high",
        "JWT Token",
    ),
    "bearer_token": (
        re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}"),
        "high",
        "Bearer Token",
    ),
    # Crypto
    "ethereum_private": (
        re.compile(r"0x[0-9a-fA-F]{64}"),
        "critical",
        "Possible Ethereum Private Key",
    ),
    # Generic patterns
    "generic_secret": (
        re.compile(
            r"(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*['\"]?[^\s'\"]{8,}"
        ),
        "medium",
        "Generic secret assignment",
    ),
    "env_file_content": (
        re.compile(r"(?i)^[A-Z_]{3,}=[^\s]{8,}$", re.MULTILINE),
        "medium",
        "Environment variable assignment",
    ),
}


def _redact_value(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-4:]}"


class SecretScanner:
    """Scan text for leaked secrets, API keys, credentials."""

    def __init__(
        self,
        patterns: dict[str, tuple[re.Pattern[str], str, str]] | None = None,
        custom_patterns: dict[str, tuple[re.Pattern[str], str, str]] | None = None,
        ignore_patterns: list[str] | None = None,
    ):
        self._patterns = dict(patterns or SECRET_PATTERNS)
        if custom_patterns:
            self._patterns.update(custom_patterns)
        if ignore_patterns:
            for name in ignore_patterns:
                self._patterns.pop(name, None)

    def scan_text(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not isinstance(text, str) or not text:
            return findings
        for pattern_name, (pattern, severity, description) in self._patterns.items():
            for match in pattern.finditer(text):
                raw_value = match.group(0)
                findings.append(
                    {
                        "pattern": pattern_name,
                        "severity": severity,
                        "description": description,
                        "match": _redact_value(raw_value),
                        "position": match.start(),
                        "raw_match": raw_value,
                    }
                )
        return sorted(findings, key=lambda item: int(item.get("position", 0)))

    def scan_dict(self, data: dict[str, Any], path: str = "") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        def walk(value: Any, current_path: str) -> None:
            if isinstance(value, str):
                for finding in self.scan_text(value):
                    item = dict(finding)
                    item["path"] = current_path or "$"
                    findings.append(item)
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{current_path}.{key}" if current_path else str(key)
                    walk(child, child_path)
                return
            if isinstance(value, list):
                for index, child in enumerate(value):
                    child_path = f"{current_path}[{index}]"
                    walk(child, child_path)

        walk(data, path)
        return findings

    def scan_tool_call(self, tool_name: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        findings = self.scan_dict(params, path="params")
        for finding in findings:
            finding["tool"] = tool_name
        return findings

    def has_secrets(self, text: str) -> bool:
        return len(self.scan_text(text)) > 0

    @staticmethod
    def redact(text: str, findings: list[dict[str, Any]]) -> str:
        redacted = text
        for finding in findings:
            raw = finding.get("raw_match")
            if isinstance(raw, str) and raw:
                redacted = redacted.replace(raw, "[REDACTED]")
        return redacted
