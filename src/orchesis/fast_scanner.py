"""Fast multi-pattern scanners using Aho-Corasick prefilter + regex validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from orchesis.ahocorasick import AhoCorasickMatcher


@dataclass(frozen=True)
class _RuleSpec:
    name: str
    regex: re.Pattern[str]
    severity: str
    description: str
    anchors: tuple[str, ...]


class FastSecretScanner:
    def __init__(self, patterns: dict[str, tuple[re.Pattern[str], str, str]]) -> None:
        self._rules: list[_RuleSpec] = []
        anchor_map: dict[str, str] = {}
        for name, (compiled, severity, description) in patterns.items():
            anchors = self._secret_anchors_for(name)
            self._rules.append(
                _RuleSpec(
                    name=name,
                    regex=compiled,
                    severity=severity,
                    description=description,
                    anchors=anchors,
                )
            )
            for idx, anchor in enumerate(anchors):
                anchor_map[f"{name}:{idx}"] = anchor
        self._matcher = AhoCorasickMatcher(anchor_map, case_insensitive=True)

    @staticmethod
    def _secret_anchors_for(name: str) -> tuple[str, ...]:
        mapping = {
            "openai_key": ("sk-",),
            "anthropic_key": ("sk-ant-",),
            "aws_access_key": ("akia",),
            "aws_secret_key": ("aws_secret_access_key",),
            "github_token": ("ghp_", "ghs_"),
            "github_fine_grained": ("github_pat_",),
            "stripe_key": ("sk_live_",),
            "slack_token": ("xox",),
            "slack_webhook": ("hooks.slack.com/services/",),
            "telegram_token": (":",),
            "google_api_key": ("aiza",),
            "private_key": ("-----begin", "private key"),
            "ssh_private": ("openssh private key",),
            "postgres_url": ("postgres://", "postgresql://"),
            "mysql_url": ("mysql://",),
            "mongodb_url": ("mongodb://", "mongodb+srv://"),
            "redis_url": ("redis://",),
            "jwt_token": ("eyj",),
            "bearer_token": ("bearer ",),
            "ethereum_private": ("0x",),
            "generic_secret": ("password", "secret", "token", "api_key", "apikey"),
            "env_file_content": ("=",),
        }
        return mapping.get(name, ())

    @staticmethod
    def _redact_value(value: str) -> str:
        if len(value) <= 8:
            return "[REDACTED]"
        return f"{value[:4]}...{value[-4:]}"

    def scan(self, text: str) -> list[dict[str, Any]]:
        if not isinstance(text, str) or text == "":
            return []
        matched_rule_names: set[str] = set()
        for match in self._matcher.search(text):
            rule_name = str(match.pattern_id).split(":", 1)[0]
            matched_rule_names.add(rule_name)
        findings: list[dict[str, Any]] = []
        for rule in self._rules:
            if rule.anchors and rule.name not in matched_rule_names:
                continue
            for item in rule.regex.finditer(text):
                raw = item.group(0)
                findings.append(
                    {
                        "pattern": rule.name,
                        "severity": rule.severity,
                        "description": rule.description,
                        "match": self._redact_value(raw),
                        "position": item.start(),
                        "raw_match": raw,
                    }
                )
        return sorted(findings, key=lambda item: int(item.get("position", 0)))


class FastPIIDetector:
    def __init__(self, patterns: dict[str, tuple[re.Pattern[str], str, str]]) -> None:
        self._rules: list[_RuleSpec] = []
        anchor_map: dict[str, str] = {}
        for name, (compiled, severity, description) in patterns.items():
            anchors = self._pii_anchors_for(name)
            self._rules.append(
                _RuleSpec(
                    name=name,
                    regex=compiled,
                    severity=severity,
                    description=description,
                    anchors=anchors,
                )
            )
            for idx, anchor in enumerate(anchors):
                anchor_map[f"{name}:{idx}"] = anchor
        self._matcher = AhoCorasickMatcher(anchor_map, case_insensitive=True)

    @staticmethod
    def _pii_anchors_for(name: str) -> tuple[str, ...]:
        mapping = {
            "email": ("@", ".com", ".org", ".net"),
            "phone_us": ("-", "(", ")"),
            "phone_intl": ("+",),
            "ssn": ("-",),
            "passport_us": (),
            "credit_card_visa": ("4",),
            "credit_card_mc": ("5",),
            "credit_card_amex": ("34", "37"),
            "iban": (),
            "swift_bic": (),
            "icd10_code": (),
            "npi_number": (),
            "ipv4_address": (".",),
            "mac_address": (":", "-"),
            "date_of_birth": ("dob", "born", "/", "-"),
            "drivers_license": ("license", "dl"),
        }
        return mapping.get(name, ())

    def scan(
        self,
        text: str,
        *,
        threshold_rank: int,
        ignored_patterns: set[str],
        mask_fn,
        severity_rank: dict[str, int],
    ) -> list[dict[str, Any]]:
        if not isinstance(text, str) or text == "":
            return []
        matched_rule_names: set[str] = set()
        for match in self._matcher.search(text):
            rule_name = str(match.pattern_id).split(":", 1)[0]
            matched_rule_names.add(rule_name)
        findings: list[dict[str, Any]] = []
        for rule in self._rules:
            if rule.name in ignored_patterns:
                continue
            if severity_rank.get(rule.severity, 0) < threshold_rank:
                continue
            if rule.anchors and rule.name not in matched_rule_names:
                continue
            for item in rule.regex.finditer(text):
                raw = item.group(0)
                findings.append(
                    {
                        "pattern": rule.name,
                        "severity": rule.severity,
                        "description": rule.description,
                        "match": mask_fn(raw, rule.name),
                        "position": item.start(),
                    }
                )
        return sorted(findings, key=lambda item: int(item.get("position", 0)))
