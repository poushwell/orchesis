"""Credential injection engine for proxy requests."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from orchesis.credential_vault import CredentialNotFoundError, CredentialVault


@dataclass(frozen=True)
class InjectionRule:
    alias: str
    target: str
    match_tools: list[str]
    header_name: str | None = None
    header_template: str | None = None
    param_name: str | None = None


class CredentialInjector:
    def __init__(self, credentials_config: dict[str, Any] | None, vault: CredentialVault) -> None:
        self._vault = vault
        self._rules = self._parse_rules(credentials_config)

    @staticmethod
    def _parse_rules(credentials_config: dict[str, Any] | None) -> list[InjectionRule]:
        if not isinstance(credentials_config, dict):
            return []
        raw_rules = credentials_config.get("inject")
        if not isinstance(raw_rules, list):
            return []
        parsed: list[InjectionRule] = []
        for item in raw_rules:
            if not isinstance(item, dict):
                continue
            alias = item.get("alias")
            target = item.get("target")
            match_tools = item.get("match_tools")
            if not isinstance(alias, str) or not alias.strip():
                continue
            if not isinstance(target, str) or target not in {"header", "param"}:
                continue
            if not isinstance(match_tools, list) or not match_tools:
                continue
            patterns = [str(pattern).strip() for pattern in match_tools if isinstance(pattern, str) and pattern.strip()]
            if not patterns:
                continue
            parsed.append(
                InjectionRule(
                    alias=alias.strip(),
                    target=target,
                    match_tools=patterns,
                    header_name=item.get("header_name") if isinstance(item.get("header_name"), str) else None,
                    header_template=item.get("header_template") if isinstance(item.get("header_template"), str) else None,
                    param_name=item.get("param_name") if isinstance(item.get("param_name"), str) else None,
                )
            )
        return parsed

    @property
    def rules(self) -> list[InjectionRule]:
        return list(self._rules)

    def _matches(self, tool_name: str, rule: InjectionRule) -> bool:
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in rule.match_tools)

    def matching_aliases(self, tool_name: str) -> list[str]:
        aliases = [rule.alias for rule in self._rules if self._matches(tool_name, rule)]
        return sorted(dict.fromkeys(aliases))

    def inject(self, tool_call: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        tool_name = tool_call.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            return dict(tool_call), []
        output = {
            "tool_name": tool_name,
            "params": dict(tool_call.get("params") if isinstance(tool_call.get("params"), dict) else {}),
            "headers": dict(tool_call.get("headers") if isinstance(tool_call.get("headers"), dict) else {}),
        }
        injected_aliases: list[str] = []
        for rule in self._rules:
            if not self._matches(tool_name, rule):
                continue
            value = self._vault.get(rule.alias)
            injected_aliases.append(rule.alias)
            if rule.target == "header":
                header_name = rule.header_name or "Authorization"
                if rule.header_template:
                    rendered = rule.header_template.replace("{value}", value)
                else:
                    rendered = value
                output["headers"][header_name] = rendered
            elif rule.target == "param":
                param_name = rule.param_name or rule.alias
                output["params"][param_name] = value
        return output, sorted(dict.fromkeys(injected_aliases))

    def scrub(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        scrubbed = {
            "tool_name": tool_call.get("tool_name"),
            "params": dict(tool_call.get("params") if isinstance(tool_call.get("params"), dict) else {}),
            "headers": dict(tool_call.get("headers") if isinstance(tool_call.get("headers"), dict) else {}),
        }
        for rule in self._rules:
            alias_marker = f"[REDACTED:{rule.alias}]"
            if rule.target == "param":
                key = rule.param_name or rule.alias
                if key in scrubbed["params"]:
                    scrubbed["params"][key] = alias_marker
            if rule.target == "header":
                key = rule.header_name or "Authorization"
                if key in scrubbed["headers"]:
                    scrubbed["headers"][key] = alias_marker
        return scrubbed


__all__ = ["CredentialInjector", "CredentialNotFoundError", "CredentialVault", "InjectionRule"]
