"""Plugin registry for custom Orchesis rule handlers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Protocol

from orchesis.state import RateLimitTracker

BUILTIN_RULE_TYPES = {
    "budget_limit",
    "rate_limit",
    "file_access",
    "sql_restriction",
    "regex_match",
    "context_rules",
    "composite",
    "identity_check",
}


class RuleHandler(Protocol):
    """Interface for custom rule handlers."""

    def evaluate(
        self,
        rule: dict,
        request: dict,
        *,
        state: RateLimitTracker,
        agent_id: str,
        session_id: str,
    ) -> tuple[list[str], list[str]]: ...


@dataclass
class PluginInfo:
    name: str
    rule_type: str
    version: str
    description: str
    handler: RuleHandler


class PluginRegistry:
    """Registry for custom rule type plugins."""

    def __init__(self):
        self._plugins: dict[str, PluginInfo] = {}

    def register(self, plugin: PluginInfo) -> None:
        if plugin.rule_type in BUILTIN_RULE_TYPES:
            raise ValueError(f"Cannot override built-in rule type: {plugin.rule_type}")
        self._plugins[plugin.rule_type] = plugin

    def get_handler(self, rule_type: str) -> RuleHandler | None:
        plugin = self._plugins.get(rule_type)
        return plugin.handler if plugin is not None else None

    def is_registered(self, rule_type: str) -> bool:
        return rule_type in self._plugins

    def list_plugins(self) -> list[PluginInfo]:
        return list(self._plugins.values())

    def unregister(self, rule_type: str) -> None:
        self._plugins.pop(rule_type, None)


def _extract_plugin_info(module: Any) -> PluginInfo | None:
    candidate = getattr(module, "PLUGIN_INFO", None)
    if isinstance(candidate, PluginInfo):
        return candidate
    factory = getattr(module, "create_plugin", None)
    if callable(factory):
        produced = factory()
        if isinstance(produced, PluginInfo):
            return produced
    getter = getattr(module, "get_plugin_info", None)
    if callable(getter):
        produced = getter()
        if isinstance(produced, PluginInfo):
            return produced
    return None


def _policy_custom_rule_types(policy: dict[str, Any]) -> list[str]:
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return []
    discovered: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        raw_type = rule.get("type")
        if not isinstance(raw_type, str) or not raw_type.strip():
            continue
        rule_type = raw_type.strip()
        if rule_type in BUILTIN_RULE_TYPES or rule_type in seen:
            continue
        seen.add(rule_type)
        discovered.append(rule_type)
    return discovered


def load_plugins_for_policy(
    policy: dict[str, Any],
    modules: list[str] | None = None,
) -> PluginRegistry:
    """Load plugin registry from explicit modules and policy auto-discovery."""
    registry = PluginRegistry()
    module_names: list[str] = []
    if modules:
        module_names.extend(modules)
    for rule_type in _policy_custom_rule_types(policy):
        module_names.append(f"orchesis.contrib.{rule_type}")
    seen: set[str] = set()
    for module_name in module_names:
        if module_name in seen:
            continue
        seen.add(module_name)
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        info = _extract_plugin_info(module)
        if info is not None:
            registry.register(info)
    return registry
