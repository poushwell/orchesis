"""Pluggable request/response hooks for proxy pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
import time
from typing import Any


class ProxyPlugin(ABC):
    """Base class for proxy pipeline plugins."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    def priority(self) -> int:
        return 50  # 0=first, 100=last

    @abstractmethod
    def on_request(self, request: dict, context: dict) -> dict:
        """Called before forwarding. Return modified request."""

    def on_response(self, response: dict, context: dict) -> dict:
        """Called after receiving response. Return modified response."""
        return response

    def on_error(self, error: Exception, context: dict) -> None:
        """Called on pipeline error."""
        _ = (error, context)


class PluginRegistry:
    """Manages proxy plugins."""

    def __init__(self):
        self._plugins: list[ProxyPlugin] = []

    def register(self, plugin: ProxyPlugin) -> None:
        """Register plugin. Sorted by priority."""
        self.unregister(plugin.name)
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda item: (int(item.priority), str(item.name)))

    def unregister(self, name: str) -> bool:
        before = len(self._plugins)
        self._plugins = [plugin for plugin in self._plugins if plugin.name != str(name)]
        return len(self._plugins) != before

    def run_request(self, request: dict, context: dict) -> dict:
        """Run all plugins on request in priority order."""
        current = request if isinstance(request, dict) else {}
        for plugin in self._plugins:
            try:
                out = plugin.on_request(current, context)
                if isinstance(out, dict):
                    current = out
            except Exception as error:
                plugin.on_error(error, context)
        return current

    def run_response(self, response: dict, context: dict) -> dict:
        """Run all plugins on response in reverse priority order."""
        current = response if isinstance(response, dict) else {}
        for plugin in reversed(self._plugins):
            try:
                out = plugin.on_response(current, context)
                if isinstance(out, dict):
                    current = out
            except Exception as error:
                plugin.on_error(error, context)
        return current

    def list_plugins(self) -> list[dict]:
        """List registered plugins with metadata."""
        return [
            {
                "name": plugin.name,
                "priority": int(plugin.priority),
                "class": plugin.__class__.__name__,
            }
            for plugin in self._plugins
        ]


class RequestLoggerPlugin(ProxyPlugin):
    """Logs all requests with timing."""

    name = "request_logger"
    priority = 10

    def on_request(self, request: dict, context: dict) -> dict:
        context["request_started_at"] = time.perf_counter()
        logs = context.setdefault("plugin_logs", [])
        if isinstance(logs, list):
            logs.append({"plugin": self.name, "event": "request"})
        return request

    def on_response(self, response: dict, context: dict) -> dict:
        started = context.get("request_started_at")
        if isinstance(started, int | float):
            context["request_latency_ms"] = (time.perf_counter() - float(started)) * 1000.0
        logs = context.setdefault("plugin_logs", [])
        if isinstance(logs, list):
            logs.append({"plugin": self.name, "event": "response"})
        return response


class RequestEnricherPlugin(ProxyPlugin):
    """Adds metadata headers to requests."""

    name = "request_enricher"
    priority = 20

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        add_headers = cfg.get("add_headers", {"X-Orchesis-Agent": "true"})
        self._headers = add_headers if isinstance(add_headers, dict) else {"X-Orchesis-Agent": "true"}

    def on_request(self, request: dict, context: dict) -> dict:
        out = dict(request)
        headers = out.get("headers")
        merged = dict(headers) if isinstance(headers, dict) else {}
        for key, value in self._headers.items():
            if isinstance(key, str):
                merged[key] = str(value)
        out["headers"] = merged
        context["enriched_headers"] = list(merged.keys())
        return out


class ResponseValidatorPlugin(ProxyPlugin):
    """Validates response structure."""

    name = "response_validator"
    priority = 90

    def on_request(self, request: dict, context: dict) -> dict:
        return request

    def on_response(self, response: dict, context: dict) -> dict:
        out = dict(response)
        has_status = isinstance(out.get("status"), int)
        has_body = isinstance(out.get("body"), bytes | str | dict | list)
        context["response_valid"] = bool(has_status and has_body)
        if not has_status:
            out["status"] = 200
        return out
