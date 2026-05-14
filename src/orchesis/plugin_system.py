"""Pluggable request/response hooks for proxy pipeline.

Two registries coexist:

- :class:`PluginRegistry` — legacy **proxy** plugins (:class:`ProxyPlugin`) used by ``proxy.py``
  (``run_request`` / ``run_response``).

- :class:`OrchesisHookRegistry` / :class:`OrchesisPipelinePluginRegistry` — **extension** plugins
  (:class:`OrchesisPlugin`) with named hooks (``fire_hook``). Proxy does not call these yet.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
import importlib
import importlib.util
import inspect
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
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
        self._headers = (
            add_headers if isinstance(add_headers, dict) else {"X-Orchesis-Agent": "true"}
        )

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


# --- Pipeline extension plugins (foundation; proxy integration later) ---


@dataclass
class PluginInfo:
    """Metadata for an Orchesis extension plugin."""

    name: str
    version: str
    author: str = ""
    description: str = ""
    hooks: list[str] = field(default_factory=list)


class OrchesisPlugin(ABC):
    """Base class for Orchesis pipeline extension plugins (hook-based)."""

    @property
    @abstractmethod
    def info(self) -> PluginInfo: ...

    def on_request(self, request: dict, context: dict) -> dict | None:
        """Called before proxy forwards request. Return modified request or None."""
        return None

    def on_response(self, response: dict, context: dict) -> dict | None:
        """Called after proxy receives response. Return modified response or None."""
        return None

    def on_finding(self, finding: dict) -> dict | None:
        """Called when a security finding is emitted. Return modified dict or None to suppress."""
        return finding

    def on_startup(self) -> None:
        """Optional lifecycle hook."""

    def on_shutdown(self) -> None:
        """Optional lifecycle hook."""


class OrchesisHookRegistry:
    """Registers extension plugins and dispatches named hooks (separate from proxy PluginRegistry)."""

    _HOOK_METHODS = frozenset(
        {"on_request", "on_response", "on_finding", "on_startup", "on_shutdown"}
    )

    def __init__(self) -> None:
        self._plugins: dict[str, OrchesisPlugin] = {}
        self._hooks: dict[str, list[OrchesisPlugin]] = defaultdict(list)

    def register(self, plugin: OrchesisPlugin) -> None:
        info = plugin.info
        key = str(info.name)
        if key in self._plugins:
            self.unregister(key)
        self._plugins[key] = plugin
        for hook in info.hooks:
            if hook in self._HOOK_METHODS and plugin not in self._hooks[hook]:
                self._hooks[hook].append(plugin)

    def unregister(self, name: str) -> None:
        plugin = self._plugins.pop(str(name), None)
        if plugin is None:
            return
        for bucket in self._hooks.values():
            bucket[:] = [p for p in bucket if p is not plugin]

    def get_plugins(self) -> list[PluginInfo]:
        return [p.info for p in self._plugins.values()]

    def fire_hook(self, hook_name: str, **kwargs: Any) -> list[Any]:
        if hook_name not in self._HOOK_METHODS:
            return []
        results: list[Any] = []
        for plugin in list(self._hooks.get(hook_name, [])):
            try:
                fn = getattr(plugin, hook_name)
                if hook_name in ("on_startup", "on_shutdown"):
                    out = fn()
                else:
                    out = fn(**kwargs)
                results.append(out)
            except Exception as error:  # noqa: BLE001
                results.append(error)
        return results

    def load_from_path(self, path: str) -> None:
        """Load a plugin class from a ``.py`` file (first concrete OrchesisPlugin subclass)."""
        file_path = Path(path).resolve()
        if not file_path.is_file():
            raise FileNotFoundError(str(file_path))
        spec = importlib.util.spec_from_file_location(
            f"orchesis_user_plugin_{file_path.stem}", file_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin from {file_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        candidate: type[OrchesisPlugin] | None = None
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if obj is OrchesisPlugin or not issubclass(obj, OrchesisPlugin):
                continue
            if inspect.isabstract(obj):
                continue
            candidate = obj
            break
        if candidate is None:
            raise TypeError(f"No concrete OrchesisPlugin subclass in {file_path}")
        self.register(candidate())

    def load_from_policy(self, policy: dict[str, Any] | None) -> None:
        """Load plugins listed under ``policy['plugins']`` (paths or importable module names)."""
        if not isinstance(policy, dict):
            return
        raw = policy.get("plugins")
        if raw is None:
            return
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            if not isinstance(item, str) or not item.strip():
                continue
            spec = item.strip()
            p = Path(spec)
            if p.suffix == ".py" and p.is_file():
                self.load_from_path(str(p))
            elif Path(spec).is_file():
                self.load_from_path(spec)
            else:
                mod = importlib.import_module(spec)
                candidate: type[OrchesisPlugin] | None = None
                for _n, obj in inspect.getmembers(mod, inspect.isclass):
                    if obj is OrchesisPlugin or not issubclass(obj, OrchesisPlugin):
                        continue
                    if inspect.isabstract(obj):
                        continue
                    candidate = obj
                    break
                if candidate is None:
                    raise TypeError(f"No concrete OrchesisPlugin in module {spec!r}")
                self.register(candidate())


class OrchesisPipelinePluginRegistry(OrchesisHookRegistry):
    """Alias for the extension hook registry (same behavior as :class:`OrchesisHookRegistry`).

    The name ``PluginRegistry`` is reserved for :class:`ProxyPlugin` in this module because
    ``proxy.py`` imports it; use this class (or :class:`OrchesisHookRegistry`) for
    :class:`OrchesisPlugin` extensions.
    """
