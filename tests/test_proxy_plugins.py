from __future__ import annotations

from orchesis.plugin_system import (
    PluginRegistry,
    ProxyPlugin,
    RequestEnricherPlugin,
    RequestLoggerPlugin,
)


class _MarkPlugin(ProxyPlugin):
    def __init__(self, name: str, priority: int, mark: str):
        self._name = name
        self._priority = priority
        self._mark = mark

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def on_request(self, request: dict, context: dict) -> dict:
        out = dict(request)
        order = out.get("order")
        if not isinstance(order, list):
            order = []
        order.append(self._mark)
        out["order"] = order
        return out

    def on_response(self, response: dict, context: dict) -> dict:
        out = dict(response)
        order = out.get("order")
        if not isinstance(order, list):
            order = []
        order.append(self._mark)
        out["order"] = order
        return out


def test_plugin_registered_and_runs() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("p1", 10, "a"))
    out = registry.run_request({"x": 1}, {})
    assert out["order"] == ["a"]


def test_priority_order_respected() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("late", 80, "late"))
    registry.register(_MarkPlugin("early", 10, "early"))
    req = registry.run_request({}, {})
    resp = registry.run_response({}, {})
    assert req["order"] == ["early", "late"]
    assert resp["order"] == ["late", "early"]


def test_request_modified_by_plugin() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("p", 20, "ok"))
    out = registry.run_request({"payload": True}, {})
    assert out["order"] == ["ok"]


def test_response_modified_by_plugin() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("p", 20, "ok"))
    out = registry.run_response({"status": 200}, {})
    assert out["order"] == ["ok"]


def test_unregister_plugin() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("p", 20, "ok"))
    assert registry.unregister("p") is True
    assert registry.unregister("p") is False


def test_list_plugins_returns_all() -> None:
    registry = PluginRegistry()
    registry.register(_MarkPlugin("p1", 20, "a"))
    registry.register(_MarkPlugin("p2", 30, "b"))
    items = registry.list_plugins()
    assert len(items) == 2
    assert {item["name"] for item in items} == {"p1", "p2"}


def test_built_in_logger_plugin() -> None:
    plugin = RequestLoggerPlugin()
    context: dict = {}
    _ = plugin.on_request({"a": 1}, context)
    _ = plugin.on_response({"status": 200, "body": b"ok"}, context)
    assert "request_started_at" in context
    assert "request_latency_ms" in context
    assert isinstance(context.get("plugin_logs"), list)


def test_built_in_enricher_plugin() -> None:
    plugin = RequestEnricherPlugin({"add_headers": {"X-Orchesis-Agent": "true"}})
    out = plugin.on_request({"headers": {"A": "1"}}, {})
    assert out["headers"]["A"] == "1"
    assert out["headers"]["X-Orchesis-Agent"] == "true"
